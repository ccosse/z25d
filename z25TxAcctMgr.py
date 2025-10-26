import os, sys, time, json, ast, base64, binascii, hmac, hashlib, secrets
import requests

CB_HOST = "api.coinbase.com"
CB_BASE = f"https://{CB_HOST}"
ACCOUNTS_PATH = "/api/v3/brokerage/accounts"

def b64url(b: bytes) -> str:
	import base64 as b64
	return b64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')

def b64_any(s: str) -> bytes:
	t = s.strip().encode('ascii')
	t = t.replace(b'-', b'+').replace(b'_', b'/')
	pad = (-len(t)) % 4
	if pad: t += b'=' * pad
	import base64 as b64
	return b64.b64decode(t)

def ed25519_from_sources(priv_sources):
	try:
		from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
		from cryptography.hazmat.primitives import serialization
	except Exception as e:
		print("[probe] cryptography not available:", e)
		return None
	# b64 raw
	b64 = priv_sources.get("private_key_b64") or priv_sources.get("private_key")
	if b64:
		try:
			raw = b64_any(b64)
			if len(raw) == 64: raw = raw[:32]
			if len(raw) == 32:
				return Ed25519PrivateKey.from_private_bytes(raw)
			print("[probe] b64 key length must be 32 or 64 bytes; got", len(raw))
		except (ValueError, binascii.Error) as e:
			print("[probe] b64 decode failed:", e)
	# hex raw
	hx = priv_sources.get("private_key_hex")
	if hx:
		try:
			raw = bytes.fromhex(hx.strip())
			if len(raw) == 64: raw = raw[:32]
			if len(raw) == 32:
				return Ed25519PrivateKey.from_private_bytes(raw)
			print("[probe] hex key length must be 32 or 64 bytes; got", len(raw))
		except ValueError as e:
			print("[probe] hex decode failed:", e)
	# PEM
	pem = priv_sources.get("private_key_pem")
	if pem:
		try:
			pem_bytes = pem.encode('utf-8') if isinstance(pem, str) else pem
			key_obj = serialization.load_pem_private_key(pem_bytes, password=None)
			raw = key_obj.private_bytes(
				encoding=serialization.Encoding.Raw,
				format=serialization.PrivateFormat.Raw,
				encryption_algorithm=serialization.NoEncryption()
			)
			if len(raw) == 32:
				return Ed25519PrivateKey.from_private_bytes(raw)
		except Exception as e:
			print("[probe] PEM load failed:", e)
	print("[probe] no usable Ed25519 private key found")
	return None

	def jwt_cdp(key_name, ed25519, exp_s=120, method="GET", path=ACCOUNTS_PATH, query=""):
		now = int(time.time()); exp = now + int(exp_s)
		uri = f"{method.upper()} {CB_HOST}{path}{query}"
		header = {"alg":"EdDSA","typ":"JWT","kid": key_name, "nonce": secrets.token_hex()}
		payload = {"iss":"cdp","sub": key_name,"nbf": now,"exp": exp,"uri": uri}
		h = b64url(json.dumps(header, separators=(',',':')).encode('utf-8'))
		p = b64url(json.dumps(payload, separators=(',',':')).encode('utf-8'))
		sig = ed25519.sign((h+"."+p).encode('ascii'))
		return (h+"."+p+"."+b64url(sig)), header, payload

	def b64url(b: bytes) -> str:
		import base64 as b64
		return b64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')

def do_request_with_bearer(token, path=ACCOUNTS_PATH, params=None):
	url = CB_BASE + path
	from urllib.parse import urlencode
	q = "?" + urlencode(params) if params else ""
	r = requests.get(url+q, headers={"Authorization": f"Bearer {token}"}, timeout=15)
	return r

def jwt_cdp(key_name, ed25519, exp_s=120, method="GET", path=ACCOUNTS_PATH, query=""):
	now = int(time.time()); exp = now + int(exp_s)
	uri = f"{method.upper()} {CB_HOST}{path}{query}"
	header = {"alg":"EdDSA","typ":"JWT","kid": key_name, "nonce": secrets.token_hex()}
	payload = {"iss":"cdp","sub": key_name,"nbf": now,"exp": exp,"uri": uri}
	h = b64url(json.dumps(header, separators=(',',':')).encode('utf-8'))
	p = b64url(json.dumps(payload, separators=(',',':')).encode('utf-8'))
	sig = ed25519.sign((h+"."+p).encode('ascii'))
	return (h+"."+p+"."+b64url(sig)), header, payload

def load_creds():
	here = os.path.dirname(os.path.abspath(__file__))
	f = os.path.join(here, "cbx_credentials.dat")
	data = {}
	if os.path.exists(f):
		raw = open(f, "r").read().strip()
		data = ast.literal_eval(raw)
	# env overrides
	if os.getenv("CB_API_KEY"):	data['api-key'] = os.getenv("CB_API_KEY")
	if os.getenv("CB_API_SECRET"): data['api-secret'] = os.getenv("CB_API_SECRET")
	return data

class Z25TxAcctMgr:

	def __init__(self):
		print("Z25TxAcctMgr")
		self.ctx=None
		self.accts=None

	def refresh_accounts(self):
		creds = load_creds()
		api_key = creds.get('api-key') or creds.get('api_key') or ""
		api_secret = creds.get('api-secret') or creds.get('api_secret') or ""
		auth = (creds.get('auth') or 'jwt').lower()
		jwt_style = (creds.get('jwt_style') or 'auto').lower()
		exp_s = int(creds.get('jwt_exp_s', 120))

		priv_sources = {
			"private_key_b64": creds.get("private_key_b64") or creds.get("private_key"),
			"private_key_hex": creds.get("private_key_hex"),
			"private_key_pem": creds.get("private_key_pem"),
			"private_key_openssh": creds.get("private_key_openssh"),
		}

		key = ed25519_from_sources(priv_sources)
		if not key:
			print("[probe] No Ed25519 key available; cannot try JWT. Set auth:'hmac' to test HMAC instead.")
			return 

		styles = [jwt_style] if jwt_style in ("cdp","coinbase") else ["cdp","coinbase"]
		last_status = None

		for style in styles:
			if style == "cdp":
				tok, hdr, pay = jwt_cdp(api_key, key, exp_s=exp_s)
				r = do_request_with_bearer(tok)
				if r.status_code == 200:
					print("[CDP] SUCCESS")
					self.accts = r.json()
					if isinstance(self.accts, str):
						self.accts = json.loads(self.accts)
					self.accts = self.accts['accounts']
					#print(self.accts)
					#print(json.dumps(self.accts, indent=2))
					for acct in self.accts:
						print(f"{acct['currency']}\t{acct['available_balance']['value']}\t{acct['hold']['value']}")
					return 


	def takeCtx(self,ctx):
		self.ctx=ctx

