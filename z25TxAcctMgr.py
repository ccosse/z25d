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
		self.accts=[]
		self.orders=[]
		self.order_keys=[]

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

	def refresh_orders(self):
		"""Fetch historical orders via JWT; returns a list[dict]."""
		creds = load_creds()
		api_key = creds.get('api-key') or creds.get('api_key') or ""
		exp_s = int(creds.get('jwt_exp_s', 120))
		priv_sources = {
			"private_key_b64": creds.get("private_key_b64") or creds.get("private_key"),
			"private_key_hex": creds.get("private_key_hex"),
			"private_key_pem": creds.get("private_key_pem"),
			"private_key_openssh": creds.get("private_key_openssh"),
		}
		key = ed25519_from_sources(priv_sources)
		if not key:
			print("[orders] No Ed25519 key available for JWT")
			return []

		from urllib.parse import urlencode
		path = "/api/v3/brokerage/orders/historical/batch"
		cursor = None
		all_orders = []

		while True:
			params = {}
			if cursor: params["cursor"] = cursor
			q = "?" + urlencode(params) if params else ""
			# JWT must include exact METHOD, HOST, PATH, and QUERY used
			tok, _, _ = jwt_cdp(api_key, key, exp_s=exp_s, method="GET", path=path, query=q)
			r = do_request_with_bearer(tok, path=path, params=params)
			if r.status_code != 200:
				print("[orders] HTTP", r.status_code, r.text[:240])
				return all_orders

			data = r.json()
			if isinstance(data, str):
				import json as _json
				data = _json.loads(data)

			orders = data.get("orders", [])
			all_orders.extend(orders)
			if not data.get("has_next"):
				break
			cursor = data.get("cursor")

		open_orders = [o for o in all_orders if str(o.get("status")).upper() == "OPEN"]
		self.order_keys=[]
		for oidx in range(len(open_orders)):
			print(open_orders[oidx])
			self.order_keys.append(open_orders[oidx]["product_id"].replace('-USDC','-USD'))
		self.orders=open_orders
		return open_orders
		#return all_orders

	def place_order(self, msg: dict) -> dict:
		"""
		Price comes from *-USD* channel. Order placed on *-USDC* book.
		Percent limits are passive by default:
		  BUY: price*(1 - pct), SELL: price*(1 + pct)
		Supports amt in <num>|MAX|MX2 and type in M|L.
		"""
		import uuid, json, requests, math

		def dbg(*a): print("[place_order]", *a)

		# --- auth helper -----------------------------------------------------
		def _jwt(method, path, query=""):
			creds = load_creds()
			api_key = creds.get('api-key') or creds.get('api_key') or ""
			exp_s = int(creds.get('jwt_exp_s', 120))
			key = ed25519_from_sources({
				"private_key_b64": creds.get("private_key_b64") or creds.get("private_key"),
				"private_key_hex": creds.get("private_key_hex"),
				"private_key_pem": creds.get("private_key_pem"),
				"private_key_openssh": creds.get("private_key_openssh"),
			})
			if not key:
				raise RuntimeError("No Ed25519 key available for JWT")
			return jwt_cdp(api_key, key, exp_s=exp_s, method=method, path=path, query=query)[0]

		def _jsonify(resp):
			try:
				j = resp.json()
				if isinstance(j, str): j = json.loads(j)
				return j
			except Exception:
				return {"error": resp.text}

		# --- balances --------------------------------------------------------
		def _scan_bal(accts, ccy: str) -> float:
			for acc in accts or []:
				if str(acc.get("currency")).upper() == ccy.upper():
					try: return float(acc["available_balance"]["value"])
					except: pass
			return 0.0

		def _get_bal(ccy: str) -> float:
			if hasattr(self, "accts") and self.accts:
				src = self.accts if isinstance(self.accts, list) else self.accts.get("accounts")
				v = _scan_bal(src, ccy)
				if v: return v
			path = "/api/v3/brokerage/accounts"
			tok = _jwt("GET", path, "")
			r = requests.get(f"https://api.coinbase.com{path}?limit=250",
							 headers={"Authorization": f"Bearer {tok}"}, timeout=12)
			if r.status_code == 200:
				return _scan_bal(_jsonify(r).get("accounts"), ccy)
			return 0.0

		# --- product increments & formatting --------------------------------
		def _product_increments(pid: str):
			try:
				path = f"/api/v3/brokerage/products/{pid}"
				tok = _jwt("GET", path, "")
				r = requests.get(f"https://api.coinbase.com{path}",
								 headers={"Authorization": f"Bearer {tok}"}, timeout=10)
				if r.status_code != 200:
					dbg("prod meta HTTP", r.status_code, r.text[:160]); raise RuntimeError("prod meta fail")
				j = _jsonify(r)
				bi = float(j.get("base_increment") or 1e-6)
				qi = float(j.get("quote_increment") or 0.01)
				return bi, qi
			except Exception as e:
				dbg("prod meta error:", e, "→ using defaults")
				return 1e-6, 0.01

		def _quantize_floor(value: float, inc: float) -> float:
			if inc <= 0: return value
			return math.floor(value / inc) * inc

		def _fmt_by_inc(x: float, inc: float) -> str:
			s = f"{inc:.12f}".rstrip('0').rstrip('.')
			decimals = len(s.split('.')[1]) if '.' in s else 0
			return f"{x:.{decimals}f}"

		# --- parse inputs ----------------------------------------------------
		dbg("incoming msg:", msg)
		try:
			pid_in = str(msg.get("pid"))
			side   = "BUY" if str(msg.get("side","B")).upper().startswith("B") else "SELL"
			o_typ  = str(msg.get("type","M")).upper()
			amt_s  = str(msg.get("amt")).strip()
			lim_s  = (str(msg.get("limit")).strip() if msg.get("limit") is not None else None)
			base_ccy, quote_ccy_in = pid_in.split("-")[0].upper(), pid_in.split("-")[1].upper()
		except Exception as e:
			return {"ok": False, "error": f"parse_error:{e}"}
		dbg("parsed:", dict(pid=pid_in, side=side, type=o_typ, amt=amt_s, limit=lim_s))

		# --- price source: ALWAYS from -USD channel --------------------------
		price_pid = pid_in
		try:
			ch = self.ctx.z25.getChannel(price_pid)
			last_px = float(ch.getPrice())
			best_bid = best_ask = last_px
			dbg("ctx price (from USD book):", last_px)
		except Exception as e:
			return {"ok": False, "error": f"ctx_price_error:{e}"}

		# --- order market: place on -USDC if input is -USD -------------------
		if pid_in.endswith("-USD"):
			order_pid = f"{base_ccy}-USDC"
			order_quote = "USDC"
			dbg("placing on USDC market:", order_pid, "(price from", price_pid, ")")
		else:
			order_pid = pid_in
			order_quote = quote_ccy_in

		# increments for the order product
		base_inc, quote_inc = _product_increments(order_pid)
		dbg("increments:", dict(base_increment=base_inc, quote_increment=quote_inc))

		# --- limit price (passive by default) --------------------------------
		try:
			limit_price = None
			if o_typ == "L":
				if lim_s is None:
					return {"ok": False, "error": "limit_missing for LIMIT order"}
				if lim_s.endswith("%"):
					pct = float(lim_s[:-1]) / 100.0
					# passive logic: BUY below, SELL above
					raw_px = last_px * (1.0 - pct) if side == "BUY" else last_px * (1.0 + pct)
				else:
					raw_px = float(lim_s)
				limit_price = _quantize_floor(raw_px, quote_inc)
				dbg("limit_price(raw→quantized for order market):", raw_px, "→", limit_price)
		except Exception as e:
			return {"ok": False, "error": f"limit_parse_error:{e}"}

		# --- amount in quote currency (USDC if switched) ---------------------
		def _quote_amount():
			u = amt_s.upper()
			if u in ("MAX","MX2"):
				factor = 0.5 if u == "MX2" else 1.0
				if side == "BUY":
					q_bal = _get_bal(order_quote); dbg(f"{order_quote} balance:", q_bal)
					return max(0.0, q_bal * factor)
				else:
					b_bal = _get_bal(base_ccy)
					ref_px = (limit_price if (o_typ == "L" and limit_price is not None) else best_bid)
					dbg("base balance:", b_bal, "ref_px:", ref_px)
					return max(0.0, b_bal * ref_px * factor)
			return float(amt_s)

		try:
			quote_amt = _quote_amount()
			dbg("quote_amt (order quote currency):", quote_amt, order_quote)
			if quote_amt <= 0: return {"ok": False, "error": "amount_not_positive"}
		except Exception as e:
			return {"ok": False, "error": f"amount_error:{e}"}

		# --- size math (quantized) ------------------------------------------
		def _base_from_quote(ref_px: float) -> float:
			if ref_px <= 0: raise ValueError("invalid reference price")
			return quote_amt / ref_px

		# --- build order body -----------------------------------------------
		try:
			body = {
				"client_order_id": str(uuid.uuid4()),
				"product_id": order_pid,
				"side": side,
				"order_configuration": {}
			}

			if o_typ == "M":
				if side == "BUY":
					q_funds = _quantize_floor(quote_amt, quote_inc)
					cfg = {"quote_size": _fmt_by_inc(q_funds, quote_inc)}
					body["order_configuration"]["market_market_ioc"] = cfg
					dbg("market BUY by quote:", cfg)
				else:
					ref_px = best_bid
					raw_size = _base_from_quote(ref_px)
					q_size = _quantize_floor(raw_size, base_inc)
					q_size = min(q_size, _quantize_floor(_get_bal(base_ccy), base_inc))
					cfg = {"base_size": _fmt_by_inc(q_size, base_inc)}
					body["order_configuration"]["market_market_ioc"] = cfg
					dbg("market SELL base_size(raw→quantized):", raw_size, "→", q_size)
			else:
				px = float(limit_price)
				raw_size = _base_from_quote(px)
				q_size = _quantize_floor(raw_size, base_inc)
				if side == "SELL":
					q_size = min(q_size, _quantize_floor(_get_bal(base_ccy), base_inc))
				cfg = {
					"base_size": _fmt_by_inc(q_size, base_inc),
					"limit_price": _fmt_by_inc(px, quote_inc),
					"post_only": False
				}
				body["order_configuration"]["limit_limit_gtc"] = cfg
				dbg("limit cfg:", cfg)
		except Exception as e:
			return {"ok": False, "error": f"build_body_error:{e}"}

		# --- POST ------------------------------------------------------------
		try:
			path = "/api/v3/brokerage/orders"
			tok  = _jwt("POST", path, "")
			url  = f"https://api.coinbase.com{path}"
			dbg("POST", url, "body:", body)
			r = requests.post(url,
							  headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
							  data=json.dumps(body), timeout=20)
			j = _jsonify(r)
			dbg("HTTP", r.status_code, "resp_head:", str(j)[:160])
			if r.status_code != 200:
				return {"ok": False, "status": r.status_code, "resp": j, "sent": body}
			return j
		except Exception as e:
			return {"ok": False, "error": f"http_exception:{e}", "sent": body}

	def report(self):
		print(f"z25TxAcctMgr.report")
		print(f"accts: {len(self.accts)}")
		print(f"orders: {len(self.orders)}")
		print(f"order_keys: {self.order_keys}")
	def getCBX(self):
		self.refresh_accounts()		
		for acct in list(self.accts):
			pid=acct["currency"]+"-USD"
			try:
				self.ctx.z25.channels[pid].balance = float(acct['available_balance']['value']) + float(acct['hold']['value'])
			except:
				print(f"NO CHANNEL FOR: {pid} {sys.exc_info()}")
		return self.accts
