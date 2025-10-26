#!/usr/bin/env python3
"""
cb_at_probe.py — Minimal standalone Advanced Trade /accounts probe using your existing cbx_credentials.dat

- Reads cbx_credentials.dat from the same folder.
- Supports three auth modes:
    1) JWT (CDP style): iss="cdp", header includes kid + nonce, payload has single 'uri' like "GET api.coinbase.com/api/v3/brokerage/accounts"
    2) JWT (Coinbase-App style): iss="coinbase", aud="retail_rest_api", payload has method + uri pieces
    3) HMAC (legacy)

- You can force behavior via cbx_credentials.dat:
    {'auth': 'jwt', 'jwt_style': 'cdp' }          # force CDP-JWT
    {'auth': 'jwt', 'jwt_style': 'coinbase'}      # force Coinbase-App-JWT
    {'auth': 'jwt', 'jwt_style': 'auto'}          # try CDP first, then Coinbase (default)
    {'auth': 'hmac'}                              # force HMAC

- Required fields for JWT: 'api-key' and one private key source (private_key_b64 | hex | pem | openssh).
  For CDP, best results when 'api-key' is the full KEY_NAME like 'organizations/{org}/apiKeys/{key_id}'.
"""

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

def load_creds():
    here = os.path.dirname(os.path.abspath(__file__))
    f = os.path.join(here, "cbx_credentials.dat")
    data = {}
    if os.path.exists(f):
        raw = open(f, "r").read().strip()
        data = ast.literal_eval(raw)
    # env overrides
    if os.getenv("CB_API_KEY"):    data['api-key'] = os.getenv("CB_API_KEY")
    if os.getenv("CB_API_SECRET"): data['api-secret'] = os.getenv("CB_API_SECRET")
    return data

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

    # OpenSSH
    ossh = priv_sources.get("private_key_openssh")
    if ossh:
        try:
            ossh_bytes = ossh.encode('utf-8') if isinstance(ossh, str) else ossh
            key_obj = serialization.load_ssh_private_key(ossh_bytes, password=None)
            raw = key_obj.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            if len(raw) == 32:
                return Ed25519PrivateKey.from_private_bytes(raw)
        except Exception as e:
            print("[probe] OpenSSH load failed:", e)

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

def jwt_coinbase(key_name, ed25519, aud="retail_rest_api", exp_s=120, method="GET", path=ACCOUNTS_PATH, query=""):
    now = int(time.time()); exp = now + int(exp_s)
    header = {"alg":"EdDSA","typ":"JWT","kid": key_name}
    payload = {
        "iss":"coinbase","sub": key_name,"aud": aud,
        "iat": now,"nbf": now-1,"exp": exp,
        "uri": path+query,"method": method.upper()
    }
    h = b64url(json.dumps(header, separators=(',',':')).encode('utf-8'))
    p = b64url(json.dumps(payload, separators=(',',':')).encode('utf-8'))
    sig = ed25519.sign((h+"."+p).encode('ascii'))
    return (h+"."+p+"."+b64url(sig)), header, payload

def do_request_with_bearer(token, path=ACCOUNTS_PATH, params=None):
    url = CB_BASE + path
    from urllib.parse import urlencode
    q = "?" + urlencode(params) if params else ""
    r = requests.get(url+q, headers={"Authorization": f"Bearer {token}"}, timeout=15)
    return r

def do_request_hmac(api_key, api_secret, method="GET", path=ACCOUNTS_PATH, params=None, body=""):
    url = CB_BASE + path
    from urllib.parse import urlencode
    q = "?" + urlencode(params) if params else ""
    ts = str(int(time.time()))
    prehash = ts + method.upper() + (path + q) + (body if body else "")
    try:
        secret = base64.b64decode(api_secret)
    except Exception:
        secret = api_secret.encode()
    sig = hmac.new(secret, prehash.encode(), hashlib.sha256).hexdigest()
    headers = {"CB-ACCESS-KEY": api_key, "CB-ACCESS-SIGN": sig, "CB-ACCESS-TIMESTAMP": ts}
    r = requests.request(method, url + q, headers=headers, data=body, timeout=15)
    return r

def main():
    import argparse
    ap = argparse.ArgumentParser(description="Probe Coinbase Advanced Trade auth using existing credentials")
    ap.add_argument("action", nargs="?", default="acct", help="acct (default)")
    ap.add_argument("-v","--verbose", action="store_true", help="verbose diagnostics")
    args = ap.parse_args()

    creds = load_creds()
    api_key = creds.get('api-key') or creds.get('api_key') or ""
    api_secret = creds.get('api-secret') or creds.get('api_secret') or ""
    auth = (creds.get('auth') or 'jwt').lower()
    jwt_style = (creds.get('jwt_style') or 'auto').lower()
    exp_s = int(creds.get('jwt_exp_s', 120))

    # Collect private key sources
    priv_sources = {
        "private_key_b64": creds.get("private_key_b64") or creds.get("private_key"),
        "private_key_hex": creds.get("private_key_hex"),
        "private_key_pem": creds.get("private_key_pem"),
        "private_key_openssh": creds.get("private_key_openssh"),
    }

    if args.verbose:
        print("[probe] auth =", auth, "jwt_style =", jwt_style)
        print("[probe] api-key (len) =", len(api_key), ("(looks like KEY_NAME)" if "/" in api_key else "(short id?)"))

    if args.action != "acct":
        print("Only 'acct' is supported in this probe.")
        return 1

    if auth == "hmac":
        r = do_request_hmac(api_key, api_secret)
        try:
            j = r.json()
        except Exception:
            print(f"[HMAC] HTTP {r.status_code}: {(r.text or '')[:200]}")
            return 1
        print(f"[HMAC] HTTP {r.status_code}: ok" if r.status_code==200 else f"[HMAC] HTTP {r.status_code}: {j}")
        if r.status_code==200:
            print(json.dumps(j, indent=2)[:2000])
            return 0
        return 1

    # JWT path
    key = ed25519_from_sources(priv_sources)
    if not key:
        print("[probe] No Ed25519 key available; cannot try JWT. Set auth:'hmac' to test HMAC instead.")
        return 1

    # Try order: auto => CDP then Coinbase; else force style
    styles = [jwt_style] if jwt_style in ("cdp","coinbase") else ["cdp","coinbase"]
    last_status = None

    for style in styles:
        if style == "cdp":
            tok, hdr, pay = jwt_cdp(api_key, key, exp_s=exp_s)
            if args.verbose:
                print("[CDP] header:", json.dumps({**hdr, "sig":"<ed25519>"}, indent=2))
                sp = dict(pay); sp["uri"] = sp.get("uri","")  # already a string
                print("[CDP] payload:", json.dumps(sp, indent=2))
            r = do_request_with_bearer(tok)
            last_status = r.status_code
            if args.verbose:
                print(f"[CDP] HTTP {r.status_code}")
                if r.status_code != 200:
                    print((r.text or "")[:400])
            if r.status_code == 200:
                print("[CDP] SUCCESS")
                print(json.dumps(r.json(), indent=2)[:2000])
                return 0

        elif style == "coinbase":
            tok, hdr, pay = jwt_coinbase(api_key, key, exp_s=exp_s)
            if args.verbose:
                print("[CB] header:", json.dumps({**hdr, "sig":"<ed25519>"}, indent=2))
                print("[CB] payload:", json.dumps(pay, indent=2))
            r = do_request_with_bearer(tok)
            last_status = r.status_code
            if args.verbose:
                print(f"[CB] HTTP {r.status_code}")
                if r.status_code != 200:
                    print((r.text or "")[:400])
            if r.status_code == 200:
                print("[CB] SUCCESS")
                print(json.dumps(r.json(), indent=2)[:2000])
                return 0

    print(f"[probe] All attempted styles failed; last HTTP status = {last_status}")
    print("Tips:")
    print("  - If your key came from portal.cdp.coinbase.com, try jwt_style='cdp' and ensure api-key is the full KEY_NAME.")
    print("  - If your key is from the Coinbase App (not CDP), try jwt_style='coinbase' with aud='retail_rest_api' (default).")
    print("  - Check system clock (NTP); JWT is time-sensitive.")
    return 1

if __name__ == "__main__":
    sys.exit(main())
