#!/usr/bin/env python3
# z26_hotlist.py — momentum “pop-off” monitor with Coinbase Advanced Trade /accounts integration
#
# This file merges the working auth from cb_at_probe.py into the benchmark z26 app:
# - JWT (CDP & Coinbase-App) + HMAC (legacy) exactly as in the probe
# - 'acct' command: fetch and print balances via /api/v3/brokerage/accounts
#
# NOTE: Reads cbx_credentials.dat from the same folder, same as the probe.

import os, sys, json, time, hmac, hashlib, threading, select, requests, websocket, re, ast, base64, binascii, secrets
from collections import deque

try:
    from colorama import Fore, Style, init as color_init
    color_init()
except Exception:
    class _D:
        def __getattr__(self, _): return ""
    Fore = Style = _D()

# ---- Existing z26 config ----
API_KEY     = os.getenv("CB_API_KEY", "YOUR_KEY")
API_SECRET  = os.getenv("CB_API_SECRET", "YOUR_SECRET")
CURRENCIES_URL = "https://api.exchange.coinbase.com/currencies"
WS_CBX_FEED = "wss://ws-feed.exchange.coinbase.com"

ROLL_SEC = 1800
SAMPLE_DT = 1.0
MINI_HIST_MINUTES = 10
BTC_PID = "BTC-USD"
STATE_FILE = "z26_state.json"

RES_WINDOWS = [60, 120, 240, 480]
RES_WEIGHTS = {60: 1.00, 120: 0.85, 240: 0.70, 480: 0.55}

PID_W = 24
PRICE_W = 15
LO_W = 15
HI_W = 15
P1_W = 7
P2_W = 7
P4_W = 7
P8_W = 7
DV_W = 7
POP_W = 5
NET_COL_W = 14
MONEY_COL_W = 14

HIST_DV_OFFSET = 4
LEFT_WIDTH = (
    PID_W + 1 + LO_W + 1 + PRICE_W + 1 + HI_W + 1 + P1_W + 1 + P2_W + 1 + P4_W + 1 + P8_W +
    1 + DV_W + 1 + POP_W + 2 + NET_COL_W + 2 + MONEY_COL_W + 2 + MONEY_COL_W + 2 + 6
)

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
def _visible_len(s): return len(ANSI_RE.sub("", s))
def _pad_visible(s, w): return s + " " * max(0, w - _visible_len(s))
def now_ts(): return time.time()

def _fmt_money_km(x):
    try:
        n = float(x)
        return "${:.2f}M".format(n/1e6) if abs(n) >= 1e6 else "${:.2f}k".format(n/1e3)
    except:
        return f"${x}"

# ---- BEGIN: Probe auth (verbatim behavior) ----
CB_HOST = "api.coinbase.com"
CB_BASE = f"https://{CB_HOST}"
ACCOUNTS_PATH = "/api/v3/brokerage/accounts"

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')

def b64_any(s: str) -> bytes:
    t = s.strip().encode('ascii')
    t = t.replace(b'-', b'+').replace(b'_', b'/')
    pad = (-len(t)) % 4
    if pad: t += b'=' * pad
    return base64.b64decode(t)

def load_creds():
    here = os.path.dirname(os.path.abspath(__file__))
    f = os.path.join(here, "cbx_credentials.dat")
    data = {}
    if os.path.exists(f):
        raw = open(f, "r").read().strip()
        data = ast.literal_eval(raw)
    if os.getenv("CB_API_KEY"):    data['api-key'] = os.getenv("CB_API_KEY")
    if os.getenv("CB_API_SECRET"): data['api-secret'] = os.getenv("CB_API_SECRET")
    return data

def ed25519_from_sources(priv_sources):
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
    except Exception as e:
        print("[auth] cryptography not available:", e)
        return None

    b64 = priv_sources.get("private_key_b64") or priv_sources.get("private_key")
    if b64:
        try:
            raw = b64_any(b64)
            if len(raw) == 64: raw = raw[:32]
            if len(raw) == 32:
                return Ed25519PrivateKey.from_private_bytes(raw)
            print("[auth] b64 key length must be 32 or 64 bytes; got", len(raw))
        except (ValueError, binascii.Error) as e:
            print("[auth] b64 decode failed:", e)

    hx = priv_sources.get("private_key_hex")
    if hx:
        try:
            raw = bytes.fromhex(hx.strip())
            if len(raw) == 64: raw = raw[:32]
            if len(raw) == 32:
                return Ed25519PrivateKey.from_private_bytes(raw)
            print("[auth] hex key length must be 32 or 64 bytes; got", len(raw))
        except ValueError as e:
            print("[auth] hex decode failed:", e)

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
            print("[auth] PEM load failed:", e)

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
            print("[auth] OpenSSH load failed:", e)

    print("[auth] no usable Ed25519 private key found")
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
# ---- END: Probe auth ----

# ---------- Channel ----------
class Channel:
    def __init__(self, msg, init_min=None):
        self.pid = msg["product_id"]
        self.price = float(msg.get("price", 0))
        self.vol24 = float(msg.get("volume_24h", 0))
        self.hi24  = float(msg.get("high_24h", 0))
        self.lo24  = float(msg.get("low_24h", 0))
        side = 1 if msg.get("side","buy")=="buy" else -1
        self.history = deque([(now_ts(), self.price, self.vol24, side)], maxlen=int(ROLL_SEC/SAMPLE_DT))
        self.flags=set(); self.active_since=None

        self._min_keys = deque(maxlen=MINI_HIST_MINUTES)
        self._min_data = {}
        if init_min is None:
            init_min = int(now_ts()//60)
        self._cur_min = init_min
        self._min_keys.append(self._cur_min)
        self._min_data[self._cur_min] = {
            "p_start": self.price, "p_last": self.price,
            "v_start": self.vol24, "v_last": self.vol24, "net": side,
            "money_buy": 0.0, "money_sell": 0.0, "vol_buy": 0.0, "vol_sell": 0.0
        }

        self.best_pct = 0.0
        self.best_win = 60

    def ensure_min(self, min_key):
        if getattr(self, "_cur_min", None) == min_key:
            return
        self._cur_min = min_key
        self._min_keys.append(min_key)
        self._min_data[min_key] = {
            "p_start": self.price, "p_last": self.price,
            "v_start": self.vol24, "v_last": self.vol24, "net": 0,
            "money_buy": 0.0, "money_sell": 0.0, "vol_buy": 0.0, "vol_sell": 0.0
        }

    def update(self, msg):
        self.price=float(msg.get("price",self.price))
        self.vol24=float(msg.get("volume_24h",self.vol24))
        self.hi24=float(msg.get("high_24h",self.hi24))
        self.lo24=float(msg.get("low_24h",self.lo24))
        last_sz = float(msg.get("last_size", msg.get("last_trade_size", 0)) or 0.0)
        side = 1 if msg.get("side","buy")=="buy" else -1
        self.history.append((now_ts(), self.price, self.vol24, side))

        m = getattr(self, "_cur_min", int(now_ts()//60))
        d = self._min_data.get(m)
        if d is None:
            d = {"p_start": self.price, "p_last": self.price, "v_start": self.vol24, "v_last": self.vol24,
                 "net": 0, "money_buy": 0.0, "money_sell": 0.0, "vol_buy": 0.0, "vol_sell": 0.0}
            self._min_data[m] = d
            self._min_keys.append(m)
            self._cur_min = m
        d["p_last"] = self.price
        d["v_last"] = self.vol24
        d["net"] += side
        if last_sz>0:
            if side>0:
                d["money_buy"] += last_sz*self.price
                d["vol_buy"]   += last_sz
            else:
                d["money_sell"] += last_sz*self.price
                d["vol_sell"]  += last_sz

    def pct_over(self, sec):
        tcut = now_ts()-sec
        hist=list(self.history)
        old=None
        for (t, p, _, _) in reversed(hist):
            if t<=tcut: old=p; break
        if old is None and hist: old=hist[0][1]
        return (self.price-old)/old*100.0 if old and old>0 else 0.0

    def current_dV_ratio(self):
        m = getattr(self, "_cur_min", int(now_ts()//60))
        d = self._min_data.get(m)
        if not d: return 0.0
        vb = float(d.get("vol_buy", 0.0)); vs = float(d.get("vol_sell", 0.0))
        avg_per_min = (self.vol24/86400.0)*60.0 if self.vol24>0 else 0.0
        if avg_per_min<=0: return 0.0
        net = vb - vs
        return net / avg_per_min

    def compute_best_window(self):
        best_score = None
        best_pct = 0.0
        best_win = RES_WINDOWS[0]
        for w in RES_WINDOWS:
            pct = self.pct_over(w)
            score = pct * RES_WEIGHTS.get(w, 1.0)
            if best_score is None or score > best_score:
                best_score = score
                best_pct = pct
                best_win = w
        self.best_pct = best_pct
        self.best_win = best_win
        return best_pct, best_win, best_score

    def trend(self, minutes=MINI_HIST_MINUTES):
        if not hasattr(self, "_cur_min"): return ""
        cur = self._cur_min
        bars = []
        for i in range(minutes):
            k = cur - i
            d = self._min_data.get(k)
            if not d or not d.get("p_start"):
                bars.append("▯"); continue
            p0 = d["p_start"]; p1 = d.get("p_last", p0)
            if not p0: bars.append("▯"); continue
            change = ((p1 - p0)/p0)*100.0
            a = abs(change)
            if a < 0.05: bars.append("▯")
            elif change > 0:
                if a < 0.20: bars.append(Style.DIM + Fore.GREEN + "▮" + Style.RESET_ALL)
                elif a < 0.50: bars.append(Fore.GREEN + "▮" + Style.RESET_ALL)
                else: bars.append(Style.BRIGHT + Fore.LIGHTGREEN_EX + "▮" + Style.RESET_ALL)
            else:
                if a < 0.20: bars.append(Style.DIM + Fore.RED + "▮" + Style.RESET_ALL)
                elif a < 0.50: bars.append(Fore.RED + "▮" + Style.RESET_ALL)
                else: bars.append(Style.BRIGHT + Fore.LIGHTRED_EX + "▮" + Style.RESET_ALL)
        return "".join(bars)

    def trend_dv(self, minutes=MINI_HIST_MINUTES):
        if not hasattr(self, "_cur_min"): return ""
        cur = self._cur_min
        bars = []
        for i in range(minutes):
            k = cur - i
            d = self._min_data.get(k)
            if not d:
                bars.append("▯"); continue
            vb = float(d.get("vol_buy", 0.0)); vs = float(d.get("vol_sell", 0.0))
            v_end = d.get("v_last", self.vol24) or 0.0
            avg_per_min = (v_end/86400.0)*60.0 if v_end>0 else 0.0
            if avg_per_min<=0: bars.append("▯"); continue
            val = (vb - vs)/avg_per_min
            a = abs(val)
            if a < 0.05: bars.append("▯")
            elif val > 0:
                if a < 0.20: bars.append(Style.DIM + Fore.GREEN + "▮" + Style.RESET_ALL)
                elif a < 0.50: bars.append(Fore.GREEN + "▮" + Style.RESET_ALL)
                else: bars.append(Style.BRIGHT + Fore.LIGHTGREEN_EX + "▮" + Style.RESET_ALL)
            else:
                if a < 0.20: bars.append(Style.DIM + Fore.RED + "▮" + Style.RESET_ALL)
                elif a < 0.50: bars.append(Fore.RED + "▮" + Style.RESET_ALL)
                else: bars.append(Style.BRIGHT + Fore.LIGHTRED_EX + "▮" + Style.RESET_ALL)
        return "".join(bars)

# ---------- App ----------
class Z26:
    def __init__(self):
        self.channels={}; self._lock=threading.RLock()
        self._stop=threading.Event()
        self.subscribed_products_list=[]; self.subscribed_products_string=""
        self.topN=5; self.p1=1.0; self.v1=6.0; self.pa=2.0; self.pv=2.0; self.ps=300
        self.raw_plog=False
        self.pinned=set([BTC_PID])
        self.prev_winners=[]; self.prev_losers=[]
        self.hysteresis_margin=1.2
        self.current_min = int(time.time()//60)
        self.prev_prices = {}
        self.accounts = {}

    # --- networking ---
    def _load_products(self):
        try:
            r=requests.get(CURRENCIES_URL,timeout=10).json()
            for i,it in enumerate(r):
                if it.get("details",{}).get("type")=="crypto":
                    pid=f"{it['id']}-USD"
                    self.subscribed_products_list.append(pid)
                    self.subscribed_products_string+=pid+("," if i<len(r)-1 else "")
        except Exception as e: print("product load failed",e)
    def _sign(self,s): return hmac.new(API_SECRET.encode(),s.encode(),hashlib.sha256).hexdigest()
    def _ws(self):
        ts=str(int(time.time())); ch="ticker"
        sub={"type":"subscribe","channels":[{"name":"ticker","product_ids":self.subscribed_products_list}],
             "api_key":API_KEY,"timestamp":ts,"signature":self._sign(ts+ch+self.subscribed_products_string)}
        def on_open(ws): ws.send(json.dumps(sub))
        def on_message(ws,raw):
            try:m=json.loads(raw)
            except: return
            if m.get("type")!="ticker": return
            if self.raw_plog: print(json.dumps(m)[:200])
            self._upd(m)
        websocket.WebSocketApp(WS_CBX_FEED,on_open=on_open,on_message=on_message).run_forever()
    def _upd(self,m):
        pid=m["product_id"]
        with self._lock:
            ch=self.channels.get(pid)
            if not ch: self.channels[pid]=Channel(m, init_min=self.current_min)
            else:
                ch.ensure_min(self.current_min)
                ch.update(m)

    # --- global minute roller ---
    def _roll_minute(self):
        with self._lock:
            self.current_min = int(time.time()//60)
            for c in self.channels.values():
                c.ensure_min(self.current_min)

    def _minute_roller(self):
        while not self._stop.is_set():
            now = time.time()
            sleep = 60.0 - (now % 60.0)
            if sleep < 0.001: sleep = 0.001
            time.sleep(sleep)
            self._roll_minute()

    # --- analytics ---
    def _an(self):
        with self._lock: arr=list(self.channels.values())
        for c in arr:
            c.flags.clear()
            c.compute_best_window()
            dV   = c.current_dV_ratio()

            Hflag = False; Lflag = False
            if c.hi24:
                dhi = (c.hi24 - c.price)/c.hi24*100.0
                if dhi <= 1.0: Hflag = True
            if c.lo24:
                dlo = (c.price - c.lo24)/c.lo24*100.0
                if dlo <= 1.0: Lflag = True
            if Hflag or Lflag:
                if Hflag and not Lflag: c.flags.add("H")
                elif Lflag and not Hflag: c.flags.add("L")
                else:
                    if (c.hi24 - c.price)/c.hi24 <= (c.price - c.lo24)/c.lo24:
                        c.flags.add("H")
                    else:
                        c.flags.add("L")

            if any(abs(c.pct_over(w)) >= self.p1 for w in RES_WINDOWS): c.flags.add("A")
            if abs(dV)>=self.v1:   c.flags.add("V")
            if c.flags:
                if not c.active_since: c.active_since=now_ts()
                elif now_ts()-c.active_since>=self.ps: c.flags.add("S")
            else: c.active_since=None
            if len([f for f in c.flags if f!="S"])>=2: c.flags.add("C")

    # --- view helpers ---
    def _fmt_pop(self,c):
        order="AVCSH"
        cmap={'A': Fore.YELLOW, 'V': Fore.CYAN, 'C': Fore.MAGENTA, 'S': Fore.WHITE, 'H': Fore.BLUE, 'L': Fore.BLUE}
        out=""
        for ch in order:
            if ch == "H":
                if "H" in c.flags:
                    out += cmap['H'] + "H" + Style.RESET_ALL
                elif "L" in c.flags:
                    out += cmap['L'] + "L" + Style.RESET_ALL
                else:
                    out += " "
            else:
                out += (cmap.get(ch,"")+ch if ch in c.flags else " ") + Style.RESET_ALL
        return out

    def _header_line(self):
        lbl_p2  = "  "    + "%2m"
        lbl_p4  = "    "  + "%4m"
        lbl_p8  = "      " + "%8m"
        lbl_dv  = "      " + "dV"
        lbl_pop = "   "   + "POP"

        net_w = max(1, NET_COL_W - 2)
        b_w   = max(1, MONEY_COL_W - 2)
        s_w   = MONEY_COL_W + 1 + 2

        hdr_left = _pad_visible(
            f"{'PID':{PID_W}} {'Lo24':>{LO_W}} {'Price':>{PRICE_W}} {'Hi24':>{HI_W}} "
            f"{'%1m':>{P1_W}} {lbl_p2:>{P2_W}} {lbl_p4:>{P4_W}} {lbl_p8:>{P8_W}} "
            f"{lbl_dv:>{DV_W}} {lbl_pop:>{POP_W}}  {'$Net':>{net_w}}  {'$B':>{b_w}}  {'$S':>{s_w}} ",
            LEFT_WIDTH
        )
        return f"{hdr_left}|Trend%{' ' * HIST_DV_OFFSET}| Trend dV"

    def _fmt(self,c):
        lo_s = f"{c.lo24:>{LO_W}.6f}"
        price_val = f"{c.price:>{PRICE_W}.6f}"

        if c.pid == BTC_PID:
            prev = self.prev_prices.get(BTC_PID)
            if prev is None:
                price = Fore.CYAN + price_val + Style.RESET_ALL
            else:
                if c.price > prev:
                    price = Fore.GREEN + price_val + Style.RESET_ALL
                elif c.price < prev:
                    price = Fore.RED + price_val + Style.RESET_ALL
                else:
                    price = Fore.CYAN + price_val + Style.RESET_ALL
            self.prev_prices[BTC_PID] = c.price
        else:
            price = Fore.CYAN + price_val + Style.RESET_ALL

        hi_s = f"{c.hi24:>{HI_W}.6f}"

        def pct_col(sec, width):
            v = c.pct_over(sec)
            clr = Fore.GREEN if v>=0 else Fore.RED
            return f"{clr}{v:>{width}.2f}%{Style.RESET_ALL}"
        p1 = pct_col(60, P1_W)
        p2 = pct_col(120, P2_W)
        p4 = pct_col(240, P4_W)
        p8 = pct_col(480, P8_W)

        dv_val = c.current_dV_ratio()
        dvclr = Fore.GREEN if dv_val>0 else (Fore.RED if dv_val<0 else "")
        dV   = f"{dvclr}{dv_val:+{DV_W}.2f}{Style.RESET_ALL}"

        pop  = self._fmt_pop(c)
        mkey = getattr(c, "_cur_min", int(now_ts()//60))
        d = getattr(c, "_min_data", {}).get(mkey, {})
        mb = d.get("money_buy", 0.0); ms = d.get("money_sell", 0.0)
        net = mb - ms
        net_txt = _fmt_money_km(net)
        net_pad = f"{net_txt:>{NET_COL_W}}"
        net_s = (Fore.GREEN if net>=0 else Fore.RED) + net_pad + Style.RESET_ALL

        buy_txt  = _fmt_money_km(mb)
        sell_txt = _fmt_money_km(ms)
        buy_pad  = f"{buy_txt:>{MONEY_COL_W}}"
        sell_pad = f"{sell_txt:>{MONEY_COL_W}}"
        buy_s  = Fore.GREEN + buy_pad  + Style.RESET_ALL
        sell_s = Fore.RED   + sell_pad + Style.RESET_ALL

        left = f"{c.pid:{PID_W}} {lo_s} {price} {hi_s} {p1} {p2} {p4} {p8} {dV} {pop}  {net_s}  {buy_s}  {sell_s} "
        left = _pad_visible(left, LEFT_WIDTH)
        return f"{left}|{c.trend()}| {c.trend_dv()}"

    def _ranked(self, arr, top=True, exclude_pids=None):
        exclude_pids = exclude_pids or set()
        scored = []
        for c in arr:
            _, _, score = c.compute_best_window()
            ord_score = score if top else -score
            scored.append((ord_score, c))
        scored.sort(key=lambda x: x[0], reverse=True)
        ranked = [c for _,c in scored if c.pid not in exclude_pids]
        return ranked

    def _time_to_next_min(self):
        rem = 60.0 - (time.time() % 60.0)
        return rem

    def print_winners_losers(self):
        self._an()
        with self._lock:
            arr=list(self.channels.values())
        if not arr: print("\n[no channels yet]\n"); return

        pins=[]
        if BTC_PID in self.channels:
            pins.append(self.channels[BTC_PID])
        for pid in self.pinned:
            if pid == BTC_PID: continue
            if pid in self.channels:
                pins.append(self.channels[pid])

        if pins:
            print(f"\n{Fore.MAGENTA}== PINNED =={Style.RESET_ALL}")
            print(self._header_line())
            for c in pins: print(self._fmt(c))

        ranked_up = self._ranked(arr, top=True)
        winners = []
        for c in ranked_up:
            if len(winners)>=self.topN: break
            winners.append(c)

        ranked_dn = self._ranked(arr, top=False, exclude_pids=set(x.pid for x in winners))
        losers = []
        for c in ranked_dn:
            if len(losers)>=self.topN: break
            losers.append(c)

        print(f"\n{Fore.GREEN}== WINNERS =={Style.RESET_ALL}")
        print(self._header_line())
        for c in winners: print(self._fmt(c))

        print(f"\n{Fore.RED}== LOSERS =={Style.RESET_ALL}")
        print(self._header_line())
        for c in reversed(losers): print(self._fmt(c))

        print(f"\nNext cycle in {self._time_to_next_min():.1f}s\n")

    # ---- Accounts (from probe) ----
    def refresh_accounts(self):
        """Populate self.accounts using the exact probe logic (JWT/HMAC; style=auto unless forced)."""
        self.accounts = {}
        creds = load_creds()
        api_key = creds.get('api-key') or creds.get('api_key') or ""
        api_secret = creds.get('api-secret') or creds.get('api_secret') or ""
        auth = (creds.get('auth') or 'jwt').lower()
        jwt_style = (creds.get('jwt_style') or 'auto').lower()
        exp_s = int(creds.get('jwt_exp_s', 120))

        if auth == "hmac":
            r = do_request_hmac(api_key, api_secret, method="GET", path=ACCOUNTS_PATH, params={"limit":250})
            try: j = r.json()
            except Exception:
                print(f"accounts non-JSON {getattr(r,'status_code','?')}: {(r.text or '')[:200]}"); return
            if r.status_code != 200:
                print(f"accounts HTTP {r.status_code}: {j}"); return
            for acct in j.get("accounts", []):
                cur = acct.get("currency", "")
                bal = acct.get("available_balance", {}).get("value", "0")
                key = f"{cur}-USD" if cur and cur != "USD" else cur or "USD"
                self.accounts[key] = {"currency": {"code": cur}, "available": bal}
            print(f"[accounts: {len(self.accounts)}]"); return

        # JWT path
        priv_sources = {
            "private_key_b64": creds.get("private_key_b64") or creds.get("private_key"),
            "private_key_hex": creds.get("private_key_hex"),
            "private_key_pem": creds.get("private_key_pem"),
            "private_key_openssh": creds.get("private_key_openssh"),
        }
        key = ed25519_from_sources(priv_sources)
        if not key:
            print("[auth] No Ed25519 key available; set auth:'hmac' to test HMAC instead."); return

        styles = [jwt_style] if jwt_style in ("cdp","coinbase") else ["cdp","coinbase"]
        last_status = None
        for style in styles:
            if style == "cdp":
                tok, hdr, pay = jwt_cdp(api_key, key, exp_s=exp_s)
                r = do_request_with_bearer(tok, path=ACCOUNTS_PATH, params={"limit":250})
                last_status = r.status_code
                if r.status_code == 200:
                    j = r.json()
                    for acct in j.get("accounts", []):
                        print(f"{acct}")
                        cur = acct.get("currency", "")
                        bal = acct.get("available_balance", {}).get("value", "0")
                        key2 = f"{cur}-USD" if cur and cur != "USD" else cur or "USD"
                        self.accounts[key2] = {"currency": {"code": cur}, "available": bal}
                    print(f"[accounts: {len(self.accounts)}]"); return
            elif style == "coinbase":
                tok, hdr, pay = jwt_coinbase(api_key, key, exp_s=exp_s)
                r = do_request_with_bearer(tok, path=ACCOUNTS_PATH, params={"limit":250})
                last_status = r.status_code
                if r.status_code == 200:
                    j = r.json()
                    for acct in j.get("accounts", []):
                        cur = acct.get("currency", "")
                        bal = acct.get("available_balance", {}).get("value", "0")
                        key2 = f"{cur}-USD" if cur and cur != "USD" else cur or "USD"
                        self.accounts[key2] = {"currency": {"code": cur}, "available": bal}
                    print(f"[accounts: {len(self.accounts)}]"); return

        print(f"accounts non-JSON {last_status}: Unauthorized "); print("[accounts: 0]")

    def _print_accounts(self):
        if not self.accounts:
            print("(no accounts cached; run 'acct' to refresh)"); return
        print(f"\n{Fore.CYAN}== ACCOUNTS =={Style.RESET_ALL}")
        h1,h2,h3 = "Currency","Available","Native (if any)"
        print(f"{h1:>12}  {h2:>20}  {h3:>16}")
        print("-"*52)
        for cur, a in sorted(self.accounts.items()):
            bal = a.get("available") or a.get("balance",{}).get("amount","0")
            nat = a.get("native_balance",{}).get("amount","")
            print(f"{cur:>12}  {bal:>20}  {nat:>16}")
            print(f"{a}")
        print()

    # --- views ---
    def save_state(self):
        with self._lock:
            data={"tunables":{"p1":self.p1,"v1":self.v1,"pa":self.pa,"pv":self.pv,"ps":self.ps,"topN":self.topN,
                               "hysteresis_margin":self.hysteresis_margin},
                  "pinned":list(self.pinned),
                  "prev":{"winners":self.prev_winners,"losers":self.prev_losers},
                  "channels":{pid:{"price":c.price,"vol24":c.vol24,"hi24":c.hi24,"lo24":c.lo24,"hist":list(c.history),
                                   "min_keys":list(c._min_keys),
                                   "min_data":{int(k):v for k,v in c._min_data.items()}
                                   }
                              for pid,c in self.channels.items()}}
        json.dump(data,open(STATE_FILE,"w"),indent=2)
        print(f"[saved {STATE_FILE}]")

    def load_state(self):
        try:
            data=json.load(open(STATE_FILE))
            t=data.get("tunables",{})
            self.p1=t.get("p1",self.p1); self.v1=t.get("v1",self.v1)
            self.pa=t.get("pa",self.pa); self.pv=t.get("pv",self.pv)
            self.ps=t.get("ps",self.ps); self.topN=t.get("topN",self.topN)
            self.hysteresis_margin=t.get("hysteresis_margin",self.hysteresis_margin)
            pins=set(data.get("pinned",[])); pins.add(BTC_PID); self.pinned=pins
            prev=data.get("prev",{})
            self.prev_winners=prev.get("winners",[]); self.prev_losers=prev.get("losers",[])
            chs=data.get("channels",{})
            with self._lock:
                self.channels.clear()
                for pid,info in chs.items():
                    c=Channel({"product_id":pid,"price":info.get("price",0.0),
                               "volume_24h":info.get("vol24",0.0),
                               "high_24h":info.get("hi24",0.0),
                               "low_24h":info.get("lo24",0.0),
                               "side":"buy"},
                               init_min=self.current_min)
                    mk = info.get("min_keys",[])
                    md = info.get("min_data",{})
                    c._min_keys = deque(mk, maxlen=MINI_HIST_MINUTES)
                    c._min_data = {int(k):v for k,v in md.items()}
                    c._cur_min = self.current_min
                    if self.current_min not in c._min_data:
                        c._min_keys.append(self.current_min)
                        c._min_data[self.current_min] = {
                            "p_start": c.price, "p_last": c.price,
                            "v_start": c.vol24, "v_last": c.vol24, "net": 0,
                            "money_buy": 0.0, "money_sell": 0.0, "vol_buy": 0.0, "vol_sell": 0.0
                        }
                    self.channels[pid]=c
            print(f"[loaded {STATE_FILE}]")
        except Exception as e:
            print("load failed:",e)

    # --- UI ---
    def help(self):
        print(f"""
Commands:
  w                stream winners/losers (press q to stop)
  pin <PID>        pin currency (BTC is always pinned)
  unpin <PID>      unpin currency (BTC cannot be unpinned)
  s                save state
  o                load state
  p1/v1/pa/pv/ps <x> adjust thresholds (p1 applies per window for 'A' flag)
  n <k>            set topN
  g                toggle raw plog
  acct             refresh accounts and show balances
  q                quit

Resolutions: {RES_WINDOWS} seconds
""")
    def _input(self):
        self.help()
        while not self._stop.is_set():
            r,_,_=select.select([sys.stdin],[],[],0.25)
            if not r: continue
            parts=sys.stdin.readline().strip().split()
            if not parts: continue
            c0=parts[0]
            if c0=="q": self._stop.set(); break
            elif c0=="w": self.stream()
            elif c0=="pin" and len(parts)>1:
                pid=parts[1].upper()
                self.pinned.add(pid); self.pinned.add(BTC_PID)
                print("pinned",pid)
            elif c0=="unpin" and len(parts)>1:
                pid=parts[1].upper()
                if pid==BTC_PID: print("BTC is permanently pinned")
                else: self.pinned.discard(pid); print("unpinned",pid)
            elif c0=="s": self.save_state()
            elif c0=="o": self.load_state()
            elif c0=="g": self.raw_plog=not self.raw_plog; print("raw_plog=",self.raw_plog)
            elif c0=="acct":
                self.refresh_accounts(); self._print_accounts()
            elif c0 in ("p1","v1","pa","pv","ps","n") and len(parts)>1:
                if c0=="n":
                    self.topN = int(parts[1]); print(f"topN={self.topN}")
                else:
                    val=float(parts[1]); setattr(self,c0,val); print(f"{c0}={val}")
            else: print("unknown"); self.help()

    def stream(self,interval=2.0):
        print("\n[streaming; press q to stop]\n")
        while not self._stop.is_set():
            r,_,_=select.select([sys.stdin],[],[],0.05)
            if r and sys.stdin.readline().strip()=="q":
                print("[stopped]\n"); break
            self.print_winners_losers()
            time.sleep(interval)

    def start(self):
        self._load_products()
        threading.Thread(target=self._ws,daemon=True).start()
        threading.Thread(target=self._minute_roller,daemon=True).start()
        self._input()

if __name__=="__main__":
    app=Z26()
    try: app.start()
    except KeyboardInterrupt:
        app._stop.set(); print("bye")