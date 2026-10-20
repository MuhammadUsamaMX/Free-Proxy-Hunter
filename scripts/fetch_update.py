#!/usr/bin/env python3
"""
Free-Proxy-Hunter hourly pipeline (stdlib-only, Python 3.9+).

1) FETCH   — pull all sources listed in sources.txt (parallel-free sequential
             fetch keeps beacons honest; fallback URLs on failure, UA spoof,
             30s timeout, 25MB cap).
2) PARSE   — extract (host, port, protocol) claims in every known format,
             merged on (host, port): union of all source claims = check plan.
3) CHECK   — live protocol checks (real handshakes, not just socket connects):
                 http    : absolute-URI GET through the proxy
                 https   : CONNECT + TLS handshake + inner GET
                 socks5  : full RFC 1928 handshake + tunnel GET
                 socks4  : full socks4 handshake  + tunnel GET
             An endpoint is published for a protocol only when that exact
             protocol round-trips end to end.
4) EMIT    — verified-only lists in all formats + stats.json.

Usage:
    python3 fetch_update.py [--no-check] [--max-check N] [--jobs 800]
                            [--budget-sec 2400] [--out dir] [--source-filter a,b]
Sources: scripts/sources.txt (TSV: id, format, default_proto, urls[...])
"""
from __future__ import annotations

import argparse, asyncio, base64, csv, ipaddress, json, os, re, socket, ssl, sys, time
import urllib.parse, urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HERE = os.path.dirname(os.path.abspath(__file__))
UA = ("Mozilla/5.0 (X11; Linux x86_64) proxy-hunter/1.0 "
      "(+https://github.com/Free-Proxy-Hunter; hourly refresh ; contact via repo issues)")
MAX_BODY = 26_214_400                      # 25 MB per source response

JUDGE_PL = [                               # plain-phase judges (absolute-URI GET)
    ("http://www.msftconnecttest.com/connecttest.txt", "http"),
    ("http://www.gstatic.com/generate_204", "http"),
]
JUDGE_TLS = "https://checkip.amazonaws.com/"
REQ_TIMEOUT = 7.0
SRC_TIMEOUT = 30.0

PROTO_WARN = ("http", "https", "socks5", "socks4")
PROTO_ORDER = ["http", "https", "socks5", "socks4"]
SUPPORTED = {"http", "https", "socks4", "socks5"}

LINE_RE = re.compile(
    r"^(?:[a-zA-Z][a-zA-Z0-9.+.-]{1,10}:\/\/)?"     # optional scheme://
    r"(?:(?P<user>[^\s@:]+):(?P<pw>[^\s@]*)@)?"     # optional user:pass@
    r"(?P<host>(?:\d{1,3}(?:\.\d{1,3}){3})"        # ipv4
    r"|(?:\[[0-9a-fA-F:.]+\])"                     # [ipv6]
    r"|(?:[A-Za-z0-9][A-Za-z0-9._-]+))"            # hostname
    r":(?P<port>\d{1,5})"
)
SCHEME_ALIASES = {"http": "http", "https": "https", "socks": "socks5",
                  "socks4": "socks4", "socks5": "socks5", "socks4a": "socks4",
                  "socks5h": "socks5", "ss": None, "mtproto": None, "mtproxy": None}

# --------------------------------------------------------------------------- #
# SOURCES + DATA
# --------------------------------------------------------------------------- #
def load_sources(filter_ids=None):
    path = os.path.join(HERE, "sources.txt")
    sources = []
    with open(path) as f:
        for raw in f:
            line = raw.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 4:
                continue
            sid = parts[0].strip(); fmt = parts[1].strip()
            proto = parts[2].strip() or None
            urls = parts[3].split()
            if filter_ids and sid not in filter_ids:
                continue
            sources.append(dict(id=sid, format=fmt, default_proto=proto, urls=urls))
    return sources

@dataclass
class Claim:
    protos: set = field(default_factory=set)
    sources: set = field(default_factory=set)
    auth: tuple = (None, None)
    meta: dict = field(default_factory=dict)

    def note_meta(self, **kw):
        for k, v in kw.items():
            if v is None or v == "": continue
            cur = self.meta.get(k)
            if cur is None: self.meta[k] = v
            elif isinstance(cur, (int, float)) and isinstance(v, (int, float)):
                self.meta[k] = min(cur, v) if "latency" in k else max(cur, v)

@dataclass
class Pool:
    claims: dict = field(default_factory=dict)          # (host, port) -> Claim
    mtproto: list = field(default_factory=list)         # [{server,port,secret}]

    def claim(self, host, port, proto, src_id, auth=(None, None), **meta):
        if proto not in SUPPORTED: return
        key = (host, port)
        c = self.claims.get(key)
        if c is None:
            c = Claim(); self.claims[key] = c
        if auth != (None, None):
            c.auth = auth                # first source wins (all need same creds; rare)
        c.protos.add(proto); c.sources.add(src_id)
        c.note_meta(**meta)

STATUS_OK = {"up", "alive", "ok", "true", "online", "working"}

def http_get(url, timeout=SRC_TIMEOUT, cap=MAX_BODY):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read(cap)

def fetch_source(src) -> bytes:
    for url in src["urls"]:
        for attempt in range(2):
            try:
                status, body = http_get(url)
                if body: return body
            except Exception:
                pass
            if attempt == 0: time.sleep(2)
        print(f"  ! {src['id']:<26} failed: {url}", flush=True)
    return b""

# --------------------------------------------------------------------------- #
# PARSERS
# --------------------------------------------------------------------------- #
def parse_text(body: bytes, src, pool: Pool, default):
    n = 0
    for line in body.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "//", "--", " solidsnake ")): continue
        m = LINE_RE.match(line)
        if not m: continue
        scheme = (line.lower().split("://", 1)[0] if "://" in line else "")
        proto = SCHEME_ALIASES.get(scheme, None) if scheme else default
        if proto is None: continue
        host = m.group("host")
        if host.startswith("["): host = host[1:-1]
        try: port = int(m.group("port"))
        except ValueError: continue
        if not (1 <= port <= 65535): continue
        if not _valid_host(host): continue
        u = m.group("user"); p = m.group("pw")
        auth = (urllib.parse.unquote(u), urllib.parse.unquote(p)) if u else (None, None)
        pool.claim(host, port, proto, src["id"], auth)
        n += 1
    return n

def _valid_host(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]+\.[A-Za-z]{2,}$", host))

def parse_geonode(body: bytes, src, pool: Pool):
    try: doc = json.loads(body.decode("utf-8", "replace"))
    except Exception: return 0
    if not isinstance(doc, dict) or not isinstance(doc.get("data"), list): return 0
    n = 0
    for it in doc["data"]:
        n += _claim_geonode_row(it, src, pool)
    # auto-paginate
    total = int(doc.get("total") or 0)
    limit = int(doc.get("limit") or 500)
    page0 = int(doc.get("page") or 1)
    if total > limit and page0 == 1:
        template = src["urls"][0]
        pages_max = min((total // limit) + 2, 12)
        for page in range(2, pages_max + 1):
            url = re.sub(r"page=\d+", f"page={page}", template)
            got = None
            for attempt in range(3):
                try:
                    status, body2 = http_get(url)
                    doc2 = json.loads(body2.decode("utf-8", "replace"))
                    if doc2.get("data"):
                        got = doc2
                        break
                except Exception:
                    pass
                time.sleep(1.5 * (attempt + 1))
            if got is None:
                break
            for it in got.get("data", []):
                n += _claim_geonode_row(it, src, pool)
            time.sleep(0.4)
    return n

def _claim_geonode_row(it, src, pool):
    if not isinstance(it, dict): return 0
    ip = it.get("ip"); port = it.get("port")
    if not ip or port is None: return 0
    try: port = int(port)
    except (ValueError, TypeError): return 0
    if not _valid_host(ip): return 0
    meta = dict(anonymity=it.get("anonymityLevel"), country=it.get("country"),
                latency=it.get("responseTime") or it.get("latency"),
                uptime=it.get("upTime"))
    n = 0
    for p in (it.get("protocols") if isinstance(it.get("protocols"), list) else [it.get("protocols") or "http"]):
        p = str(p).lower().replace("socks4a", "socks4")
        if p in SUPPORTED:
            pool.claim(ip, port, p, src["id"], **meta); n += 1
    return n

def parse_objects_json(body: bytes, src, pool: Pool, shape):
    try: doc = json.loads(body.decode("utf-8", "replace"))
    except Exception: return 0
    rows = doc if isinstance(doc, list) else (doc.get("data") if isinstance(doc, dict) else None)
    if rows is None: return 0
    n = 0
    for it in rows:
        if not isinstance(it, dict): continue
        if shape == "proxyscrape":
            ip, port = it.get("ip"), it.get("port")
            proto = (it.get("protocol") or "http").lower()
            meta = dict(anonymity=it.get("anonymity"),
                        country=it.get("country_code") or it.get("country"),
                        latency=it.get("latency_ms"), uptime=it.get("uptime_percent"))
        else:  # hproxy
            pr = str(it.get("proxy") or "")
            if ":" not in pr: continue
            ip, _, p_ = pr.rpartition(":")
            port = p_
            proto = "http"
            meta = dict(anonymity=it.get("anonymity"), country=it.get("country"),
                        latency=it.get("latency_ms"), uptime=it.get("uptime_pct"))
            if it.get("alive") is False: continue
        if ip is None or port is None: continue
        try: port = int(port)
        except (ValueError, TypeError): continue
        if not _valid_host(ip): continue
        pool.claim(ip, port, proto, src["id"], **meta)
        n += 1
    return n

def parse_mtproxy_json(body: bytes, pool: Pool):
    try: doc = json.loads(body.decode("utf-8", "replace"))
    except Exception: return 0
    items = doc.get("proxies") if isinstance(doc, dict) else doc
    if not isinstance(items, list): return 0
    n = 0
    for it in items:
        if not isinstance(it, dict): continue
        server = it.get("server") or it.get("host")
        port, secret = it.get("port"), it.get("secret")
        if not server or port is None: continue
        if str(it.get("status", "up")).lower() not in STATUS_OK: continue
        try: port = int(port)
        except (ValueError, TypeError): continue
        pool.mtproto.append(dict(server=str(server), port=port,
                                 secret=str(secret or ""), country=it.get("country")))
        n += 1
    return n

def parse_mtproxy_txt(body: bytes, pool: Pool):
    n = 0
    for line in body.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        for kind in ("t.me/proxy?", "tg://proxy?"):
            if kind in line: line = line.split(kind, 1)[1]; break
        q = urllib.parse.parse_qs(line.strip(), keep_blank_values=True)
        server = (q.get("server") or [""])[0]
        port, secret = (q.get("port") or [""])[0], (q.get("secret") or [""])[0]
        if not server or not port: continue
        try: port = int(port)
        except ValueError: continue
        pool.mtproto.append(dict(server=server, port=port, secret=secret))
        n += 1
    return n

def parse_any(body: bytes, src, pool: Pool):
    fmt = src["format"]
    if fmt == "geonode":      return parse_geonode(body, src, pool)
    if fmt == "proxyscrape":  return parse_objects_json(body, src, pool, "proxyscrape")
    if fmt == "hproxy":       return parse_objects_json(body, src, pool, "hproxy")
    if fmt == "mtproxy_json": return parse_mtproxy_json(body, pool)
    if fmt == "mtproxy_txt":  return parse_mtproxy_txt(body, pool)
    return parse_text(body, src, pool, src["default_proto"] or "http")

# --------------------------------------------------------------------------- #
# CHECKS
# --------------------------------------------------------------------------- #
class CheckerError(Exception): pass

async def _topen(host, port, timeout=REQ_TIMEOUT):
    return await asyncio.wait_for(asyncio.open_connection(host, port), timeout)

def _auth_line(user, pw):
    if user is None: return ""
    tok = base64.b64encode(f"{user or ''}:{pw or ''}".encode()).decode()
    return f"Proxy-Authorization: Basic {tok}\r\n"

async def check_http_plain(host, port, user, pw, judge):
    jh, jp, jpath = judge
    reader, writer = await _topen(host, port)
    try:
        writer.write((f"GET http://{jh}:{jp}{jpath} HTTP/1.1\r\nHost: {jh}\r\n"
                      f"User-Agent: Mozilla/5.0 (X11; Linux x86_64) hunter\r\n"
                      f"Accept: */*\r\n{_auth_line(user, pw)}Connection: close\r\n\r\n").encode())
        await asyncio.wait_for(writer.drain(), 5)
        t0 = time.monotonic()
        resp = await asyncio.wait_for(reader.read(8192), 5)
        head = resp.split(b"\r\n\r\n", 1)[0].decode("utf-8", "replace")
        ok = head.startswith(("HTTP/1.1 204", "HTTP/1.0 204", "HTTP/1.1 200", "HTTP/1.0 200"))
        return (ok, round((time.monotonic() - t0) * 1000)) if ok else (False, None)
    finally:
        try: writer.close()
        except Exception: pass

def _tls_check_blocking(host, port, auth_line, jh, jp, jpath, timeout):
    """CONNECT + TLS + inner GET, on a blocking socket (thread-executed)."""
    import socket as _s, ssl, time as _t
    t0 = _t.monotonic()
    s = _s.create_connection((host, port), timeout=timeout)
    try:
        s.settimeout(timeout)
        s.sendall((f"CONNECT {jh}:{jp} HTTP/1.1\r\nHost: {jh}\r\n"
                   f"User-Agent: Mozilla/5.0 (X11; Linux x86_64) hunter\r\n"
                   f"{auth_line}\r\n").encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = s.recv(4096)
            if not chunk: return False
            head += chunk
            if len(head) > 8192: return False
        first = head.split(b"\r\n", 1)[0]
        if b" 200" not in first: return False
        try:
            ctx = ssl.create_default_context()
            ts = ctx.wrap_socket(s, server_hostname=jh)
        except ssl.SSLCertVerificationError:
            ctx = ssl._create_unverified_context()
            ts = ctx.wrap_socket(s, server_hostname=jh)
        try:
            ts.sendall((f"GET {jpath} HTTP/1.1\r\nHost: {jh}\r\n"
                        f"User-Agent: Mozilla/5.0 (X11; Linux x86_64) hunter\r\n"
                        f"Accept: */*\r\nConnection: close\r\n\r\n").encode())
            r2 = ts.recv(8192)
            ok = r2.startswith((b"HTTP/1.1 204", b"HTTP/1.0 204", b"HTTP/1.1 200", b"HTTP/1.0 200"))
            return (ok, round((_t.monotonic() - t0) * 1000)) if ok else (False, None)
        finally:
            try: ts.close()
            except Exception: pass
    finally:
        try: s.close()
        except Exception: pass

_tls_exec = None
def _tls_executor():
    global _tls_exec
    if _tls_exec is None:
        _tls_exec = ThreadPoolExecutor(max_workers=256, thread_name_prefix="tls")
    return _tls_exec

async def check_http_connect(host, port, user, pw, judge):
    """https:// claim — CONNECT + TLS + inner GET via worker thread."""
    jh, jp, jpath = judge
    loop = asyncio.get_running_loop()
    ok, lat = await loop.run_in_executor(
        _tls_executor(), _tls_check_blocking,
        host, port, _auth_line(user, pw), jh, jp, jpath, REQ_TIMEOUT + 2)
    return (ok, lat)

async def check_socks5(host, port, user, pw, judge):
    jh, jp, jpath = judge
    reader, writer = await _topen(host, port)
    try:
        writer.write(b"\x05\x01\x02" if user is not None else b"\x05\x01\x00")
        await asyncio.wait_for(writer.drain(), 4)
        sel = await asyncio.wait_for(reader.readexactly(2), 5)
        if sel[0] != 5: return (False, None)
        if user is not None and sel[1] == 2:
            ub, pb = (user or "").encode(), (pw or "").encode()
            writer.write(b"\x01" + bytes([len(ub)]) + ub + bytes([len(pb)]) + pb)
            await asyncio.wait_for(writer.drain(), 4)
            sel = await asyncio.wait_for(reader.readexactly(2), 5)
            if sel[1] != 0: return (False, None)
        elif sel[1] != 0 and user is not None:
            # proxy picked no-auth although we offered user/pass: fall back
            return (False, None)
        elif sel[1] != 0:
            return (False, None)
        if re.match(r"^[0-9.]+$", jh):
            writer.write(b"\x05\x01\x00\x01" + bytes(int(x) for x in jh.split(".")) + (jp).to_bytes(2, "big"))
        else:
            writer.write(b"\x05\x01\x00\x03" + bytes([len(jh)]) + jh.encode() + (jp).to_bytes(2, "big"))
        await asyncio.wait_for(writer.drain(), 4)
        resp = await asyncio.wait_for(reader.readexactly(4), 5)
        if resp[1] != 0: return (False, None)
        if resp[3] == 1: await asyncio.wait_for(reader.readexactly(6), 5)
        elif resp[3] == 4: await asyncio.wait_for(reader.readexactly(18), 5)
        t0 = time.monotonic()
        writer.write((f"GET {jpath} HTTP/1.1\r\nHost: {jh}\r\n"
                      f"User-Agent: Mozilla/5.0 (X11; Linux x86_64) hunter\r\n"
                      f"Accept: */*\r\nConnection: close\r\n\r\n").encode())
        await asyncio.wait_for(writer.drain(), 4)
        r2 = await asyncio.wait_for(reader.read(8192), 5)
        ok = r2.startswith((b"HTTP/1.1 204", b"HTTP/1.0 204", b"HTTP/1.1 200", b"HTTP/1.0 200"))
        return (ok, round((time.monotonic() - t0) * 1000)) if ok else (False, None)
    finally:
        try: writer.close()
        except Exception: pass

async def check_socks4(host, port, user, pw, judge):
    jh, jp, jpath = judge
    reader, writer = await _topen(host, port)
    try:
        if re.match(r"^[0-9.]+$", jh):
            j_ip = jh
        else:
            loop = asyncio.get_running_loop()
            j_ip = await loop.run_in_executor(None, socket.gethostbyname, jh)
        octs = [int(x) for x in j_ip.split(".")]
        uid = (user or "").encode()
        writer.write(bytes([0x04, 0x01]) + jp.to_bytes(2, "big") + bytes(octs) + uid + b"\x00")
        await asyncio.wait_for(writer.drain(), 4)
        resp = await asyncio.wait_for(reader.readexactly(8), 5)
        if resp[1] not in (0x5A, 90): return (False, None)
        t0 = time.monotonic()
        writer.write((f"GET {jpath} HTTP/1.1\r\nHost: {jh}\r\n"
                      f"User-Agent: Mozilla/5.0 (X11; Linux x86_64) hunter\r\n"
                      f"Accept: */*\r\nConnection: close\r\n\r\n").encode())
        await asyncio.wait_for(writer.drain(), 4)
        r2 = await asyncio.wait_for(reader.read(8192), 5)
        ok = r2.startswith((b"HTTP/1.1 204", b"HTTP/1.0 204", b"HTTP/1.1 200", b"HTTP/1.0 200"))
        return (ok, round((time.monotonic() - t0) * 1000)) if ok else (False, None)
    finally:
        try: writer.close()
        except Exception: pass

async def check_endpoint(pool_entry, judge_pl, judge_tl, sem):
    """For one (host, port): verify each claimed protocol, return {proto: latency}."""
    host, port = pool_entry["host"], pool_entry["port"]
    user, pw = pool_entry["user"], pool_entry["pw"]
    claims = pool_entry["protos"]
    out = {}
    async with sem:
        for proto in claims:
            if proto == "http":
                fn = lambda: check_http_plain(host, port, user, pw, judge_pl)
            elif proto == "https":
                fn = lambda: check_http_connect(host, port, user, pw, judge_tl)
            elif proto == "socks5":
                fn = lambda: check_socks5(host, port, user, pw, judge_pl)
            elif proto == "socks4":
                fn = lambda: check_socks4(host, port, user, pw, judge_pl)
            else:
                continue
            try:
                ok, lat = await fn()
            except (OSError, ssl.SSLError, asyncio.TimeoutError,
                    asyncio.IncompleteReadError, ValueError, CheckerError):
                ok, lat = False, None
            except Exception:
                ok, lat = False, None
            if ok: out[proto] = lat
    return out

# --------------------------------------------------------------------------- #
# ORCHESTRATION
# --------------------------------------------------------------------------- #
def judge_pair(spec):
    url = spec[0]
    u = urllib.parse.urlparse(url)
    return (u.hostname, (u.port or (443 if u.scheme == "https" else 80)), u.path or "/")

async def run_checks(pool: Pool, jobs, budget_sec, max_check):
    judge_pl = judge_pair(JUDGE_PL[0])
    judge_tl = judge_pair((JUDGE_TLS, "https"))
    entries = []
    for (host, port), c in pool.claims.items():
        protos = [p for p in PROTO_ORDER if p in c.protos]
        if protos:
            entries.append(dict(host=host, port=port, protos=protos,
                                user=c.auth[0], pw=c.auth[1],
                                weight=len(c.sources)))
    entries.sort(key=lambda e: -e["weight"])
    truncated = len(entries) - max_check if len(entries) > max_check else 0
    entries = entries[:max_check]

    sem = asyncio.Semaphore(jobs)
    deadline = time.monotonic() + budget_sec
    results = {}
    done = failed = 0

    async def one(e):
        nonlocal done, failed
        if time.monotonic() > deadline:
            failed += 1; return
        r = await check_endpoint(e, judge_pl, judge_tl, sem)
        if r:
            results[(e["host"], e["port"])] = dict(verified=r, auth=(e["user"], e["pw"]))
        done += 1

    step = max(jobs * 2, 100)
    for i in range(0, len(entries), step):
        if time.monotonic() > deadline:
            failed += len(entries) - i
            break
        await asyncio.gather(*[one(e) for e in entries[i:i+step]])
    return results, done, failed, truncated

# --------------------------------------------------------------------------- #
# OUTPUT
# --------------------------------------------------------------------------- #
def write_outputs(pool, results, stats, outdir):
    os.makedirs(outdir, exist_ok=True)
    verified_by = {p: set() for p in PROTO_ORDER}
    rows = []
    for key, c in pool.claims.items():
        r = results.get(key)
        if not r: continue
        host, port = key
        protos = sorted(r["verified"])
        for p in protos: verified_by[p].add((host, port))
        rows.append(dict(host=host, port=port, protocols=protos,
                         latency_ms=round(min(v for v in r["verified"].values()), 1),
                         sources=sorted(c.sources),
                         anonymity=c.meta.get("anonymity"),
                         country=c.meta.get("country")))
    rows.sort(key=lambda x: x["latency_ms"])

    def W(name, lines):
        with open(os.path.join(outdir, name), "w") as f:
            f.write("\n".join(lines) + ("\n" if lines else ""))
    for proto in PROTO_ORDER:
        W(f"{proto}.txt", [f"{proto}://{h}:{p}" for h, p in sorted(verified_by[proto])])
    W("all.txt", sorted(set(f"{p}://{r['host']}:{r['port']}" for r in rows for p in r["protocols"])))

    def metad(r):
        meta = pool.claims.get((r["host"], r["port"]))
        mm = meta.meta if meta else {}
        return {**r, "anonymity": mm.get("anonymity"), "country": mm.get("country"),
                "latency_ms": r["latency_ms"]}
    with open(os.path.join(outdir, "all.json"), "w") as f:
        json.dump([metad(r) for r in rows], f, indent=1)
    with open(os.path.join(outdir, "all.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["host", "port", "protocols", "latency_ms", "country", "anonymity", "sources"])
        for r in rows:
            mm = pool.claims.get((r["host"], r["port"]))
            w.writerow([r["host"], r["port"], ";".join(r["protocols"]), r["latency_ms"],
                        r["country"] or "", r["anonymity"] or "",
                        ";".join(r["sources"])])

    # MTProto (everything from mtproxy sources, deduped)
    seen, mt = set(), []
    for m in pool.mtproto:
        k = (m["server"], m["port"], m["secret"])
        if k in seen: continue
        seen.add(k)
        mt.append(f"tg://proxy?server={m['server']}&port={m['port']}&secret={m['secret']}")
    W("mtproxy.txt", mt)
    W("stats.json", json.dumps(stats, indent=1))
    counts = {p: len(verified_by[p]) for p in PROTO_ORDER}
    counts["all"] = len({(r['host'], r['port']) for r in rows})
    counts["mtproto_total"] = len(seen)
    return counts

def refresh_readme(outdir, counts, total_claims, srcstats, elapsed):
    """Update README 'LIVE STATS' block between <!-- DYN ... DYN --> markers."""
    path = os.path.join(ROOT, "README.md")
    if not os.path.exists(path): return
    with open(path) as f: txt = f.read()
    now = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    src_ok = sum(1 for v in srcstats.values() if v["ok"])
    block = ("\n<!-- DYN-STATS:BEGIN (auto-refreshed by fetch_update.py) -->\n"
             "**Last run:** {now} · **sources ok:** {src_ok}/{n_src} · "
             "**unique endpoints found:** {tot_claims:,} · runtime {el:.0f}s\n\n"
             "| list | verified count |\n|---|---|\n"
             "| {rows} |\n<!-- DYN-STATS:END -->\n").format(
        now=now, src_ok=src_ok, n_src=len(srcstats),
        tot_claims=total_claims, el=elapsed,
        rows="|\n".join("| `%s.txt` | %d |\n" % (p, counts.get(p, 0)) if False else
                        f"| `{p}.txt` | {counts.get(p, 0)} |" for p in PROTO_ORDER) )
    pat = re.compile(r"<!--\s*DYN-STATS:BEGIN.*?DYN-STATS:END\s*-->", re.S)
    new = pat.sub(lambda m: block.lstrip("\n"), txt) if pat.search(txt) else (txt.rstrip() + "\n" + block)
    with open(path, "w") as f: f.write(new)

# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-check", action="store_true")
    ap.add_argument("--jobs", type=int, default=800)
    ap.add_argument("--budget-sec", type=float, default=2400.0)
    ap.add_argument("--max-check", type=int, default=150_000)
    ap.add_argument("--out", default=os.path.join(ROOT, "proxies"))
    ap.add_argument("--source-filter", default="")
    args = ap.parse_args()
    filter_ids = set(args.source_filter.split(",")) if args.source_filter else None

    t0 = time.monotonic()
    sources = load_sources(filter_ids)
    pool = Pool()
    srcstats = {}
    for s in sources:
        body = fetch_source(s)
        if not body:
            if not s["urls"]:
                print(f"  ! {s['id']:<26} no urls configured", flush=True)
            srcstats[s["id"]] = dict(ok=False, count=0); continue
        try:
            n = parse_any(body, s, pool)
        except Exception as e:
            print(f"  ! {s['id']:<26} parse error {e}", flush=True); n = 0
        srcstats[s["id"]] = dict(ok=True, count=n)
        print(f"  + {s['id']:<26} {n:>6} claims", flush=True)

    total_claims = len(pool.claims)
    print(f"- unique endpoints: {total_claims}", flush=True)

    if args.no_check:
        results, done, failed, truncated = {}, 0, 0, 0
    else:
        results, done, failed, truncated = asyncio.run(run_checks(
            pool, args.jobs, args.budget_sec, args.max_check))
        print(f"- checked {done}, verified {len(results)}, dead {done - len(results)}, "
              f"skipped {failed}, truncated {truncated}", flush=True)

    stats = dict(sources=srcstats, unique_claims=total_claims,
                 checked=done, verified=len(results), skipped=failed,
                 truncated=truncated, runtime_sec=round(time.monotonic() - t0, 1))
    counts = write_outputs(pool, results, stats, args.out)
    print(f"- counts: {counts}", flush=True)
    refresh_readme(args.out, counts, total_claims, srcstats, time.monotonic() - t0)
    print(f"- done in {time.monotonic()-t0:.0f}s", flush=True)

if __name__ == "__main__":
    main()
