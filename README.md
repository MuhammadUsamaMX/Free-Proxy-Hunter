# Free-Proxy-Hunter

[![fetch-and-verify](https://github.com/MuhammadUsamaMX/Free-Proxy-Hunter/actions/workflows/fetch.yml/badge.svg)](.github/workflows/fetch.yml)
*Verified every 6 hours — free proxy lists fetched from 30+ public sources,
merged into unique endpoints, and live handshake-verified before publication.*

Quick fetch one-liners point at this repo's raw outputs.

Every 6 hours the workflow:

1. **fetches** 30+ public proxy sources (scheme-lists, plain IP:port lists,
   geonode / proxyscrape / hproxy JSON APIs, MTProto feeds),
2. **merges** everything into unique endpoints — the claims of every source
   are unioned per `host:port`, so an endpoint claimed by 5 sources is
   checked first,
3. **live-verifies** each endpoint with real protocol handshakes
   (not just "is the socket open"), then
4. **emits** clean verified-only lists in every common format.

Only proxies that round-trip end-to-end end up in the lists.

## Lists (all `proxies/`)

| file | contents |
|---|---|
| `http.txt`   | `http://ip:port` (plain http proxies) |
| `https.txt`  | `https://ip:port` (CONNECT + TLS verified) |
| `socks4.txt` | `socks4://ip:port` (socks4 handshake-verified) |
| `socks5.txt` | `socks5://ip:port` (socks5 handshake-verified) |
| `all.txt`    | every verified proxy, scheme-qualified (deduped) |
| `all.json`   | metadata per proxy: protocols, latency, country, anonymity, sources |
| `all.csv`    | same as CSV |
| `mtproxy.txt`| MTProto (Telegram) proxies as `tg://proxy?...` links |
| `stats.json` | per-run stats: per-source claim counts, checked/verified, timing |

Quick fetch one-liners:

```bash
curl -o http.txt   https://raw.githubusercontent.com/MuhammadUsamaMX/Free-Proxy-Hunter/main/proxies/http.txt
curl -o all.json   https://raw.githubusercontent.com/MuhammadUsamaMX/Free-Proxy-Hunter/main/proxies/all.json
```

## How verification works

| claim | check |
|---|---|
| `http` | absolute-URI `GET http://judge/...` through the proxy; must answer `HTTP 204/200` |
| `https` | `CONNECT` tunnel to judge, real TLS handshake, encrypted `GET` |
| `socks5` | RFC 1928 handshake (auth negotiation), judge `GET` inside tunnel |
| `socks4` | RFC socks4 handshake, judge `GET` inside tunnel |
| `mtproto` | listed as reported by mtproxy feeds (not handshaked) |

Judges: `msftconnecttest.com` / `gstatic.com` (plain phase) and
`checkip.amazonaws.com` (TLS phase). Endpoints are checked in order of
source-claim weight; a per-run time budget (40 min) bounds the queue —
the tail (usually dead weight) is logged in `stats.json` as `skipped`.

A proxy verified an hour ago can still die tomorrow — nothing on the free
web is guaranteed; treat the lists as an hourly snapshot of what was alive.

## Layout

```
.github/workflows/fetch.yml   hourly cron + auto-commit of fresh lists
scripts/fetch_update.py       whole pipeline (stdlib only — no pip install)
scripts/sources.txt           source registry: id / format / default proto / urls (fallbacks)
proxies/                      generated output lists (committed every run)
```

## Run locally

```bash
python3 scripts/fetch_update.py --no-check                 # fetch + merge only
python3 scripts/fetch_update.py --max-check 2000           # verify a small sample
python3 scripts/fetch_update.py --source-filter sunny9577,monosans
python3 scripts/fetch_update.py --jobs 800 --budget-sec 600
```

## Adding a source

Append one tab-separated line to `scripts/sources.txt`:

```
<id>	<format>	<default_proto>	<url> [fallback_url ...]
```

* `format`: `txt` (plain or scheme list), `geonode`, `proxyscrape`,
  `hproxy`, `mtproxy_json`, `mtproxy_txt`
* `default_proto`: protocol for scheme-less `ip:port` lines
  (blank for scheme list sources)
* fallback urls are tried in order (e.g. jsdelivr mirrors of the same file)

## Sources handled

azestkingscrown, sunny9577, ALIILAPRO, proxio-io, ErcinDedeoglu (4 lists),
geonode API (auto-paginated), tgmtproxy (JSON + t.me text), proxyscrape
(JSON + TXT), hproxy JSON, TheSpeedX SOCKS-List/PROXY-List, SoliSpirit
(4 lists), stormsia, maximilianfeix, monosans, 6yyn, dpangestuw,
VPSLab (all + elite). ALIILAPRO raw URLs sit behind Cloudflare for CI
ranges — the jsdelivr mirror is wired in as fallback for every source.

## Legal

These are publicly-mediated free endpoints. Content from endpoints you
browse through may be untrustworthy — treat outputs as unreliable network
hops, not as privacy tools. Verify against your own policies before use.

<!-- DYN-STATS:BEGIN (auto-refreshed by fetch_update.py) -->
**Last run:** 2026-10-27 12:42 UTC · **sources ok:** 31/31 · **unique endpoints found:** 233,556 · runtime 2448s

| list | verified count |
|---|---|
| | `http.txt` | 2173 ||
| `https.txt` | 362 ||
| `socks5.txt` | 1875 ||
| `socks4.txt` | 681 | |
<!-- DYN-STATS:END -->


























