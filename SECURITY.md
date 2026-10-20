# Reporting potential issues

Public proxy lists are, by nature, paths to untrusted infrastructure.

* Found a bug or a broken output? Open an issue with the `stats.json`
  snippet of the failing run (it contains per-source counts).
* Want a source removed because you own it? Open an issue; it will be
  dropped from `scripts/sources.txt` on the next run.
* Do not use the lists as a security boundary. Endpoints are community
  hops of unknown ownership; nothing is logged here except aggregate
  counts per run.
