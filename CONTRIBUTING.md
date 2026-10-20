# Contribution notes

* If your proxy source emits a new JSON/event shape, add a parser branch in
  `scripts/fetch_update.py` (`parse_any`) and register it in
  `scripts/sources.txt`.
* Keep the checker honest: an endpoint is "verified" only after a full
  protocol round-trip through it. Never list connect-only results.
* Keep the pipeline dependency-free (stdlib) so the hourly Action needs no
  `pip install`.
* Judges change every few years; if a judge dies, pick another low-latency
  `204` endpoint and update `JUDGE_PL` / `JUDGE_TLS`.
