# ER-S01 retrieval specification

Source: `ait_ads.zip`, member `russellmitchell_aminer.json`.

1. Stream the JSONL member without extracting the 2.86 GB archive.
2. Apply `annotations/trigger_spec.json` to every record in the declared member
   and select `A0` with its deterministic strategy.
3. Treat the exact line and SHA-256 in `build/case.json` as a replay assertion,
   not as part of the trigger predicate.
4. Parse the underlying Apache access line into timestamp, source, method, URL,
   status, response size, and user agent.
5. URL-decode and Base64-decode `wp_meta` as UTF-8 JSON. Replace the password
   argument with `[redacted-password]` before emitting DER-001.
6. Omit AMiner detector prose, AIT phase labels, scenario identity, and all
   decision labels from the model package.

The selected JSONL line number and SHA-256 are written to `source/provenance.json`.
