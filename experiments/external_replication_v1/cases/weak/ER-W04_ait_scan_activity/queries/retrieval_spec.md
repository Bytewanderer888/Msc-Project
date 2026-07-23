# ER-W04 retrieval specification

Source: `ait_ads.zip`, member `santos_wazuh.json`.

1. Apply `annotations/trigger_spec.json` to every record in the declared member
   and select the earliest matching request as `A0`.
2. Use exact line locators only to verify the replayed alert and recover its
   correlated same-transaction context.
3. Retain the two Apache access records from one client to the same web server
   for `/nmaplowercheck1642418506` and `/HNAP1`.
4. Retain the two network HTTP records with the same client, server, paths,
   methods, status codes, and sub-second timestamps.
5. Exclude Wazuh rule prose, IDS signatures/categories, duplicated fast.log
   records, mirrored copies of the same flow, phase labels, and all decision
   labels. Anonymise the client and server consistently.

Apache and network telemetry observe the same two HTTP transactions, so this
is genuine sensor correlation. The package establishes scan-like behaviour but
does not import the corpus phase label as proof of hostile intent.
