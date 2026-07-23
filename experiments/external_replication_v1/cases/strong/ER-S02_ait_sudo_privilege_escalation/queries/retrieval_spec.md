# ER-S02 retrieval specification

Source: `ait_ads.zip`, members `harrison_wazuh.json` and
`harrison_aminer.json`.

1. Apply `annotations/trigger_spec.json` to the complete declared Wazuh member;
   the deterministic match is `A0`.
2. Use exact source locators only to verify that replay and to recover the
   correlated context, not to define the alert.
3. Retain the intranet-server auth records for the `www-data -> jward` su
   session around the matched sudo command.
4. From the AMiner member, retain the Linux Audit `USER_CMD` record for process
   28346 with `res=success` and its matching successful root `USER_START` event.
5. Hex-decode the audit command into DER-001.
6. Exclude detector descriptions, phase labels, unrelated hosts, DNS/mail
   records, and all decision labels. Anonymise the service account, user, host,
   and site domain deterministically.

The two sources observe the same host, command, process, and second, so this is
genuine auth-log + audit-log correlation rather than duplicated detector output.
