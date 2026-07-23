# ER-S04 retrieval specification

Source: `SL100.zip`, raw members `SL100/sl100-raw-data/2nd Data Extraction_with_suricata_netflows/WSUS.txt` and `SL100/sl100-raw-data/2nd Data Extraction_with_suricata_netflows/WIN2.txt`.

1. Apply `annotations/trigger_spec.json` to every event block in the declared
   source member and select `A0` by its deterministic strategy.
2. Use the exact byte ranges in `build/case.json` only as replay assertions and
   context locators, never as trigger predicates.
3. On the source host, retain the high-integrity custom remote-session process
   and the later PowerShell-created VNC-profile artifact.
4. On the target host, retain the source-to-target TCP/5985 connection and the
   `wsmprovhost.exe` PowerShell policy-test file creation in the same window.
5. Remove the numeric attack-step prefix, scenario topology names, supplied
   labels/mappings, and decision labels; anonymise both hosts and the user.
6. Record the exact source-member byte range and SHA-256 of every event block.

This is genuine cross-host correlation: source and target Sysmon independently
observe compatible parts of one remoting session. The package does not use the
inconsistent supplied timeline as outcome proof.
