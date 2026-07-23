# ER-S03 retrieval specification

Source: `SL100.zip`, raw members `SL100/sl100-raw-data/2nd Data Extraction_with_suricata_netflows/audit.log` and
`SL100/sl100-raw-data/2nd Data Extraction_with_suricata_netflows/drone_flight_logs.log`.

1. Apply `annotations/trigger_spec.json` to every audit group in the complete
   declared audit member and select `A0` deterministically.
2. Use audit serial 626718 only as a post-rule replay assertion and context
   join key; it is not part of the trigger predicate.
3. Retain the successful root-effective `ptrace` group whose `OBJ_PID`
   identifies QGroundControl as the target.
4. Retain the later flight records for accepted `COMPONENT_ARM_DISARM`, the
   disarmed state, and ground impact at 19.36427 m/s.
5. Remove the attack executable name that states the intended outcome, supplied
   malicious flags/timeline prose, dataset identities, and decision labels.
6. Preserve exact raw byte/line locators and hashes in provenance.

The two sensors describe one compatible control-host/vehicle window. Ground
truth uses the observed attachment and outcome, not the inconsistent supplied
timeline metadata.
