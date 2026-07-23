# ER-C04 retrieval specification

Source: `ait_ads.zip`, member `russellmitchell_wazuh.json`.

1. Apply `annotations/trigger_spec.json` to every record in the declared member
   and select the earliest matching package-manager request as `A0`.
2. Use exact line locators only as replay assertions and to retain the
   associated 33-millisecond request burst from the same internal endpoint.
3. Retain the HTTP facts needed to interpret the burst: Debian APT user agent,
   official repository hostnames, `InRelease` paths, and observed status codes.
4. Select only the endpoint-side source address and remove NAT-side duplicates.
5. Exclude the IDS signature, its `Not Suspicious Traffic` category, Wazuh rule
   prose, scenario/phase labels, and all decision labels.

The counter classification follows affirmative model-visible context, not the
corpus label: one package-manager user agent requests base, security, and
update-channel metadata from official Ubuntu repositories, including an HTTP
304 response.
