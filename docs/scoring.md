# How priorities are assigned

The rules are a short table on purpose. A weighted score is harder to explain to
the person who has to patch the server, and harder to defend in an audit. Each
rule below maps to one line in the "Why" column of the output.

## Order of evidence

1. **Known exploitation (CISA KEV).** If CISA has confirmed exploitation in the
   wild, the finding is P1 regardless of CVSS. Zerologon on a domain controller
   is the classic case: it is internal, but it hands an attacker the domain.
2. **Predicted exploitation (EPSS).** EPSS estimates the probability of
   exploitation activity in the next 30 days. 0.5 or more on an internet-facing
   asset is P1. 0.1 or more anywhere is at least P2. Most CVEs score well under
   0.1, so 0.1 already separates the small set attackers actually go after.
3. **Exposure.** An unauthenticated, no-user-interaction network flaw rated
   9.0+ on an internet-facing asset is P1 even before it shows up in KEV,
   because that is exactly the profile that gets mass-exploited first.
4. **Severity (CVSS v3.1).** Used last, to order what is left.
5. **Asset criticality.** A high-criticality asset raises P3 or P4 by one tier.
   It never creates a P1, because criticality says how bad a compromise would
   be, not how likely one is.

## Due dates

| Priority | Days | Basis |
|---|---|---|
| P1 | 15 | CISA BOD 22-01 sets two weeks for newly added KEV entries |
| P2 | 30 | FedRAMP continuous monitoring: high risk findings |
| P3 | 90 | FedRAMP continuous monitoring: moderate risk findings |
| P4 | 180 | FedRAMP continuous monitoring: low risk findings |

Days count from `first_seen`, the date the scanner first reported the finding.
The POA&M "Original Risk Rating" column maps P1 and P2 to High, P3 to Moderate
and P4 to Low.

## CVSS source

If the scanner supplied a vector, that is used, since it may reflect the real
configuration. Otherwise the vector comes from NVD. When NVD lists more than one
v3 score, NVD's own assessment (source `nvd@nist.gov`) wins over the vendor's,
even when NVD has marked its own entry "Secondary", which happens on older
records such as CVE-2020-1472.

## ATT&CK mapping

The technique is chosen from the CVSS vector, the CWE and the asset:

| Signal | Technique |
|---|---|
| Availability impact only, or a resource exhaustion CWE | T1499.004 Endpoint DoS: Application or System Exploitation |
| Credential or secret exposure CWE with confidentiality impact | T1212 Exploitation for Credential Access |
| Local or physical attack vector | T1068 Exploitation for Privilege Escalation |
| Cross-site scripting (CWE-79) | T1189 Drive-by Compromise |
| Network vector that needs a user to act | T1203 Exploitation for Client Execution |
| Network vector, no user, internet-facing asset | T1190 Exploit Public-Facing Application |
| Network vector, no user, internal asset | T1210 Exploitation of Remote Services |

It is a heuristic and is labeled that way in every output.
