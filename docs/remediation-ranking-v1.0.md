# Remediation ranking 1.0.0

The backend returns a per-finding `remediation_rank`, reason and ruleset version.
This is a decision-ordering policy over recorded scan and business observations.
Existing categorical risk tiers, scores, recommendations and Mosca urgency retain
their recorded values. Ranking is derived when reading a run and requires no
rewrite of historical assessments.

The first descending dimension is protection context:

| Bucket | Required observed facts |
| --- | --- |
| 3 | Confidential/restricted data, confidentiality lifetime >= 5 years, internet exposure true |
| 2 | Confidential/restricted data and lifetime >= 5 years |
| 1 | Confidential/restricted data or high/critical business criticality |
| 0 | Other or insufficient context |

Five years is an explicit planning-policy threshold, not an estimate of quantum
computer arrival. Missing values never qualify as known sensitive, long-lived or
exposed inputs. Reasons state which context is unknown; missing values do not
establish that a finding is safe.

Within each bucket, descending tie-breakers are categorical technical risk,
Mosca urgency, sensitivity, internet exposure, data lifetime and criticality.
Finding ID is used only after all decision dimensions tie. Finding counts,
application size, recommendation count and evidence volume are never inputs.
Adding any number of bucket-0 findings cannot displace a bucket-3 finding.

The backend roadmap uses this rank before recommendation priority. The web queue
contains unique findings, so multiple recommendations cannot crowd out other
findings. Filtering preserves the backend rank and shows the rank from the full
run. The matrix displays persisted Mosca urgency and criticality membership;
cell color is the highest recorded risk of the filtered members, never their
count. Unknown/not-applicable urgency remain separate rows.
