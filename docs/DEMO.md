# Demonstration Runbook

## Goal

Demonstrate evidence-backed AI diagnosis and controlled authority, then prove that the temporary AWS environment was removed.

## Recording sequence

1. Show the architecture, CI safety tests, and Terraform plan.
2. Show the EKS workloads, Argo CD `Healthy/Synced` state, and Grafana metrics.
3. Port-forward the API: `kubectl -n sentinelops port-forward service/sentinelops 8080:80`.
4. Submit `examples/alerts/crashloop.json` to `/v1/incidents/analyze`.
5. Highlight the retrieved runbook, read-only tool observation, diagnosis, confidence, and citations.
6. Attempt an unapproved or modified action and show the policy rejection.
7. Request an approval, execute the approved action, and show `simulated_success`.
8. Replay the same approval and show that it is rejected.
9. Display `/v1/audit`, including chain validity and linked event hashes.
10. Show AI request latency, incident count, and policy metrics in Grafana.
11. Run the golden evaluation dataset and show all cases passing.
12. Trigger the destroy workflow and confirm EKS, EC2, NAT, DynamoDB, SQS, S3, ECR, and KMS cleanup.

## Evidence to retain

- Green CI workflow
- Bedrock-backed incident report with account details hidden
- Argo CD and Grafana screenshots
- Policy rejection and single-use approval demonstrations
- Evaluation output
- Successful destroy workflow and AWS resource checks
