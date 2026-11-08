# AWS Security Configuration Checker

An educational Python CLI that inspects selected AWS configurations and produces
JSON findings with illustrative HIPAA framework references. Includes a fictional
demo that runs without AWS credentials. Passing checks does not establish HIPAA
compliance; policy thresholds are lab assumptions, not universal legal rules.

## Start with the offline demo

Python 3.12+; the demo and tests use only the standard library.

```sh
python aws_checker.py --demo --output demo-report.json
python -m unittest discover -s tests -v
```

Inspect the JSON `mode`, `summary`, and `checks`. Results include control ID,
PASS/FAIL, severity, resource, details and suggested remediation. The numerical
score is the percentage of selected checks passed, not a compliance rating.
Reports are sensitive operational artifacts; keep real results out of Git.

## Implemented checks

| Service | Lab checks |
| --- | --- |
| S3 | Bucket encryption, bucket-level public-access-block settings, access logging |
| IAM | Root MFA, user MFA devices, illustrative password-policy baseline |
| CloudTrail | Active logging with multi-region configuration, log validation |
| RDS | Encryption and illustrative seven-day backup retention |
| VPC | Presence of flow logs and rules on default security groups |
| Monitoring | GuardDuty detector and AWS Config recorder status |

## Live collection

```sh
python -m pip install -r requirements.txt
aws configure sso --profile audit-readonly
# PowerShell: $env:AWS_PROFILE = "audit-readonly"
# macOS/Linux: export AWS_PROFILE=audit-readonly
python aws_checker.py --output live-report.json
```

Use a read-only audit role and an explicitly configured region through the AWS
credential chain. Never use root or embed access keys. Read-only API requests
inspect configuration; the program does not apply remediation. Missing SDK or
failed collection exits with status 2 and writes no new report. An old report
may still exist—always inspect its timestamp. Successful report generation exits
0 even when findings fail; it is not yet a CI policy gate.

## Architecture and limits

`SDK collectors -> configuration dictionary -> rule functions -> console + JSON`

Each `run_all()` resets findings. CLI options select input mode and output file.
Tests cover deterministic repeated runs, report metadata/counts and collection
failure behavior. CI runs these tests; no live AWS tests are implied.

Collection currently lacks complete pagination, cross-region enumeration and a
per-control UNKNOWN model. A collection error now aborts rather than fabricating
a complete report from defaults. Empty results, regional aggregates and missing
bucket-level blocks still require interpretation; they do not establish account
coverage or actual public reachability. Flow-log presence does not prove all
VPCs are logged. Checks are not a replacement for an evidence-based audit.

## Roadmap and contributions

Prioritize SDK-stub tests, paginated/regional collection, explicit
PASS/FAIL/UNKNOWN/NOT_APPLICABLE evidence, and separation of collection from rules.
Then add scoped IAM policy documentation and configurable baselines. Use
synthetic fixtures in contributions and explain false-positive/negative cases.
