# 🏥 HIPAA AWS Security Compliance Checker (WORK IN PROGRESS)

A Python-based CLI tool that audits AWS configurations against **HIPAA Security Rule** requirements — helping healthcare organizations identify misconfigurations that could expose Protected Health Information (PHI).

---

## 🔍 What It Checks

| Category | Controls |
|----------|----------|
| **S3 Buckets** | Encryption at rest, public access blocking, access logging |
| **IAM** | Root MFA, user MFA enforcement, password policy strength |
| **CloudTrail** | Multi-region logging, log file validation |
| **RDS Databases** | Encryption at rest, backup retention >= 7 days |
| **VPC / Network** | Flow logs enabled, default security group lockdown |
| **Monitoring** | GuardDuty threat detection, AWS Config change tracking |

Each check maps directly to a **HIPAA Security Rule citation** (45 CFR Part 164).

---

## 🚀 Quick Start

```bash
# Clone the repo
git clone https://github.com/markthedev12/hipaa-aws-checker.git
cd hipaa-aws-checker

# Install dependencies
pip install -r requirements.txt

# Run in demo mode (no AWS credentials needed)
python checker.py
```

---

## 📋 Sample Output

```
============================================================
  HIPAA AWS COMPLIANCE REPORT
  Generated: 2026-04-27 21:00 UTC
============================================================
  Score:             52%
  Total Checks:      16
  Passed:            8
  Failed:            8
  Critical Failures: 4
============================================================

❌ [CRITICAL] HIPAA-S3-01
   Rule:     §164.312(a)(2)(iv) Encryption
   Check:    S3 bucket 'dev-test-bucket' must be encrypted at rest
   Fix:      Enable AES-256 or KMS encryption on the bucket

✅ [HIGH] HIPAA-IAM-02
   Rule:     §164.312(d) Authentication
   Check:    All IAM users must have MFA enabled
   Resource: iam::users
```

A full `hipaa_report.json` is saved after every run.

---

## 🔧 Extending to Real AWS (boto3)

This tool runs in **demo mode** by default using simulated config data.

To connect to a real AWS account:

1. Install and configure the AWS CLI:
```bash
pip install boto3 awscli
aws configure
```

2. Replace the `SIMULATED_AWS_CONFIG` block in `checker.py` with live boto3 calls:
```python
import boto3

s3 = boto3.client('s3')
buckets = s3.list_buckets()['Buckets']
```

> ⚠️ Always use a **read-only IAM role** when running security audits. Never use root credentials.

---

## 📁 Project Structure

```
hipaa-aws-checker/
├── checker.py          # Main compliance checker
├── hipaa_report.json   # Auto-generated report (after run)
├── requirements.txt    # Dependencies
└── README.md
```

---

## 🗺️ Roadmap

- [ ] Live boto3 AWS integration
- [ ] HTML report export
- [ ] Email alerting for critical failures
- [ ] Scheduled Lambda deployment
- [ ] CIS AWS Foundations Benchmark mapping
- [ ] Azure / SC-200 version (coming soon)

---

## 📚 HIPAA Security Rule References

- [HHS HIPAA Security Rule Summary](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- [AWS HIPAA Compliance Guide](https://aws.amazon.com/compliance/hipaa-compliance/)
- [NIST 800-66 HIPAA Implementation Guide](https://csrc.nist.gov/publications/detail/sp/800-66/rev-2/final)

---

## 👨‍💻 Author

**Mark Schwinn** — Cloud Security | Healthcare IT | AWS | Security+ | IAM

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)](https://linkedin.com/in/mark-schwinn-994625362)
[![GitHub](https://img.shields.io/badge/GitHub-markthedev12-black)](https://github.com/markthedev12)
