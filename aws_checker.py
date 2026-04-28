"""
HIPAA AWS Security Compliance Checker
======================================
Maps AWS configurations to HIPAA Security Rule requirements.
Checks for common misconfigurations that can expose PHI.

Author: Mark Schwinn | github.com/markthedev12
"""

import json
import datetime

# ──────────────────────────────────────────────
# SIMULATED AWS CONFIG (Demo Mode)
# Replace with real boto3 calls once you have AWS creds
# ──────────────────────────────────────────────

SIMULATED_AWS_CONFIG = {
    "s3_buckets": [
        {"name": "phi-patient-records", "public": False, "encrypted": True,  "logging": True},
        {"name": "hospital-backups",    "public": False, "encrypted": True,  "logging": False},
        {"name": "dev-test-bucket",     "public": True,  "encrypted": False, "logging": False},
    ],
    "iam": {
        "mfa_enabled_root": False,
        "users_without_mfa": ["dev-user-1", "temp-admin"],
        "password_policy": {
            "min_length": 8,
            "require_symbols": False,
        }
    },
    "cloudtrail": {
        "enabled": True,
        "multi_region": False,
        "log_validation": True,
    },
    "rds": [
        {"name": "patient-db",    "encrypted": True,  "backup_retention": 7},
        {"name": "analytics-db",  "encrypted": False, "backup_retention": 1},
    ],
    "vpc": {
        "flow_logs_enabled": False,
        "default_sg_open": True,
    },
    "guardduty":      {"enabled": True},
    "config_service": {"enabled": False},
}


# ──────────────────────────────────────────────
# CHECKS
# ──────────────────────────────────────────────

results = []

def add(control_id, hipaa_rule, description, passed, severity, remediation, resource="", details=""):
    status = "PASS" if passed else "FAIL"
    results.append({
        "control_id":   control_id,
        "hipaa_rule":   hipaa_rule,
        "description":  description,
        "status":       status,
        "severity":     severity,
        "remediation":  remediation,
        "resource":     resource,
        "details":      details,
    })


def check_s3(config):
    for b in config["s3_buckets"]:
        n = b["name"]
        add("HIPAA-S3-01", "§164.312(a)(2)(iv) Encryption",
            f"S3 bucket '{n}' must be encrypted at rest",
            b["encrypted"], "CRITICAL",
            "Enable AES-256 or KMS encryption on the bucket",
            f"s3://{n}")

        add("HIPAA-S3-02", "§164.312(b) Audit Controls",
            f"S3 bucket '{n}' must have access logging enabled",
            b["logging"], "HIGH",
            "Enable S3 server access logging",
            f"s3://{n}")

        add("HIPAA-S3-03", "§164.312(c)(1) Integrity Controls",
            f"S3 bucket '{n}' must block all public access",
            not b["public"], "CRITICAL",
            "Enable S3 Block Public Access",
            f"s3://{n}")


def check_iam(config):
    iam = config["iam"]

    add("HIPAA-IAM-01", "§164.312(d) Authentication",
        "Root account must have MFA enabled",
        iam["mfa_enabled_root"], "CRITICAL",
        "Enable MFA on the AWS root account immediately",
        "iam::root")

    no_mfa = iam["users_without_mfa"]
    add("HIPAA-IAM-02", "§164.312(d) Authentication",
        "All IAM users must have MFA enabled",
        len(no_mfa) == 0, "HIGH",
        "Enforce MFA for all IAM users via policy",
        "iam::users",
        f"Users missing MFA: {', '.join(no_mfa)}" if no_mfa else "")

    policy = iam["password_policy"]
    weak = policy["min_length"] < 12 or not policy["require_symbols"]
    add("HIPAA-IAM-03", "§164.308(a)(5)(ii)(D) Password Management",
        "IAM password policy must meet HIPAA complexity requirements",
        not weak, "MEDIUM",
        "Set min length >= 12, require symbols, rotate every 90 days",
        "iam::password-policy")


def check_cloudtrail(config):
    ct = config["cloudtrail"]

    add("HIPAA-CT-01", "§164.312(b) Audit Controls",
        "CloudTrail must be enabled and multi-region",
        ct["enabled"] and ct["multi_region"], "HIGH",
        "Enable CloudTrail with multi-region support",
        "cloudtrail")

    add("HIPAA-CT-02", "§164.312(c)(1) Integrity Controls",
        "CloudTrail log file validation must be enabled",
        ct["log_validation"], "MEDIUM",
        "Enable log file validation to detect tampering",
        "cloudtrail")


def check_rds(config):
    for db in config["rds"]:
        n = db["name"]
        add("HIPAA-RDS-01", "§164.312(a)(2)(iv) Encryption",
            f"RDS instance '{n}' must be encrypted at rest",
            db["encrypted"], "CRITICAL",
            "Enable RDS encryption at rest using AWS KMS",
            f"rds::{n}")

        add("HIPAA-RDS-02", "§164.308(a)(7)(ii)(A) Data Backup",
            f"RDS instance '{n}' backup retention must be >= 7 days",
            db["backup_retention"] >= 7, "HIGH",
            "Set automated backup retention to minimum 7 days",
            f"rds::{n}",
            f"Current retention: {db['backup_retention']} days")


def check_network(config):
    vpc = config["vpc"]
    add("HIPAA-NET-01", "§164.312(e)(1) Transmission Security",
        "VPC Flow Logs must be enabled",
        vpc["flow_logs_enabled"], "HIGH",
        "Enable VPC Flow Logs and ship to CloudWatch or S3",
        "vpc")

    add("HIPAA-NET-02", "§164.312(a)(1) Access Control",
        "Default security group must not allow open access",
        not vpc["default_sg_open"], "HIGH",
        "Remove all rules from the default VPC security group",
        "vpc::default-sg")


def check_monitoring(config):
    add("HIPAA-MON-01", "§164.308(a)(1)(ii)(D) Activity Review",
        "AWS GuardDuty must be enabled for threat detection",
        config["guardduty"]["enabled"], "HIGH",
        "Enable GuardDuty in all regions",
        "guardduty")

    add("HIPAA-MON-02", "§164.308(a)(1)(ii)(D) Activity Review",
        "AWS Config must be enabled for change tracking",
        config["config_service"]["enabled"], "MEDIUM",
        "Enable AWS Config to track resource changes",
        "aws-config")


# ──────────────────────────────────────────────
# RUN ALL CHECKS
# ──────────────────────────────────────────────

def run_all(config):
    check_s3(config)
    check_iam(config)
    check_cloudtrail(config)
    check_rds(config)
    check_network(config)
    check_monitoring(config)


def print_report():
    total    = len(results)
    passed   = sum(1 for r in results if r["status"] == "PASS")
    failed   = sum(1 for r in results if r["status"] == "FAIL")
    critical = sum(1 for r in results if r["status"] == "FAIL" and r["severity"] == "CRITICAL")
    score    = round((passed / total) * 100) if total else 0

    print("\n" + "="*60)
    print("  HIPAA AWS COMPLIANCE REPORT")
    print(f"  Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    print("="*60)
    print(f"  Score:            {score}%")
    print(f"  Total Checks:     {total}")
    print(f"  Passed:           {passed}")
    print(f"  Failed:           {failed}")
    print(f"  Critical Failures:{critical}")
    print("="*60)

    for r in results:
        icon = "✅" if r["status"] == "PASS" else "❌"
        print(f"\n{icon} [{r['severity']}] {r['control_id']}")
        print(f"   Rule:       {r['hipaa_rule']}")
        print(f"   Check:      {r['description']}")
        print(f"   Resource:   {r['resource']}")
        if r["details"]:
            print(f"   Details:    {r['details']}")
        if r["status"] == "FAIL":
            print(f"   Fix:        {r['remediation']}")

    print("\n" + "="*60)

    # Save JSON report
    report = {
        "generated_at": datetime.datetime.utcnow().isoformat(),
        "summary": {
            "score": score,
            "total": total,
            "passed": passed,
            "failed": failed,
            "critical_failures": critical
        },
        "checks": results
    }
    with open("hipaa_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print("  Full report saved to: hipaa_report.json")
    print("="*60 + "\n")


# ──────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────

if __name__ == "__main__":
    run_all(SIMULATED_AWS_CONFIG)
    print_report()
