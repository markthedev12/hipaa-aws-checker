"""
HIPAA AWS Security Compliance Checker
======================================
Maps AWS configurations to HIPAA Security Rule requirements.
Checks for common misconfigurations that can expose Protected Health Information (PHI).

Usage:
    python aws_checker.py           # Live mode — requires configured AWS credentials
    python aws_checker.py --demo    # Demo mode — runs on simulated data, no credentials needed

Security Design:
    - Read-only by design: requires only SecurityAudit + ReadOnlyAccess IAM policies
    - No credentials stored in code: uses AWS CLI profile or IAM role
    - No external data transmission: report saved locally as JSON only

Author: Mark Schwinn | github.com/markthedev12
"""

import json
import sys
import datetime

# ──────────────────────────────────────────────────────────────
# DEMO MODE — Simulated AWS config for testing without credentials
# ──────────────────────────────────────────────────────────────

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
        },
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


# ──────────────────────────────────────────────────────────────
# LIVE MODE — Real boto3 AWS data collection
# Requires: pip install boto3 && aws configure
# IAM permissions needed: SecurityAudit, ReadOnlyAccess (read-only)
# ──────────────────────────────────────────────────────────────

def collect_live_aws_config():
    """
    Collects real AWS configuration data using boto3.
    Uses read-only API calls only — never modifies any resources.
    """
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError
    except ImportError:
        print("[ERROR] boto3 is not installed. Run: pip install boto3")
        print("        Or use demo mode: python aws_checker.py --demo")
        sys.exit(1)

    print("[*] Connecting to AWS...")
    config = {}

    # ── S3 ──────────────────────────────────────────────────
    print("[*] Checking S3 buckets...")
    s3 = boto3.client("s3")
    s3_buckets = []

    try:
        buckets = s3.list_buckets().get("Buckets", [])
        for bucket in buckets:
            name = bucket["Name"]
            encrypted = False
            public = False
            logging_enabled = False

            # Check encryption
            try:
                s3.get_bucket_encryption(Bucket=name)
                encrypted = True
            except ClientError as e:
                if e.response["Error"]["Code"] != "ServerSideEncryptionConfigurationNotFoundError":
                    pass  # Bucket exists but encryption not configured

            # Check public access block
            try:
                pub = s3.get_public_access_block(Bucket=name)
                block = pub["PublicAccessBlockConfiguration"]
                public = not (
                    block.get("BlockPublicAcls") and
                    block.get("BlockPublicPolicy") and
                    block.get("IgnorePublicAcls") and
                    block.get("RestrictPublicBuckets")
                )
            except ClientError:
                public = True  # No block config = potentially public

            # Check access logging
            try:
                log = s3.get_bucket_logging(Bucket=name)
                logging_enabled = "LoggingEnabled" in log
            except ClientError:
                pass

            s3_buckets.append({
                "name": name,
                "encrypted": encrypted,
                "public": public,
                "logging": logging_enabled,
            })
    except (ClientError, NoCredentialsError) as e:
        print(f"[WARNING] S3 check failed: {e}")

    config["s3_buckets"] = s3_buckets

    # ── IAM ─────────────────────────────────────────────────
    print("[*] Checking IAM configuration...")
    iam = boto3.client("iam")
    iam_config = {
        "mfa_enabled_root": False,
        "users_without_mfa": [],
        "password_policy": {"min_length": 0, "require_symbols": False},
    }

    try:
        # Root MFA check via account summary
        summary = iam.get_account_summary()["SummaryMap"]
        iam_config["mfa_enabled_root"] = summary.get("AccountMFAEnabled", 0) == 1

        # Users without MFA
        users = iam.list_users()["Users"]
        for user in users:
            mfa = iam.list_mfa_devices(UserName=user["UserName"])["MFADevices"]
            if not mfa:
                iam_config["users_without_mfa"].append(user["UserName"])

        # Password policy
        try:
            pp = iam.get_account_password_policy()["PasswordPolicy"]
            iam_config["password_policy"]["min_length"] = pp.get("MinimumPasswordLength", 0)
            iam_config["password_policy"]["require_symbols"] = pp.get("RequireSymbols", False)
        except ClientError:
            pass  # No password policy set

    except (ClientError, NoCredentialsError) as e:
        print(f"[WARNING] IAM check failed: {e}")

    config["iam"] = iam_config

    # ── CloudTrail ───────────────────────────────────────────
    print("[*] Checking CloudTrail...")
    ct_client = boto3.client("cloudtrail")
    ct_config = {"enabled": False, "multi_region": False, "log_validation": False}

    try:
        trails = ct_client.describe_trails(includeShadowTrails=False)["trailList"]
        if trails:
            ct_config["enabled"] = True
            for trail in trails:
                if trail.get("IsMultiRegionTrail"):
                    ct_config["multi_region"] = True
                if trail.get("LogFileValidationEnabled"):
                    ct_config["log_validation"] = True
    except (ClientError, NoCredentialsError) as e:
        print(f"[WARNING] CloudTrail check failed: {e}")

    config["cloudtrail"] = ct_config

    # ── RDS ─────────────────────────────────────────────────
    print("[*] Checking RDS instances...")
    rds_client = boto3.client("rds")
    rds_list = []

    try:
        instances = rds_client.describe_db_instances()["DBInstances"]
        for db in instances:
            rds_list.append({
                "name": db["DBInstanceIdentifier"],
                "encrypted": db.get("StorageEncrypted", False),
                "backup_retention": db.get("BackupRetentionPeriod", 0),
            })
    except (ClientError, NoCredentialsError) as e:
        print(f"[WARNING] RDS check failed: {e}")

    config["rds"] = rds_list

    # ── VPC ─────────────────────────────────────────────────
    print("[*] Checking VPC configuration...")
    ec2 = boto3.client("ec2")
    vpc_config = {"flow_logs_enabled": False, "default_sg_open": False}

    try:
        # Flow logs
        flow_logs = ec2.describe_flow_logs()["FlowLogs"]
        vpc_config["flow_logs_enabled"] = len(flow_logs) > 0

        # Default security group
        sgs = ec2.describe_security_groups(
            Filters=[{"Name": "group-name", "Values": ["default"]}]
        )["SecurityGroups"]
        for sg in sgs:
            if sg.get("IpPermissions") or sg.get("IpPermissionsEgress"):
                vpc_config["default_sg_open"] = True
                break
    except (ClientError, NoCredentialsError) as e:
        print(f"[WARNING] VPC check failed: {e}")

    config["vpc"] = vpc_config

    # ── GuardDuty ────────────────────────────────────────────
    print("[*] Checking GuardDuty...")
    gd = boto3.client("guardduty")
    gd_config = {"enabled": False}

    try:
        detectors = gd.list_detectors()["DetectorIds"]
        if detectors:
            detector = gd.get_detector(DetectorId=detectors[0])
            gd_config["enabled"] = detector.get("Status") == "ENABLED"
    except (ClientError, NoCredentialsError) as e:
        print(f"[WARNING] GuardDuty check failed: {e}")

    config["guardduty"] = gd_config

    # ── AWS Config ───────────────────────────────────────────
    print("[*] Checking AWS Config...")
    cfg = boto3.client("config")
    cfg_config = {"enabled": False}

    try:
        recorders = cfg.describe_configuration_recorders()["ConfigurationRecorders"]
        status = cfg.describe_configuration_recorder_status()["ConfigurationRecordersStatus"]
        if recorders and status and status[0].get("recording"):
            cfg_config["enabled"] = True
    except (ClientError, NoCredentialsError) as e:
        print(f"[WARNING] AWS Config check failed: {e}")

    config["config_service"] = cfg_config

    print("[*] Data collection complete.\n")
    return config


# ──────────────────────────────────────────────────────────────
# COMPLIANCE CHECKS
# ──────────────────────────────────────────────────────────────

results = []

def add(control_id, hipaa_rule, description, passed, severity, remediation, resource="", details=""):
    results.append({
        "control_id":  control_id,
        "hipaa_rule":  hipaa_rule,
        "description": description,
        "status":      "PASS" if passed else "FAIL",
        "severity":    severity,
        "remediation": remediation,
        "resource":    resource,
        "details":     details,
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
            "Enable S3 server access logging to a dedicated logging bucket",
            f"s3://{n}")
        add("HIPAA-S3-03", "§164.312(c)(1) Integrity Controls",
            f"S3 bucket '{n}' must block all public access",
            not b["public"], "CRITICAL",
            "Enable all four S3 Block Public Access settings",
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
        "Enforce MFA for all IAM users via IAM policy",
        "iam::users",
        f"Users missing MFA: {', '.join(no_mfa)}" if no_mfa else "")
    policy = iam["password_policy"]
    weak = policy["min_length"] < 12 or not policy["require_symbols"]
    add("HIPAA-IAM-03", "§164.308(a)(5)(ii)(D) Password Management",
        "IAM password policy must meet HIPAA complexity requirements",
        not weak, "MEDIUM",
        "Set minimum length >= 12, require symbols, rotate every 90 days",
        "iam::password-policy")

def check_cloudtrail(config):
    ct = config["cloudtrail"]
    add("HIPAA-CT-01", "§164.312(b) Audit Controls",
        "CloudTrail must be enabled and multi-region",
        ct["enabled"] and ct["multi_region"], "HIGH",
        "Enable CloudTrail with multi-region support in all regions",
        "cloudtrail")
    add("HIPAA-CT-02", "§164.312(c)(1) Integrity Controls",
        "CloudTrail log file validation must be enabled",
        ct["log_validation"], "MEDIUM",
        "Enable log file validation to detect log tampering",
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
            "Set automated backup retention period to minimum 7 days",
            f"rds::{n}",
            f"Current retention: {db['backup_retention']} days")

def check_network(config):
    vpc = config["vpc"]
    add("HIPAA-NET-01", "§164.312(e)(1) Transmission Security",
        "VPC Flow Logs must be enabled",
        vpc["flow_logs_enabled"], "HIGH",
        "Enable VPC Flow Logs and ship to CloudWatch Logs or S3",
        "vpc")
    add("HIPAA-NET-02", "§164.312(a)(1) Access Control",
        "Default security group must not allow open inbound or outbound access",
        not vpc["default_sg_open"], "HIGH",
        "Remove all inbound and outbound rules from the default VPC security group",
        "vpc::default-sg")

def check_monitoring(config):
    add("HIPAA-MON-01", "§164.308(a)(1)(ii)(D) Activity Review",
        "AWS GuardDuty must be enabled for threat detection",
        config["guardduty"]["enabled"], "HIGH",
        "Enable GuardDuty in all active regions",
        "guardduty")
    add("HIPAA-MON-02", "§164.308(a)(1)(ii)(D) Activity Review",
        "AWS Config must be enabled for configuration change tracking",
        config["config_service"]["enabled"], "MEDIUM",
        "Enable AWS Config to track resource configuration changes over time",
        "aws-config")

def run_all(config):
    check_s3(config)
    check_iam(config)
    check_cloudtrail(config)
    check_rds(config)
    check_network(config)
    check_monitoring(config)


# ──────────────────────────────────────────────────────────────
# REPORT OUTPUT
# ──────────────────────────────────────────────────────────────

def print_report():
    total    = len(results)
    passed   = sum(1 for r in results if r["status"] == "PASS")
    failed   = sum(1 for r in results if r["status"] == "FAIL")
    critical = sum(1 for r in results if r["status"] == "FAIL" and r["severity"] == "CRITICAL")
    score    = round((passed / total) * 100) if total else 0

    print("\n" + "=" * 60)
    print("  HIPAA AWS COMPLIANCE REPORT")
    print(f"  Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    print("=" * 60)
    print(f"  Score:             {score}%")
    print(f"  Total Checks:      {total}")
    print(f"  Passed:            {passed}")
    print(f"  Failed:            {failed}")
    print(f"  Critical Failures: {critical}")
    print("=" * 60)

    for r in results:
        icon = "✅" if r["status"] == "PASS" else "❌"
        print(f"\n{icon} [{r['severity']}] {r['control_id']}")
        print(f"   Rule:     {r['hipaa_rule']}")
        print(f"   Check:    {r['description']}")
        print(f"   Resource: {r['resource']}")
        if r["details"]:
            print(f"   Details:  {r['details']}")
        if r["status"] == "FAIL":
            print(f"   Fix:      {r['remediation']}")

    print("\n" + "=" * 60)

    report = {
        "generated_at": datetime.datetime.utcnow().isoformat(),
        "mode": "demo" if "--demo" in sys.argv else "live",
        "summary": {
            "score": score, "total": total,
            "passed": passed, "failed": failed,
            "critical_failures": critical,
        },
        "checks": results,
    }

    with open("hipaa_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print("  Full report saved to: hipaa_report.json")
    print("=" * 60 + "\n")


# ──────────────────────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    demo_mode = "--demo" in sys.argv

    if demo_mode:
        print("[*] Running in DEMO MODE — using simulated AWS config data.")
        print("[*] To audit a real AWS account run: python aws_checker.py\n")
        config = SIMULATED_AWS_CONFIG
    else:
        print("[*] Running in LIVE MODE — connecting to AWS...")
        print("[*] Ensure your AWS CLI is configured and you have read-only permissions.\n")
        config = collect_live_aws_config()

    run_all(config)
    print_report()
