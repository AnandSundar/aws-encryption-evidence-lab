# Cloud Encryption Evidence Lab

**Creator:** GRC Engineering Club  
**Date:** September 2025  
**Focus:** Encryption-at-Rest Validation for AWS

---

## Overview

Encryption-at-rest is one of the most fundamental security controls in cloud environments. Auditors constantly ask: *"Can you prove all your data is encrypted?"* If you can't answer that with real evidence, it's a problem.

This lab helps you solve that problem. Instead of screenshots or ad-hoc checks, you'll automate encryption validation across S3 buckets and EBS volumes, assess KMS usage, and generate JSON/CSV reports mapped directly to SOC 2 and NIST requirements.

---

## What You'll Walk Away With

By the end of this lab, you'll have:

- A Python-based tool that validates S3, EBS, and KMS encryption settings
- JSON and CSV reports mapped to SOC 2 CC6.1 and NIST SC-28
- A portfolio-ready project that demonstrates encryption evidence collection
- A clear example for interviews and LinkedIn posts

---

## Compliance Mappings

| Control | Framework | Description |
|---------|-----------|-------------|
| CC6.1 | SOC 2 | Logical and physical access to information assets is limited to authorized users |
| SC-28 | NIST 800-53 | Protection of information at rest |

---

## Prerequisites

Before starting this lab, ensure you have:

1. **Python 3.8 or higher** installed
2. **AWS Account** with appropriate access
3. **AWS CLI** installed and configured
4. **AWS Credentials** configured (via AWS CLI or environment variables)

### AWS IAM Permissions Required

The following AWS IAM permissions are required for the script to run:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListBuckets",
        "s3:GetBucketEncryption",
        "s3:GetBucketLocation",
        "ec2:DescribeVolumes",
        "ec2:DescribeRegions",
        "kms:ListKeys",
        "kms:DescribeKey",
        "kms:GetKeyRotationStatus",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Setup Instructions

### Step 1: Create Your Project Directory

Create a new folder for this lab:

```bash
mkdir cloud-encryption-lab
cd cloud-encryption-lab
```

### Step 2: Create Virtual Environment

Create a Python virtual environment to isolate dependencies:

**On Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**On macOS/Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies

Install the required Python packages:

```bash
pip install boto3
```

Or install from requirements.txt:

```bash
pip install -r requirements.txt
```

### Step 4: Configure AWS Credentials

Ensure your AWS credentials are configured:

```bash
aws configure
```

Or set environment variables:

```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1
```

---

## Usage

### Basic Usage

Run the script with your AWS profile:

```bash
python encryption_validator.py
```

### Optional Arguments

```bash
python encryption_validator.py --region us-west-2 --output-dir ./reports
```

**Available Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `--region` | AWS region to scan | `us-east-1` |
| `--all-regions` | Scan all AWS regions | `False` |
| `--output-dir` | Output directory for reports | `./evidence` |
| `--profile` | AWS profile name | `default` |

---

## Understanding the Output

### 1. JSON Report (`encryption_report.json`)

The JSON report contains detailed findings with:

```json
{
  "scan_metadata": {
    "scan_date": "2025-09-10T12:00:00Z",
    "aws_account_id": "123456789012",
    "regions_scanned": ["us-east-1"],
    "total_resources_checked": 25
  },
  "summary": {
    "compliant": 18,
    "non_compliant": 5,
    "warning": 2,
    "compliance_percentage": 72
  },
  "findings": [
    {
      "resource_type": "AWS::S3::Bucket",
      "resource_id": "my-bucket",
      "status": "PASS",
      "risk_level": "LOW",
      "encryption_type": "AES256",
      "compliance_mappings": ["SOC 2 CC6.1", "NIST SC-28"]
    }
  ]
}
```

### 2. CSV Report (`encryption_summary.csv`)

The CSV summary provides audit-ready evidence:

| Resource Type | Resource ID | Status | Risk Level | Encryption Type | SOC 2 CC6.1 | NIST SC-28 |
|---------------|-------------|--------|-----------|-----------------|-------------|------------|
| S3 Bucket | my-bucket | COMPLIANT | LOW | AES256 | YES | YES |
| EBS Volume | vol-12345 | NON-COMPLIANT | HIGH | None | NO | NO |
| KMS Key | key-67890 | COMPLIANT | LOW | SSE-KMS | YES | YES |

---

## Risk Classifications

| Risk Level | Description | Example |
|------------|-------------|---------|
| **CRITICAL** | No encryption on sensitive data | Unencrypted EBS volume in production |
| **HIGH** | Missing default encryption | S3 bucket without default encryption |
| **MEDIUM** | KMS key without rotation | Customer-managed KMS key, rotation disabled |
| **LOW** | Suboptimal configuration | Using AES256 instead of SSE-KMS |

---

## Testing Scenarios

### Scenario 1: Compliant Environment

Create test resources that are fully compliant:

```bash
# Create encrypted S3 bucket
aws s3api create-bucket --bucket my-encrypted-bucket --region us-east-1
aws s3api put-bucket-encryption --bucket my-encrypted-bucket --server-side-encryption-configuration '{
  "Rules": [{
    "ApplyServerSideEncryptionByDefault": {
      "SSEAlgorithm": "AES256"
    }
  }]
}'
```

### Scenario 2: Mixed Compliance Environment

Create resources with varying encryption states:

```bash
# Create unencrypted S3 bucket (for testing)
aws s3api create-bucket --bucket my-unencrypted-bucket --region us-east-1
# Don't set encryption - this will be flagged
```

### Scenario 3: Non-Compliant Environment

Temporarily disable encryption to test detection:

```bash
# Create EBS volume without encryption
aws ec2 create-volume --availability-zone us-east-1a --size 10 --volume-type gp2
```

---

## Remediation Guidance

### S3 Bucket Encryption

**Issue:** S3 bucket lacks default encryption

**Remediation:**
```bash
aws s3api put-bucket-encryption --bucket BUCKET_NAME --server-side-encryption-configuration '{
  "Rules": [{
    "ApplyServerSideEncryptionByDefault": {
      "SSEAlgorithm": "AES256"
    }
  }]
}'
```

### EBS Volume Encryption

**Issue:** EBS volume not encrypted

**Note:** EBS volumes cannot be encrypted after creation. You must:
1. Create a snapshot
2. Copy the snapshot with encryption enabled
3. Create a new volume from the encrypted snapshot
4. Attach to the instance

### KMS Key Rotation

**Issue:** Customer-managed KMS key without automatic rotation

**Remediation:**
```bash
aws kms enable-key-rotation --key-id KEY_ID
```

---

## Compliance Evidence for Audits

When auditors request encryption evidence, provide:

1. **Executive Summary** - The summary section from the JSON report
2. **Detailed Findings** - The CSV report with all resources
3. **Risk Assessment** - Resources categorized by risk level
4. **Remediation Plan** - Action items for non-compliant resources

---

## For Your Portfolio

### Interview Talking Points

When asked about encryption validation, you can discuss:

- How you automated S3 encryption checks using boto3
- How you assessed EBS volume encryption across regions
- How you evaluated KMS key rotation policies
- How you mapped findings to SOC 2 and NIST requirements
- How you generated audit-ready reports in JSON and CSV formats

### LinkedIn Post Example

> "Just completed a GRC Engineering lab where I automated encryption-at-rest validation in AWS. Instead of screenshots, I now have JSON and CSV evidence showing S3, EBS, and KMS compliance with SOC 2 CC6.1 and NIST SC-28 requirements.
>
> The tool validates:
> - S3 bucket default encryption
> - EBS volume encryption status
> - KMS key rotation status
> - Generates audit-ready reports
>
> This is how we move GRC from manual checks to engineering."

---

## Troubleshooting

### Common Issues

**Issue:** `AccessDenied` error

**Solution:** Ensure your AWS credentials have the required IAM permissions listed in the Prerequisites section.

**Issue:** `NoCredentialsError`

**Solution:** Run `aws configure` and enter your credentials, or set the `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variables.

**Issue:** `Region not found`

**Solution:** Ensure you're using a valid AWS region code (e.g., `us-east-1`, `us-west-2`, `eu-west-1`).

---

## Extending the Lab

After completing this lab, consider:

1. **Adding RDS encryption checks** - Validate RDS instance encryption
2. **Implementing Lambda scans** - Run on schedule with AWS Lambda
3. **Creating CloudWatch alarms** - Alert on unencrypted resources
4. **Building a dashboard** - Visualize compliance over time
5. **Adding auto-remediation** - Automatically enable encryption when safe

---

## Resources

- [AWS S3 Encryption Documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html)
- [AWS EBS Encryption Documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html)
- [AWS KMS Key Rotation](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html)
- [SOC 2 Trust Services Criteria](https://www.aicpa.org/soc4so)
- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)

---

## License

This lab is provided exclusively to the GRC Engineering Club Patreon community.

---

## Support

For questions or issues, please engage with the GRC Engineering Club community on Patreon.

---

**Happy Building!** :lock::cloud:
