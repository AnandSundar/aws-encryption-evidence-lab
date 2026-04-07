# Quick Start Guide

Get up and running with the Cloud Encryption Evidence Lab in 5 minutes.

## 1. Prerequisites Check

```bash
# Check Python version (need 3.8+)
python --version

# Check if AWS CLI is installed
aws --version

# Check if AWS credentials are configured
aws sts get-caller-identity
```

If the last command returns an error, configure AWS credentials:

```bash
aws configure
```

## 2. Setup (One-Time)

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## 3. Run Your First Scan

```bash
# Basic scan (us-east-1 region)
python encryption_validator.py

# Scan all regions
python encryption_validator.py --all-regions

# Use a specific AWS profile
python encryption_validator.py --profile your-profile-name

# Verbose output for debugging
python encryption_validator.py --verbose
```

## 4. View Results

After running, check the `evidence/` folder:

```bash
# View JSON report (detailed)
cat evidence/encryption_report.json

# View CSV report (spreadsheet-friendly)
cat evidence/encryption_summary.csv
```

## 5. Understanding the Output

| Status | Meaning | Action Required |
|--------|---------|-----------------|
| PASS | Resource is encrypted | None |
| FAIL | Resource is NOT encrypted | Remediate immediately |
| WARNING | Could not verify | Investigate manually |

## Common Issues

**"AccessDenied" error?**
→ Your AWS credentials lack the required permissions. See README.md for the full IAM policy.

**"NoCredentialsError"?**
→ Run `aws configure` or set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variables.

**Script hangs?**
→ Press Ctrl+C to interrupt. Some regions may take longer to scan.

## Next Steps

1. Review the findings in the generated reports
2. Remediate any non-compliant resources
3. Add the script to a CI/CD pipeline for continuous monitoring
4. Share your experience with the GRC Engineering Club!

---

For detailed documentation, see [README.md](README.md).
