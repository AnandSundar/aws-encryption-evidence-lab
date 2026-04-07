#!/usr/bin/env python3
"""
Cloud Encryption Evidence Lab - Encryption Validator

This script validates encryption-at-rest settings across AWS services:
- S3 buckets (default encryption configuration)
- EBS volumes (encryption status)
- KMS keys (rotation status)

Generates JSON and CSV reports mapped to SOC 2 CC6.1 and NIST SC-28 requirements.

Author: GRC Engineering Club
Date: September 2025
"""

import argparse
import csv
import json
import logging
import os
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Set
import boto3
from botocore.exceptions import ClientError, BotoCoreError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class Finding:
    """Represents a single encryption compliance finding."""
    resource_type: str
    resource_id: str
    resource_arn: str
    status: str  # PASS, FAIL, WARNING
    risk_level: str  # CRITICAL, HIGH, MEDIUM, LOW
    encryption_type: str
    region: str
    compliance_mappings: List[str] = field(default_factory=list)
    finding_details: str = ""
    remediation: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return asdict(self)


@dataclass
class ScanSummary:
    """Summary statistics for the encryption scan."""
    total_resources: int = 0
    compliant: int = 0
    non_compliant: int = 0
    warnings: int = 0
    regions_scanned: List[str] = field(default_factory=list)
    scan_date: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def compliance_percentage(self) -> int:
        """Calculate compliance percentage."""
        if self.total_resources == 0:
            return 0
        return int((self.compliant / self.total_resources) * 100)


@dataclass
class ScanReport:
    """Complete encryption scan report."""
    metadata: Dict[str, Any]
    summary: ScanSummary
    findings: List[Finding]

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary for JSON serialization."""
        return {
            "scan_metadata": self.metadata,
            "summary": asdict(self.summary),
            "findings": [f.to_dict() for f in self.findings]
        }


# ============================================================================
# Constants
# ============================================================================

COMPLIANCE_MAPPINGS = {
    "SOC_2_CC6_1": "SOC 2 CC6.1",
    "NIST_SC_28": "NIST SC-28"
}

RISK_LEVELS = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4
}

ENCRYPTION_TYPES = {
    "AES256": "SSE-S3 (AES256)",
    "aws:kms": "SSE-KMS",
    "NONE": "None",
    "UNKNOWN": "Unknown"
}


# ============================================================================
# Encryption Validator Class
# ============================================================================

class EncryptionValidator:
    """Main validator class for encryption-at-rest checks."""

    def __init__(
        self,
        region: str = "us-east-1",
        all_regions: bool = False,
        profile: Optional[str] = None
    ):
        """Initialize the encryption validator.

        Args:
            region: Primary AWS region
            all_regions: Whether to scan all AWS regions
            profile: AWS profile name (optional)
        """
        self.region = region
        self.all_regions = all_regions
        self.profile = profile

        # Initialize boto3 session
        if profile:
            self.session = boto3.Session(profile_name=profile)
        else:
            self.session = boto3.Session()

        # Get account ID
        self.account_id = self._get_account_id()

        # Get regions to scan
        self.regions = self._get_regions_to_scan()

        logger.info(f"Initialized validator for account: {self.account_id}")
        logger.info(f"Regions to scan: {', '.join(self.regions)}")

        # Storage for findings
        self.findings: List[Finding] = []

    def _get_account_id(self) -> str:
        """Get the current AWS account ID."""
        try:
            sts_client = self.session.client('sts')
            identity = sts_client.get_caller_identity()
            return identity.get('Account', '')
        except (ClientError, BotoCoreError) as e:
            logger.error(f"Failed to get account ID: {e}")
            return "unknown"

    def _get_regions_to_scan(self) -> List[str]:
        """Get list of regions to scan."""
        if self.all_regions:
            try:
                ec2_client = self.session.client('ec2', region_name='us-east-1')
                response = ec2_client.describe_regions()
                regions = [r['RegionName'] for r in response['Regions']]
                logger.info(f"Discovered {len(regions)} regions")
                return regions
            except (ClientError, BotoCoreError) as e:
                logger.error(f"Failed to describe regions: {e}")
                return [self.region]
        return [self.region]

    # ========================================================================
    # S3 Validation
    # ========================================================================

    def validate_s3_encryption(self) -> None:
        """Validate S3 bucket default encryption settings."""
        logger.info("Starting S3 encryption validation...")

        try:
            s3_client = self.session.client('s3')

            # List all buckets
            response = s3_client.list_buckets()
            buckets = response.get('Buckets', [])

            logger.info(f"Found {len(buckets)} S3 buckets to check")

            for bucket in buckets:
                bucket_name = bucket['Name']
                bucket_arn = f"arn:aws:s3:::{bucket_name}"

                try:
                    # Get bucket location to determine region
                    location = s3_client.get_bucket_location(Bucket=bucket_name)
                    bucket_region = location.get('LocationConstraint') or 'us-east-1'

                    # Skip if region not in our scan list (for all_regions mode)
                    if self.all_regions and bucket_region not in self.regions:
                        continue

                    # Check encryption configuration
                    try:
                        encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
                        rules = encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])

                        if rules:
                            rule = rules[0]
                            sse_config = rule.get('ApplyServerSideEncryptionByDefault', {})
                            algorithm = sse_config.get('SSEAlgorithm', 'UNKNOWN')
                            kms_key = sse_config.get('KMSMasterKeyID', '')

                            # Map to friendly name
                            if algorithm == 'AES256':
                                encryption_type = "AES256"
                                risk_level = "LOW"
                            elif algorithm == 'aws:kms':
                                encryption_type = f"SSE-KMS ({kms_key[:20]}...)" if kms_key else "SSE-KMS"
                                risk_level = "LOW"
                            else:
                                encryption_type = algorithm
                                risk_level = "MEDIUM"

                            finding = Finding(
                                resource_type="AWS::S3::Bucket",
                                resource_id=bucket_name,
                                resource_arn=bucket_arn,
                                status="PASS",
                                risk_level=risk_level,
                                encryption_type=encryption_type,
                                region=bucket_region,
                                compliance_mappings=list(COMPLIANCE_MAPPINGS.values()),
                                finding_details=f"S3 bucket has default encryption configured: {algorithm}",
                                raw_data={
                                    "bucket_name": bucket_name,
                                    "encryption_algorithm": algorithm,
                                    "kms_key_id": kms_key
                                }
                            )
                            logger.info(f"✓ S3 bucket {bucket_name} encrypted with {algorithm}")

                    except ClientError as e:
                        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                            # No encryption configured
                            finding = Finding(
                                resource_type="AWS::S3::Bucket",
                                resource_id=bucket_name,
                                resource_arn=bucket_arn,
                                status="FAIL",
                                risk_level="HIGH",
                                encryption_type="NONE",
                                region=bucket_region,
                                compliance_mappings=list(COMPLIANCE_MAPPINGS.values()),
                                finding_details="S3 bucket does not have default encryption configured",
                                remediation=f"Enable default encryption for S3 bucket {bucket_name} using SSE-S3 or SSE-KMS",
                                raw_data={"bucket_name": bucket_name, "encryption_configured": False}
                            )
                            logger.warning(f"✗ S3 bucket {bucket_name} has no default encryption")
                        else:
                            raise

                except ClientError as e:
                    logger.error(f"Error checking bucket {bucket_name}: {e}")

                    finding = Finding(
                        resource_type="AWS::S3::Bucket",
                        resource_id=bucket_name,
                        resource_arn=bucket_arn,
                        status="WARNING",
                        risk_level="MEDIUM",
                        encryption_type="UNKNOWN",
                        region=self.region,
                        compliance_mappings=list(COMPLIANCE_MAPPINGS.values()),
                        finding_details=f"Failed to check encryption: {str(e)}",
                        raw_data={"error": str(e)}
                    )

                self.findings.append(finding)

        except (ClientError, BotoCoreError) as e:
            logger.error(f"Failed to list S3 buckets: {e}")

    # ========================================================================
    # EBS Validation
    # ========================================================================

    def validate_ebs_encryption(self) -> None:
        """Validate EBS volume encryption settings."""
        logger.info("Starting EBS encryption validation...")

        for region in self.regions:
            try:
                ec2_client = self.session.client('ec2', region_name=region)

                # Describe all volumes
                paginator = ec2_client.get_paginator('describe_volumes')
                page_iterator = paginator.paginate()

                volume_count = 0
                for page in page_iterator:
                    volumes = page.get('Volumes', [])
                    volume_count += len(volumes)

                    for volume in volumes:
                        volume_id = volume['VolumeId']
                        volume_arn = f"arn:aws:ec2:{region}:{self.account_id}:volume/{volume_id}"
                        encrypted = volume.get('Encrypted', False)
                        kms_key_id = volume.get('KmsKeyId', '')
                        volume_type = volume.get('VolumeType', 'unknown')
                        size = volume.get('Size', 0)
                        state = volume.get('State', 'unknown')

                        # Determine encryption type
                        if encrypted:
                            if kms_key_id:
                                # Extract just the key ID for cleaner output
                                key_id = kms_key_id.split('/')[-1]
                                encryption_type = f"SSE-KMS ({key_id})"
                            else:
                                encryption_type = "EBS Default (AES-256)"

                            finding = Finding(
                                resource_type="AWS::EC2::Volume",
                                resource_id=volume_id,
                                resource_arn=volume_arn,
                                status="PASS",
                                risk_level="LOW",
                                encryption_type=encryption_type,
                                region=region,
                                compliance_mappings=list(COMPLIANCE_MAPPINGS.values()),
                                finding_details=f"EBS volume is encrypted. Type: {volume_type}, Size: {size}GB, State: {state}",
                                raw_data={
                                    "volume_id": volume_id,
                                    "volume_type": volume_type,
                                    "size": size,
                                    "state": state,
                                    "encrypted": True,
                                    "kms_key_id": kms_key_id
                                }
                            )
                            logger.info(f"✓ EBS volume {volume_id} is encrypted")

                        else:
                            finding = Finding(
                                resource_type="AWS::EC2::Volume",
                                resource_id=volume_id,
                                resource_arn=volume_arn,
                                status="FAIL",
                                risk_level="CRITICAL",
                                encryption_type="NONE",
                                region=region,
                                compliance_mappings=list(COMPLIANCE_MAPPINGS.values()),
                                finding_details=f"EBS volume is NOT encrypted. Type: {volume_type}, Size: {size}GB, State: {state}",
                                remediation=f"EBS volume {volume_id} is not encrypted. Create a snapshot, copy with encryption enabled, and replace the volume.",
                                raw_data={
                                    "volume_id": volume_id,
                                    "volume_type": volume_type,
                                    "size": size,
                                    "state": state,
                                    "encrypted": False
                                }
                            )
                            logger.warning(f"✗ EBS volume {volume_id} is NOT encrypted")

                        self.findings.append(finding)

                logger.info(f"Checked {volume_count} EBS volumes in {region}")

            except (ClientError, BotoCoreError) as e:
                logger.error(f"Failed to describe volumes in region {region}: {e}")

    # ========================================================================
    # KMS Validation
    # ========================================================================

    def validate_kms_encryption(self) -> None:
        """Validate KMS key settings and rotation status."""
        logger.info("Starting KMS encryption validation...")

        kms_regions = self.regions if self.all_regions else [self.region]

        for region in kms_regions:
            try:
                kms_client = self.session.client('kms', region_name=region)

                # List all keys
                paginator = kms_client.get_paginator('list_keys')
                page_iterator = paginator.paginate()

                key_count = 0
                customer_keys = 0

                for page in page_iterator:
                    keys = page.get('Keys', [])
                    key_count += len(keys)

                    for key in keys:
                        key_id = key['KeyId']

                        try:
                            # Get key metadata
                            metadata = kms_client.describe_key(KeyId=key_id)
                            key_metadata = metadata['KeyMetadata']

                            # Only check customer managed keys
                            if key_metadata.get('KeyManager') != 'CUSTOMER':
                                continue

                            customer_keys += 1

                            key_arn = key_metadata['Arn']
                            key_state = key_metadata.get('KeyState', 'Unknown')
                            key_spec = key_metadata.get('KeySpec', 'SYMMETRIC_DEFAULT')
                            key_usage = key_metadata.get('KeyUsage', 'ENCRYPT_DECRYPT')
                            creation_date = key_metadata.get('CreationDate')

                            # Check rotation status (only for symmetric keys)
                            rotation_enabled = False
                            rotation_finding = ""

                            if key_spec == 'SYMMETRIC_DEFAULT' and key_usage == 'ENCRYPT_DECRYPT':
                                try:
                                    rotation_status = kms_client.get_key_rotation_status(KeyId=key_id)
                                    rotation_enabled = rotation_status.get('KeyRotationEnabled', False)
                                except ClientError:
                                    pass  # Rotation check failed

                                if rotation_enabled:
                                    rotation_finding = "Key rotation is enabled"
                                else:
                                    rotation_finding = "Key rotation is NOT enabled"
                            else:
                                rotation_finding = "Rotation not applicable for asymmetric keys"

                            # Determine status
                            if rotation_enabled or key_spec != 'SYMMETRIC_DEFAULT':
                                status = "PASS"
                                risk_level = "LOW"
                                finding_details = f"Customer-managed KMS key. State: {key_state}, Spec: {key_spec}. {rotation_finding}"
                            else:
                                status = "FAIL"
                                risk_level = "MEDIUM"
                                finding_details = f"Customer-managed KMS key without automatic rotation. State: {key_state}, Spec: {key_spec}"

                            # Calculate key age
                            age_days = 0
                            if creation_date:
                                age_days = (datetime.now(timezone.utc) - creation_date).days
                                finding_details += f", Age: {age_days} days"

                            finding = Finding(
                                resource_type="AWS::KMS::Key",
                                resource_id=key_id,
                                resource_arn=key_arn,
                                status=status,
                                risk_level=risk_level,
                                encryption_type="SSE-KMS",
                                region=region,
                                compliance_mappings=list(COMPLIANCE_MAPPINGS.values()),
                                finding_details=finding_details,
                                remediation=f"Enable automatic key rotation for KMS key {key_id}" if not rotation_enabled else "",
                                raw_data={
                                    "key_id": key_id,
                                    "key_state": key_state,
                                    "key_spec": key_spec,
                                    "key_usage": key_usage,
                                    "rotation_enabled": rotation_enabled,
                                    "age_days": age_days
                                }
                            )

                            if status == "PASS":
                                logger.info(f"✓ KMS key {key_id} rotation: {'enabled' if rotation_enabled else 'N/A'}")
                            else:
                                logger.warning(f"✗ KMS key {key_id} rotation: disabled")

                            self.findings.append(finding)

                        except (ClientError, BotoCoreError) as e:
                            logger.error(f"Error describing key {key_id}: {e}")

                logger.info(f"Checked {customer_keys} customer-managed KMS keys in {region}")

            except (ClientError, BotoCoreError) as e:
                logger.error(f"Failed to list KMS keys in region {region}: {e}")

    # ========================================================================
    # Report Generation
    # ========================================================================

    def generate_report(self) -> ScanReport:
        """Generate the complete scan report."""
        # Calculate summary statistics
        summary = ScanSummary(
            total_resources=len(self.findings),
            compliant=sum(1 for f in self.findings if f.status == "PASS"),
            non_compliant=sum(1 for f in self.findings if f.status == "FAIL"),
            warnings=sum(1 for f in self.findings if f.status == "WARNING"),
            regions_scanned=self.regions
        )

        # Create metadata
        metadata = {
            "scan_date": datetime.now(timezone.utc).isoformat(),
            "aws_account_id": self.account_id,
            "regions_scanned": self.regions,
            "total_resources_checked": summary.total_resources,
            "tool_name": "Cloud Encryption Evidence Lab",
            "tool_version": "1.0.0",
            "compliance_frameworks": list(COMPLIANCE_MAPPINGS.values())
        }

        return ScanReport(
            metadata=metadata,
            summary=summary,
            findings=self.findings
        )

    def save_json_report(self, report: ScanReport, output_dir: str) -> str:
        """Save the report as JSON."""
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, 'encryption_report.json')

        with open(output_path, 'w') as f:
            json.dump(report.to_dict(), f, indent=2, default=str)

        logger.info(f"JSON report saved to: {output_path}")
        return output_path

    def save_csv_report(self, report: ScanReport, output_dir: str) -> str:
        """Save the report as CSV."""
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, 'encryption_summary.csv')

        fieldnames = [
            'Resource Type',
            'Resource ID',
            'Region',
            'Status',
            'Risk Level',
            'Encryption Type',
            'SOC 2 CC6.1',
            'NIST SC-28',
            'Finding Details',
            'Remediation'
        ]

        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for finding in report.findings:
                writer.writerow({
                    'Resource Type': finding.resource_type,
                    'Resource ID': finding.resource_id,
                    'Region': finding.region,
                    'Status': finding.status,
                    'Risk Level': finding.risk_level,
                    'Encryption Type': finding.encryption_type,
                    'SOC 2 CC6.1': 'YES' if finding.status == 'PASS' else 'NO',
                    'NIST SC-28': 'YES' if finding.status == 'PASS' else 'NO',
                    'Finding Details': finding.finding_details,
                    'Remediation': finding.remediation
                })

        logger.info(f"CSV report saved to: {output_path}")
        return output_path

    # ========================================================================
    # Main Execution
    # ========================================================================

    def run(self, output_dir: str = './evidence') -> ScanReport:
        """Run the complete validation scan."""
        logger.info("=" * 60)
        logger.info("Cloud Encryption Evidence Lab - Starting Scan")
        logger.info("=" * 60)

        # Run all validations
        self.validate_s3_encryption()
        self.validate_ebs_encryption()
        self.validate_kms_encryption()

        # Generate and save reports
        report = self.generate_report()

        json_path = self.save_json_report(report, output_dir)
        csv_path = self.save_csv_report(report, output_dir)

        # Print summary
        logger.info("=" * 60)
        logger.info("Scan Complete - Summary")
        logger.info("=" * 60)
        logger.info(f"Total Resources Checked: {report.summary.total_resources}")
        logger.info(f"Compliant: {report.summary.compliant} ({report.summary.compliance_percentage}%)")
        logger.info(f"Non-Compliant: {report.summary.non_compliant}")
        logger.info(f"Warnings: {report.summary.warnings}")
        logger.info(f"Reports saved to: {output_dir}")
        logger.info("=" * 60)

        # Print high-risk findings
        high_risk = [f for f in report.findings if f.risk_level in ['CRITICAL', 'HIGH']]
        if high_risk:
            logger.warning(f"\n{len(high_risk)} High/Critical Risk Findings:")
            for finding in high_risk[:10]:  # Show first 10
                logger.warning(f"  - [{finding.resource_type}] {finding.resource_id}: {finding.finding_details}")

        return report


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description='Validate encryption-at-rest across AWS S3, EBS, and KMS',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan default region (us-east-1)
  python encryption_validator.py

  # Scan specific region
  python encryption_validator.py --region us-west-2

  # Scan all regions
  python encryption_validator.py --all-regions

  # Use specific AWS profile
  python encryption_validator.py --profile prod-account

  # Custom output directory
  python encryption_validator.py --output-dir ./reports
        """
    )

    parser.add_argument(
        '--region',
        default='us-east-1',
        help='AWS region to scan (default: us-east-1)'
    )

    parser.add_argument(
        '--all-regions',
        action='store_true',
        help='Scan all AWS regions'
    )

    parser.add_argument(
        '--output-dir',
        default='./evidence',
        help='Output directory for reports (default: ./evidence)'
    )

    parser.add_argument(
        '--profile',
        help='AWS profile name to use'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    args = parser.parse_args()

    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        # Create validator and run scan
        validator = EncryptionValidator(
            region=args.region,
            all_regions=args.all_regions,
            profile=args.profile
        )

        report = validator.run(output_dir=args.output_dir)

        # Exit with appropriate code
        if report.summary.non_compliant > 0:
            sys.exit(1)  # Non-zero exit code for non-compliant findings
        else:
            sys.exit(0)

    except KeyboardInterrupt:
        logger.info("\nScan interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
