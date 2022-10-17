"""Test Cloud Custodian S3 polices."""

from unittest.mock import patch

import boto3
from moto import mock_s3
from test_runner import CustodianPolicyTest


class S3PolicyTest(CustodianPolicyTest):
    """Cloud Custodian S3 policies test runner base class."""

    @patch("c7n.policy.Policy._write_file")
    @patch("c7n.utils.dumps")
    @mock_s3
    def test_s3_with_public_block_disabled(self, dumps, wf):
        """Test S3 buckets with public block access disabled."""
        client = boto3.client("s3")

        # Make sure there are no buckets in the moto backend
        list_buckets = client.list_buckets()
        self.assertEqual(len(list_buckets["Buckets"]), 0)

        # Create S3 bucket with public block disabled
        client.create_bucket(Bucket="test-bucket-public")
        client.put_public_access_block(
            Bucket="test-bucket-public",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )

        resources, metrics = self.run_policy(
            policy_file_path="policies/s3.yml",
            policy_names=["s3-public-block-enable-all"],
            dumps=dumps,
        )
        s3_public_access_block_after_policy_run = client.get_public_access_block(
            Bucket="test-bucket-public"
        )
        expected_public_access_block_configuration = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
        self.assertEqual(len(resources), 1)  # Verify that 1 bucket violated the policy
        self.assertEqual(
            s3_public_access_block_after_policy_run["PublicAccessBlockConfiguration"],
            expected_public_access_block_configuration,
        )  # Verify that the public access block settings are equal to the expected ones

    @patch("c7n.policy.Policy._write_file")
    @patch("c7n.utils.dumps")
    @mock_s3
    def test_s3_with_public_block_disabled_with_tag(self, dumps, wf):
        """Test S3 buckets with public block access disabled, excluded with tag."""
        client = boto3.client("s3")

        # Make sure there are no buckets in the moto backend
        list_buckets = client.list_buckets()
        self.assertEqual(len(list_buckets["Buckets"]), 0)

        # Create S3 bucket with public block disabled
        client.create_bucket(Bucket="test-bucket-public")
        client.put_public_access_block(
            Bucket="test-bucket-public",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        client.put_bucket_tagging(
            Bucket="test-bucket-public",
            Tagging={"TagSet": [{"Key": "AllowPublic", "Value": "Yes"}]},
        )

        resources, metrics = self.run_policy(
            policy_file_path="policies/s3.yml",
            policy_names=["s3-public-block-enable-all"],
            dumps=dumps,
        )
        self.assertEqual(
            len(resources), 0
        )  # Verify that no resources violated the policy

    @patch("c7n.policy.Policy._write_file")
    @patch("c7n.utils.dumps")
    @mock_s3
    def test_s3_with_public_block_enabled(self, dumps, wf):
        """Test S3 buckets with public block access enabled."""
        client = boto3.client("s3")

        # Make sure there are no buckets in the moto backend
        list_buckets = client.list_buckets()
        self.assertEqual(len(list_buckets["Buckets"]), 0)

        # Create S3 bucket with public block disabled
        client.create_bucket(Bucket="test-bucket-public")
        client.put_public_access_block(
            Bucket="test-bucket-public",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )

        resources, metrics = self.run_policy(
            policy_file_path="policies/s3.yml",
            policy_names=["s3-public-block-enable-all"],
            dumps=dumps,
        )
        self.assertEqual(
            len(resources), 0
        )  # Verify that no resources violated the policy
