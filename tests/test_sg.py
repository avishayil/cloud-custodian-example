"""Test Cloud Custodian SG polices."""

from unittest.mock import patch

import boto3
from helpers import listdiff
from moto import mock_ec2
from test_runner import CustodianPolicyTest


class EC2PolicyTest(CustodianPolicyTest):
    """Cloud Custodian EC2 policies test runner base class."""

    @patch("c7n.policy.Policy._write_file")
    @patch("c7n.utils.dumps")
    @mock_ec2
    def test_sg_with_open_ssh_ingress(self, dumps, wf):
        """Test security groups SSH ingress rules open."""
        client = boto3.client("ec2")
        ec2 = boto3.resource("ec2")

        # Delete existing default security group
        client.delete_security_group(GroupName="default")

        # Create security group with open ingress rule
        sg = ec2.create_security_group(
            GroupName="SSH-Open", Description="Allow SSH traffic", VpcId="vpc-41744d3f"
        )
        client.authorize_security_group_ingress(
            GroupId=sg.id,
            IpPermissions=[
                {
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "foo"}],
                }
            ],
        )

        sg_before_policy_run = client.describe_security_groups(GroupIds=[sg.id])[
            "SecurityGroups"
        ][0]
        resources, metrics = self.run_policy(
            policy_file_path="policies/sg.yml",
            policy_names=["sg-that-allows-ssh-open-ingress"],
            dumps=dumps,
        )
        sg_after_policy_run = client.describe_security_groups(GroupIds=[sg.id])[
            "SecurityGroups"
        ][0]
        expected_removed_rules = [
            {
                "FromPort": 22,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "foo"}],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "ToPort": 22,
                "UserIdGroupPairs": [],
            }
        ]

        self.assertEqual(
            len(resources), 1
        )  # Verify that there is only 1 security group, that we've created
        self.assertEqual(
            sg_after_policy_run["IpPermissions"], []
        )  # Verify that the security group ingress rules are empty after policy run
        self.assertEqual(
            len(sg_before_policy_run["IpPermissions"])
            - len(sg_after_policy_run["IpPermissions"]),
            1,
        )  # Verify that exactly 1 ingress rule was deleted from the security group after policy run
        self.assertEqual(
            listdiff(
                sg_before_policy_run["IpPermissions"],
                sg_after_policy_run["IpPermissions"],
            ),
            expected_removed_rules,
        )  # Verify that the specific rule was removed as expected

    @patch("c7n.policy.Policy._write_file")
    @patch("c7n.utils.dumps")
    @mock_ec2
    def test_sg_with_open_ssh_ingress_with_tag(self, dumps, wf):
        """Test security groups SSH ingress rules open, excluded by tag."""
        client = boto3.client("ec2")
        ec2 = boto3.resource("ec2")

        # Delete existing default security group
        client.delete_security_group(GroupName="default")

        # Create security group with open ingress rule
        sg = ec2.create_security_group(
            GroupName="SSH-Open", Description="Allow SSH traffic", VpcId="vpc-41744d3f"
        )
        sg.create_tags(Tags=[{"Key": "AllowSSHFromEverywhere", "Value": "Yes"}])
        client.authorize_security_group_ingress(
            GroupId=sg.id,
            IpPermissions=[
                {
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "foo"}],
                }
            ],
        )

        sg_before_policy_run = client.describe_security_groups(GroupIds=[sg.id])[
            "SecurityGroups"
        ][0]
        resources, metrics = self.run_policy(
            policy_file_path="policies/sg.yml",
            policy_names=["sg-that-allows-ssh-open-ingress"],
            dumps=dumps,
        )
        sg_after_policy_run = client.describe_security_groups(GroupIds=[sg.id])[
            "SecurityGroups"
        ][0]

        self.assertEqual(
            len(resources), 0
        )  # Verify that the policy haven't caught our security group
        self.assertEqual(
            sg_after_policy_run["IpPermissions"], sg_before_policy_run["IpPermissions"]
        )  # Verify that the security group ingress rules are empty after policy run

    @patch("c7n.policy.Policy._write_file")
    @patch("c7n.utils.dumps")
    @mock_ec2
    def test_sg_with_open_rdp_ingress(self, dumps, wf):
        """Test security groups RDP ingress rules open."""
        client = boto3.client("ec2")
        ec2 = boto3.resource("ec2")

        # Delete existing default security group
        client.delete_security_group(GroupName="default")

        # Create security group with open ingress rule
        sg = ec2.create_security_group(
            GroupName="RDP-Open", Description="Allow RDP traffic", VpcId="vpc-41744d3f"
        )
        client.authorize_security_group_ingress(
            GroupId=sg.id,
            IpPermissions=[
                {
                    "FromPort": 3389,
                    "ToPort": 3389,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "foo"}],
                }
            ],
        )

        sg_before_policy_run = client.describe_security_groups(GroupIds=[sg.id])[
            "SecurityGroups"
        ][0]
        resources, metrics = self.run_policy(
            policy_file_path="policies/sg.yml",
            policy_names=["sg-that-allows-rdp-open-ingress"],
            dumps=dumps,
        )
        sg_after_policy_run = client.describe_security_groups(GroupIds=[sg.id])[
            "SecurityGroups"
        ][0]
        expected_removed_rules = [
            {
                "FromPort": 3389,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "foo"}],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "ToPort": 3389,
                "UserIdGroupPairs": [],
            }
        ]

        self.assertEqual(
            len(resources), 1
        )  # Verify that 1 security group violated the policy
        self.assertEqual(
            sg_after_policy_run["IpPermissions"], []
        )  # Verify that the security group ingress rules are empty after policy run
        self.assertEqual(
            len(sg_before_policy_run["IpPermissions"])
            - len(sg_after_policy_run["IpPermissions"]),
            1,
        )  # Verify that exactly 1 ingress rule was deleted from the security group after policy run
        self.assertEqual(
            listdiff(
                sg_before_policy_run["IpPermissions"],
                sg_after_policy_run["IpPermissions"],
            ),
            expected_removed_rules,
        )  # Verify that the specific rule was removed as expected

    @patch("c7n.policy.Policy._write_file")
    @patch("c7n.utils.dumps")
    @mock_ec2
    def test_sg_with_open_rdp_ingress_with_tag(self, dumps, wf):
        """Test security groups RDP ingress rules open, excluded by tag."""
        client = boto3.client("ec2")
        ec2 = boto3.resource("ec2")

        # Delete existing default security group
        client.delete_security_group(GroupName="default")

        # Create security group with open ingress rule
        sg = ec2.create_security_group(
            GroupName="RDP-Open", Description="Allow RDP traffic", VpcId="vpc-41744d3f"
        )
        sg.create_tags(Tags=[{"Key": "AllowRDPFromEverywhere", "Value": "Yes"}])
        client.authorize_security_group_ingress(
            GroupId=sg.id,
            IpPermissions=[
                {
                    "FromPort": 3389,
                    "ToPort": 3389,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "foo"}],
                }
            ],
        )

        sg_before_policy_run = client.describe_security_groups(GroupIds=[sg.id])[
            "SecurityGroups"
        ][0]
        resources, metrics = self.run_policy(
            policy_file_path="policies/sg.yml",
            policy_names=["sg-that-allows-rdp-open-ingress"],
            dumps=dumps,
        )
        sg_after_policy_run = client.describe_security_groups(GroupIds=[sg.id])[
            "SecurityGroups"
        ][0]

        self.assertEqual(
            len(resources), 0
        )  # Verify that no resources violated the policy
        self.assertEqual(
            sg_after_policy_run["IpPermissions"], sg_before_policy_run["IpPermissions"]
        )  # Verify that the security group ingress rules are empty after policy run

    @patch("c7n.policy.Policy._write_file")
    @patch("c7n.utils.dumps")
    @mock_ec2
    def test_sg_with_open_generic_ingress(self, dumps, wf):
        """Test security groups generic ingress rules open."""
        client = boto3.client("ec2")
        ec2 = boto3.resource("ec2")

        # Delete existing default security group
        client.delete_security_group(GroupName="default")

        # Create security group with open ingress rule
        sg = ec2.create_security_group(
            GroupName="Generic-Open",
            Description="Allow Generic traffic",
            VpcId="vpc-41744d3f",
        )
        client.authorize_security_group_ingress(
            GroupId=sg.id,
            IpPermissions=[
                {
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "foo"}],
                },
                {
                    "FromPort": 80,
                    "ToPort": 80,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "foo"}],
                },
            ],
        )

        sg_before_policy_run = client.describe_security_groups(GroupIds=[sg.id])[
            "SecurityGroups"
        ][0]
        resources, metrics = self.run_policy(
            policy_file_path="policies/sg.yml",
            policy_names=["sg-that-allows-everywhere-open-ingress"],
            dumps=dumps,
        )
        sg_after_policy_run = client.describe_security_groups(GroupIds=[sg.id])[
            "SecurityGroups"
        ][0]
        expected_removed_rules = [
            {
                "FromPort": 443,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "foo"}],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "ToPort": 443,
                "UserIdGroupPairs": [],
            },
            {
                "FromPort": 80,
                "IpProtocol": "tcp",
                "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "foo"}],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "ToPort": 80,
                "UserIdGroupPairs": [],
            },
        ]

        self.assertEqual(
            len(resources), 1
        )  # Verify that 1 security group violated the policy
        self.assertEqual(
            len(sg_before_policy_run["IpPermissions"])
            - len(sg_after_policy_run["IpPermissions"]),
            2,
        )  # Verify that exactly 2 ingress rules were deleted from the security group after policy run
        self.assertEqual(
            listdiff(
                sg_before_policy_run["IpPermissions"],
                sg_after_policy_run["IpPermissions"],
            ),
            expected_removed_rules,
        )  # Verify that the specific rule was removed as expected

    @patch("c7n.policy.Policy._write_file")
    @patch("c7n.utils.dumps")
    @mock_ec2
    def test_sg_with_open_generic_ingress_with_tag(self, dumps, wf):
        """Test security groups generic ingress rules open, excluded by tag."""
        client = boto3.client("ec2")
        ec2 = boto3.resource("ec2")

        # Delete existing default security group
        client.delete_security_group(GroupName="default")

        # Create security group with open ingress rule
        sg = ec2.create_security_group(
            GroupName="Generic-Open",
            Description="Allow Generic traffic",
            VpcId="vpc-41744d3f",
        )
        sg.create_tags(Tags=[{"Key": "AllowFromEverywhere", "Value": "Yes"}])
        client.authorize_security_group_ingress(
            GroupId=sg.id,
            IpPermissions=[
                {
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "foo"}],
                },
                {
                    "FromPort": 80,
                    "ToPort": 80,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "foo"}],
                },
            ],
        )

        sg_before_policy_run = client.describe_security_groups(GroupIds=[sg.id])[
            "SecurityGroups"
        ][0]
        resources, metrics = self.run_policy(
            policy_file_path="policies/sg.yml",
            policy_names=["sg-that-allows-everywhere-open-ingress"],
            dumps=dumps,
        )
        sg_after_policy_run = client.describe_security_groups(GroupIds=[sg.id])[
            "SecurityGroups"
        ][0]
        expected_removed_rules = []

        self.assertEqual(
            len(resources), 0
        )  # Verify that no resources violated the policy
        self.assertEqual(
            listdiff(
                sg_before_policy_run["IpPermissions"],
                sg_after_policy_run["IpPermissions"],
            ),
            expected_removed_rules,
        )  # Verify that the specific rule was removed as expected

    @patch("c7n.policy.Policy._write_file")
    @patch("c7n.utils.dumps")
    @mock_ec2
    def test_default_sg_with_rules(self, dumps, wf):
        """Test default security groups."""
        client = boto3.client("ec2")
        ec2 = boto3.resource("ec2")

        # Delete existing default security group
        client.delete_security_group(GroupName="default")

        # Create security group with open ingress rule
        sg = ec2.create_security_group(
            GroupName="default",
            Description="Default VPC Security Group",
            VpcId="vpc-41744d3f",
        )
        client.authorize_security_group_ingress(
            GroupId=sg.id,
            IpPermissions=[
                {
                    "FromPort": 1024,
                    "ToPort": 65535,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "foo"}],
                }
            ],
        )
        client.authorize_security_group_egress(
            GroupId=sg.id,
            IpPermissions=[
                {
                    "FromPort": 1024,
                    "ToPort": 65535,
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "foo"}],
                }
            ],
        )

        resources, metrics = self.run_policy(
            policy_file_path="policies/sg.yml",
            policy_names=["sg-with-ingress-or-egress-with-default"],
            dumps=dumps,
        )
        sg_after_policy_run = client.describe_security_groups(GroupIds=[sg.id])[
            "SecurityGroups"
        ][0]

        self.assertEqual(
            len(resources), 1
        )  # Verify that 1 security group violated the policy
        self.assertEqual(
            resources[0]["c7n:MatchedFilters"], ["GroupName"]
        )  # Verify that the policy matched the correct filter
        self.assertEqual(
            sg_after_policy_run["IpPermissions"], []
        )  # Verify that the security group ingress rules are empty after policy run
        self.assertEqual(
            sg_after_policy_run["IpPermissionsEgress"], []
        )  # Verify that the security group egress rules are empty after policy run
