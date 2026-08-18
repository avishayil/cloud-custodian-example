"""Test runner for cloud custodian policies."""

import pathlib
import tempfile
import unittest

import yaml


class CustodianPolicyTest(unittest.TestCase):
    """Cloud Custodian test runner base class."""

    def extract_test_policy(self, policy_file_path: str, policy_names: list):
        """Alter policies YAML, strip mode and notify sections."""
        with open(policy_file_path) as f:
            policy_doc = yaml.safe_load(f)

        new_policy_doc = []
        test_policy_file_paths = []
        for policy in policy_doc["policies"]:
            if policy["name"] in policy_names:
                if "mode" in policy:
                    policy.pop("mode")
                for action in list(policy.get("actions", [])):
                    if isinstance(action, dict) and action.get("type") == "notify":
                        policy["actions"].remove(action)
                new_policy_doc.append(policy)

                pathlib.Path(".test").mkdir(parents=True, exist_ok=True)
                test_policy_file_path = f'.test/test-{pathlib.Path(policy_file_path).stem}-{policy["name"]}.yaml'
                test_policy_file_paths.append(test_policy_file_path)

                with open(test_policy_file_path, "w") as f:
                    yaml.dump({"policies": new_policy_doc}, f)

        return test_policy_file_paths

    def run_policy(self, policy_file_path: str, policy_names: list):
        """Run Cloud Custodian policies against the moto test backend.

        Loads the requested policies, executes each one in pull mode, and
        returns the resources that matched the policy filters together with
        the policy names that ran.
        """
        from c7n.config import Config
        from c7n.policy import load as load_policies

        test_policy_file_paths = self.extract_test_policy(
            policy_file_path=policy_file_path, policy_names=policy_names
        )

        config = Config.empty(
            output_dir=tempfile.mkdtemp(prefix="c7n-test-output-"),
            dryrun=False,
            debug=False,
        )

        resources = []
        metrics = []
        for test_policy_file_path in test_policy_file_paths:
            collection = load_policies(config, test_policy_file_path, validate=True)
            for policy in collection:
                matched = policy() or []
                resources.extend(matched)
                metrics.append(policy.name)

        return (resources, metrics)
