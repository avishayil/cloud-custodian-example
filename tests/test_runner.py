"""Test runner for cloud custodian policies."""

import pathlib
import unittest
from unittest.mock import PropertyMock, patch

import yaml


class CustodianPolicyTest(unittest.TestCase):
    """Cloud Custodian test runner base class."""

    @staticmethod
    def get_all_resources(call_args):
        """Get outputs from Cloud Custodian run."""
        resources = []
        metrics = []
        for i, resource in enumerate(call_args):
            if i % 2 == 0:
                resources.extend(resource[0][0])
            else:
                metrics.extend([resource[0][0]])
        return (resources, metrics)

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
                for action in policy["actions"]:
                    if action["type"] == "notify":
                        policy["actions"].remove(action)
                new_policy_doc.append(policy)

                pathlib.Path(".test").mkdir(parents=True, exist_ok=True)
                test_policy_file_path = f'.test/test-{pathlib.Path(policy_file_path).stem}-{policy["name"]}.yaml'
                test_policy_file_paths.append(test_policy_file_path)

                with open(test_policy_file_path, "w") as f:
                    yaml.dump({"policies": new_policy_doc}, f)

        return test_policy_file_paths

    def run_policy(self, policy_file_path: str, policy_names: list, dumps):
        """Run Cloud Custodian policy on moto test backend."""
        from c7n.commands import run
        from c7n.config import Config

        test_policy_file_paths = self.extract_test_policy(
            policy_file_path=policy_file_path, policy_names=policy_names
        )

        args = {"output_dir": "output", "configs": test_policy_file_paths, "vars": None}
        config = Config.empty(**args)

        with patch("c7n.policy.Policy.execution_mode", new_callable=PropertyMock) as em:
            em.return_value = "pull"
            run(config)

        return self.get_all_resources(dumps.call_args_list)
