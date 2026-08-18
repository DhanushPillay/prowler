from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.policy.policy_client import policy_client


class policy_ensure_allowed_extensions_are_installed(Check):
    """Check if Allowed VM Extensions policy is enabled.

    This check verifies if there is a policy assignment for the Only approved VM extensions should be installed built-in policy (c0e996f8-39cf-4af9-9f45-83fbde810432).
    """

    def execute(self) -> list[Check_Report_Azure]:
        """Execute policy_ensure_allowed_extensions_are_installed check.

        Returns:
            list[Check_Report_Azure]: List of findings for subscriptions.
        """
        findings = []
        for subscription_id, assignments in policy_client.policy_assigments.items():
            report = Check_Report_Azure(
                metadata=self.metadata(),
                resource=None,
            )
            report.status = "FAIL"
            report.subscription = subscription_id
            report.location = "global"
            report.resource_name = "Policy Assignment c0e996f8-39cf-4af9-9f45-83fbde810432"
            report.resource_id = subscription_id

            found_policy = None
            for name, assignment in assignments.items():
                if assignment.policy_definition_id and "c0e996f8-39cf-4af9-9f45-83fbde810432" in assignment.policy_definition_id.lower():
                    found_policy = assignment
                    break

            if found_policy and found_policy.enforcement_mode == "Default":
                report.status = "PASS"
                report.resource_id = found_policy.id
                report.resource_name = found_policy.name
                report.status_extended = f"Policy assignment '{found_policy.name}' for definition 'c0e996f8-39cf-4af9-9f45-83fbde810432' exists with enforcement enabled."
            elif found_policy:
                report.status = "FAIL"
                report.resource_id = found_policy.id
                report.resource_name = found_policy.name
                report.status_extended = f"Policy assignment '{found_policy.name}' for definition 'c0e996f8-39cf-4af9-9f45-83fbde810432' exists but enforcement is disabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"Policy assignment for definition 'c0e996f8-39cf-4af9-9f45-83fbde810432' not found for the subscription."

            findings.append(report)

        return findings
