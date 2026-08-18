from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.policy.policy_client import policy_client


class policy_ensure_asc_enforcement_enabled(Check):
    """Ensure Azure Security Center Default Policy enforcement is enabled.

    This check verifies that the Azure Security Center Default Policy assignment
    (SecurityCenterBuiltIn or ASC Default) has its enforcement mode set to Default.
    """

    def execute(self) -> list[Check_Report_Azure]:
        """Execute policy_ensure_asc_enforcement_enabled check.

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
            report.resource_name = "Azure Security Center Default Policy"
            report.resource_id = subscription_id

            asc_policy = None
            for name, assignment in assignments.items():
                def_id = (assignment.policy_definition_id or "").lower()
                asg_name = (assignment.name or "").lower()
                if (
                    "1f3afdf9-d0c9-4c3d-847f-89da613e70a8" in def_id
                    or "securitycenterbuiltin" in asg_name
                    or "asc default" in asg_name
                ):
                    asc_policy = assignment
                    break

            if asc_policy:
                report.resource_id = asc_policy.id
                report.resource_name = asc_policy.name
                if asc_policy.enforcement_mode == "Default":
                    report.status = "PASS"
                    report.status_extended = f"ASC Default policy '{asc_policy.name}' has enforcement enabled."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"ASC Default policy '{asc_policy.name}' has enforcement disabled (DoNotEnforce)."
            else:
                report.status = "FAIL"
                report.status_extended = "ASC Default policy assignment not found for the subscription."

            findings.append(report)

        return findings
