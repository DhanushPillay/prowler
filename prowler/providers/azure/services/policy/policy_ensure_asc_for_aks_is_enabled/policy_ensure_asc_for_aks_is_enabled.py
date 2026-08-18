from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.policy.policy_client import policy_client


class policy_ensure_asc_for_aks_is_enabled(Check):
    """Check if Azure Security Center is enabled for AKS via Policy.

    This check verifies if the Azure Security Center Default Policy (or SecurityCenterBuiltIn) has the pricingTierKubernetes parameter set to Standard, ensuring that Defender for AKS is enabled.
    """

    def execute(self) -> list[Check_Report_Azure]:
        """Execute policy_ensure_asc_for_aks_is_enabled check.

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
                param_val = None
                if asc_policy.parameters and "pricingTierKubernetes" in asc_policy.parameters:
                    raw_val = asc_policy.parameters["pricingTierKubernetes"]
                    if hasattr(raw_val, "value"):
                        param_val = raw_val.value
                    elif isinstance(raw_val, dict):
                        param_val = raw_val.get("value")
                    else:
                        param_val = raw_val

                if param_val == "Standard" and asc_policy.enforcement_mode == "Default":
                    report.status = "PASS"
                    report.status_extended = (
                        f"ASC Default policy '{asc_policy.name}' has 'pricingTierKubernetes' set to Standard with enforcement enabled."
                    )
                elif param_val == "Standard":
                    report.status = "FAIL"
                    report.status_extended = (
                        f"ASC Default policy '{asc_policy.name}' has 'pricingTierKubernetes' set to Standard but enforcement is disabled."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"ASC Default policy '{asc_policy.name}' does not have 'pricingTierKubernetes' set to Standard."
                    )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    "ASC Default policy assignment not found for the subscription."
                )

            findings.append(report)

        return findings
