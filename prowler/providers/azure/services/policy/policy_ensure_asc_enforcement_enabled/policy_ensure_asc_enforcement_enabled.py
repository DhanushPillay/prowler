from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.policy.policy_client import policy_client


class policy_ensure_asc_enforcement_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription_id, assignments in policy_client.policy_assigments.items():
            report = Check_Report_Azure(
                metadata=self.metadata(),
                resource_id=subscription_id,
                resource_name="Azure Security Center Default Policy",
                subscription_id=subscription_id,
                location="global",
            )
            
            asc_policy = None
            for name, assignment in assignments.items():
                if "SecurityCenterBuiltIn" in assignment.name or "ASC Default" in assignment.name:
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
