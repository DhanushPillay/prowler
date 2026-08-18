from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.network.network_client import network_client


class network_security_group_not_empty(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription_id, security_groups in network_client.security_groups.items():
            for sg in security_groups:
                report = Check_Report_Azure(
                    metadata=self.metadata(),
                    resource_id=sg.id,
                    resource_name=sg.name,
                    subscription_id=subscription_id,
                    location=sg.location,
                )

                if len(sg.security_rules) > 0:
                    report.status = "PASS"
                    report.status_extended = f"Network Security Group {sg.name} contains custom security rules."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Network Security Group {sg.name} is empty and contains no custom security rules."

                findings.append(report)

        return findings
