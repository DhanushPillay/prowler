from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.network.network_client import network_client


class network_sg_open_all_ports_to_any_source(Check):
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
                
                open_all_ports_any_source = False
                for rule in sg.security_rules:
                    if rule.access == "Allow" and rule.direction == "Inbound":
                        if rule.source_address_prefix in ["*", "0.0.0.0", "<nw>/0", "/0", "internet", "any"]:
                            if rule.destination_port_range in ["*", "0-65535", "Any"]:
                                open_all_ports_any_source = True
                                break
                
                if open_all_ports_any_source:
                    report.status = "FAIL"
                    report.status_extended = f"Network Security Group {sg.name} has a rule that opens all ports to any source."
                else:
                    report.status = "PASS"
                    report.status_extended = f"Network Security Group {sg.name} does not open all ports to any source."

                findings.append(report)

        return findings
