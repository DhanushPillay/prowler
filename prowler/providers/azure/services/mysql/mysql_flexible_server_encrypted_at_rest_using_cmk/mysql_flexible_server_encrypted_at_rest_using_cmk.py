from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.mysql.mysql_client import mysql_client


class mysql_flexible_server_encrypted_at_rest_using_cmk(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription_id, servers in mysql_client.flexible_servers.items():
            for server_id, server in servers.items():
                report = Check_Report_Azure(
                    metadata=self.metadata(),
                    resource_id=server.resource_id,
                    resource_name=server.name,
                    subscription_id=subscription_id,
                    location=server.location,
                )
                
                if server.encryption_type and server.encryption_type == "CustomerManagedKey":
                    report.status = "PASS"
                    report.status_extended = f"Flexible MySQL server {server.name} is encrypted at rest using a customer-managed key."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Flexible MySQL server {server.name} is not encrypted at rest using a customer-managed key."

                findings.append(report)

        return findings
