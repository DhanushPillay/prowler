from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.mysql.mysql_client import mysql_client


class mysql_flexible_server_retain_backup_35_days(Check):
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
                
                if server.backup_retention_days is not None and server.backup_retention_days >= 35:
                    report.status = "PASS"
                    report.status_extended = f"Flexible MySQL server {server.name} has a backup retention period of {server.backup_retention_days} days."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Flexible MySQL server {server.name} does not have a backup retention period of at least 35 days."

                findings.append(report)

        return findings
