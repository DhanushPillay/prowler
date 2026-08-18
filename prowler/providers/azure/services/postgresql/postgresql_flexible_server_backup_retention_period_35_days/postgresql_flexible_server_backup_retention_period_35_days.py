from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.postgresql.postgresql_client import postgresql_client


class postgresql_flexible_server_backup_retention_period_35_days(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription_id, servers in postgresql_client.flexible_servers.items():
            for server in servers:
                report = Check_Report_Azure(
                    metadata=self.metadata(),
                    resource_id=server.id,
                    resource_name=server.name,
                    subscription_id=subscription_id,
                    location=server.location,
                )
                
                if server.backup_retention_days is not None and server.backup_retention_days >= 35:
                    report.status = "PASS"
                    report.status_extended = f"Flexible PostgreSQL server {server.name} has a backup retention period of {server.backup_retention_days} days."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Flexible PostgreSQL server {server.name} does not have a backup retention period of at least 35 days."

                findings.append(report)

        return findings
