from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.postgresql.postgresql_client import postgresql_client


class postgresql_flexible_server_audit_logs_enabled(Check):
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
                
                if server.audit_logging_enabled == "ENABLED":
                    report.status = "PASS"
                    report.status_extended = f"Flexible PostgreSQL server {server.name} has audit logging enabled."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Flexible PostgreSQL server {server.name} does not have audit logging enabled."

                findings.append(report)

        return findings
