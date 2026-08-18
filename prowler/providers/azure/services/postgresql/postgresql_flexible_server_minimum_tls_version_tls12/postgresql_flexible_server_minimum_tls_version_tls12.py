from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.postgresql.postgresql_client import postgresql_client


class postgresql_flexible_server_minimum_tls_version_tls12(Check):
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
                
                if server.tls_min_version is not None and "1.2" in server.tls_min_version:
                    report.status = "PASS"
                    report.status_extended = f"Flexible PostgreSQL server {server.name} enforces minimum TLS version of {server.tls_min_version}."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Flexible PostgreSQL server {server.name} does not enforce minimum TLS version of 1.2."

                findings.append(report)

        return findings
