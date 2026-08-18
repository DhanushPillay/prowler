from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.sqlserver.sqlserver_client import sqlserver_client


class sqlserver_public_network_access_disabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription_id, servers in sqlserver_client.sql_servers.items():
            for server in servers:
                report = Check_Report_Azure(
                    metadata=self.metadata(),
                    resource_id=server.id,
                    resource_name=server.name,
                    subscription_id=subscription_id,
                    location=server.location,
                )
                
                # server.public_network_access is usually "Enabled" or "Disabled"
                if server.public_network_access and str(server.public_network_access).lower() == "disabled":
                    report.status = "PASS"
                    report.status_extended = f"SQL Server {server.name} has public network access disabled."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"SQL Server {server.name} has public network access enabled."

                findings.append(report)

        return findings
