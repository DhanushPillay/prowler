from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.sqlserver.sqlserver_client import sqlserver_client


class sqlserver_advanced_data_security_enabled(Check):
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
                
                if server.security_alert_policies and str(server.security_alert_policies.state).lower() == "enabled":
                    report.status = "PASS"
                    report.status_extended = f"SQL Server {server.name} has advanced data security (security alert policies) enabled."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"SQL Server {server.name} does not have advanced data security enabled."

                findings.append(report)

        return findings
