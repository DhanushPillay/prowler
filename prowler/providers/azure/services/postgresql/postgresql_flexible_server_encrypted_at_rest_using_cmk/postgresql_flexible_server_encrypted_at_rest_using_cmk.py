from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.postgresql.postgresql_client import postgresql_client


class postgresql_flexible_server_encrypted_at_rest_using_cmk(Check):
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
                
                # We need to rely on properties that indicate encryption with CMK
                # However, this property isn't explicitly modeled in the provided postgresql_service.py
                # This might require checking a specific data_encryption parameter if available.
                # Assuming `data_encryption` might be fetched, but currently not in the `Server` object in Prowler.
                # So we must fail and state we need manual verification if CMK status is not available,
                # or use a generic "FAIL" since it cannot be proven programmatically yet.
                report.status = "FAIL"
                report.status_extended = f"Flexible PostgreSQL server {server.name} cannot be verified for CMK encryption at rest natively via current parser."

                findings.append(report)

        return findings
