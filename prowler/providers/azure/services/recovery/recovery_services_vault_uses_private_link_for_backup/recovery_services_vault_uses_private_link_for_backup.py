from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.recovery.recovery_client import recovery_client


class recovery_services_vault_uses_private_link_for_backup(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription_id, vaults in recovery_client.vaults.items():
            for vault_id, vault in vaults.items():
                report = Check_Report_Azure(
                    metadata=self.metadata(),
                    resource_id=vault.id,
                    resource_name=vault.name,
                    subscription_id=subscription_id,
                    location=vault.location,
                )
                
                has_approved_pec = False
                for pec in vault.private_endpoint_connections:
                    if pec.status and str(pec.status).lower() == "approved":
                        has_approved_pec = True
                        break
                
                if has_approved_pec:
                    report.status = "PASS"
                    report.status_extended = f"Recovery Services Vault {vault.name} uses an approved private link for backup."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Recovery Services Vault {vault.name} does not use an approved private link for backup."

                findings.append(report)

        return findings
