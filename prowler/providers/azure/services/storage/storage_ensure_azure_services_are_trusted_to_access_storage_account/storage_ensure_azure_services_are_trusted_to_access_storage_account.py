from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.storage.storage_client import storage_client


class storage_ensure_azure_services_are_trusted_to_access_storage_account(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription_id, storage_accounts in storage_client.storage_accounts.items():
            for account in storage_accounts:
                report = Check_Report_Azure(
                    metadata=self.metadata(),
                    resource_id=account.id,
                    resource_name=account.name,
                    subscription_id=subscription_id,
                    location=account.location,
                )
                
                # Check if network rules default action is Deny, as bypass only matters if default is Deny.
                if account.network_rule_set.default_action == "Deny":
                    if "AzureServices" in account.network_rule_set.bypass:
                        report.status = "PASS"
                        report.status_extended = f"Storage account {account.name} allows trusted Microsoft services to access this storage account."
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"Storage account {account.name} does not allow trusted Microsoft services to access this storage account."
                else:
                    report.status = "PASS"
                    report.status_extended = f"Storage account {account.name} default network access rule is Allow, so trusted Microsoft services have access."

                findings.append(report)

        return findings
