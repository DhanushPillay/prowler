from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.storage.storage_client import storage_client


class storage_default_network_access_rule_is_denied(Check):
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
                
                if account.network_rule_set.default_action == "Deny":
                    report.status = "PASS"
                    report.status_extended = f"Storage account {account.name} has default network access rule set to Deny."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Storage account {account.name} does not have default network access rule set to Deny."

                findings.append(report)

        return findings
