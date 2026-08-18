from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.storage.storage_client import storage_client


class storage_key_rotation_90_days(Check):
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
                
                if account.key_expiration_period_in_days is not None and account.key_expiration_period_in_days <= 90:
                    report.status = "PASS"
                    report.status_extended = f"Storage account {account.name} has a key expiration period of {account.key_expiration_period_in_days} days (90 days or less)."
                else:
                    report.status = "FAIL"
                    if account.key_expiration_period_in_days is None:
                        report.status_extended = f"Storage account {account.name} does not have a key expiration period configured."
                    else:
                        report.status_extended = f"Storage account {account.name} has a key expiration period of {account.key_expiration_period_in_days} days, which is greater than 90 days."

                findings.append(report)

        return findings
