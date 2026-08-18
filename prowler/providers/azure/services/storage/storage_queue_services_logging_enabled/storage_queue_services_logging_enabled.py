from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.storage.storage_client import storage_client


class storage_queue_services_logging_enabled(Check):
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
                
                if account.queue_properties and account.queue_properties.logging:
                    if account.queue_properties.logging.read and account.queue_properties.logging.write and account.queue_properties.logging.delete:
                        report.status = "PASS"
                        report.status_extended = f"Storage account {account.name} queue service has Read, Write, and Delete logging enabled."
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"Storage account {account.name} queue service logging does not have Read, Write, and Delete fully enabled."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Storage account {account.name} queue service does not have logging enabled or is not supported."

                findings.append(report)

        return findings
