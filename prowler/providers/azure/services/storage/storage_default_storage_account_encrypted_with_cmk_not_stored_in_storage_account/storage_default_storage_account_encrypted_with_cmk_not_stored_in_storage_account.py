from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.storage.storage_client import storage_client


class storage_default_storage_account_encrypted_with_cmk_not_stored_in_storage_account(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        # TODO: Implement check logic here
        return findings
