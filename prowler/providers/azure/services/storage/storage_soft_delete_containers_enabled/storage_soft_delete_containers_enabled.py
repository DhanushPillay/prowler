from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.storage.storage_client import storage_client


class storage_soft_delete_containers_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        # TODO: Implement check logic here
        return findings
