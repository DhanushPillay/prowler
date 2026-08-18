from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.monitor.monitor_client import monitor_client


class monitor_activity_log_retention_policy_set(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        # TODO: Implement check logic here
        return findings
