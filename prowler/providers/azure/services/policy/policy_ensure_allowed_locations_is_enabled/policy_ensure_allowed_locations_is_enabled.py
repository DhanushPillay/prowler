from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.policy.policy_client import policy_client


class policy_ensure_allowed_locations_is_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        # TODO: Implement check logic here
        return findings
