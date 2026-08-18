from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.app.app_client import app_client


class app_ensure_auth_is_set_up(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription_id, apps in app_client.apps.items():
            for app_id, app in apps.items():
                report = Check_Report_Azure(
                    metadata=self.metadata(),
                    resource_id=app.resource_id,
                    resource_name=app.name,
                    subscription_id=subscription_id,
                    location=app.location,
                )
                
                if app.auth_enabled:
                    report.status = "PASS"
                    report.status_extended = f"App {app.name} has authentication set up."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"App {app.name} does not have authentication set up."

                findings.append(report)

        return findings
