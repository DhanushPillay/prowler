from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.monitor.monitor_client import monitor_client


class monitor_activity_log_alert_create_update_delete_network_sg_rule(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for subscription, alert_rules in monitor_client.alert_rules.items():
            report = Check_Report_Azure(metadata=self.metadata(), resource={})
            report.status = "FAIL"
            report.subscription = subscription
            report.resource_name = subscription
            report.resource_id = f"/subscriptions/{subscription}"
            report.status_extended = f"There is not an active log alert for 'Create, Update or Delete Network Security Group Rule' in subscription {subscription}."

            for alert_rule in alert_rules:
                if alert_rule.enabled:
                    for condition in alert_rule.condition.all_of:
                        if (
                            condition.field == "category"
                            and condition.equals.lower() == "administrative"
                        ):
                            for condition in alert_rule.condition.all_of:
                                if (
                                    condition.field == "operationName"
                                    and condition.equals.lower()
                                    == "microsoft.network/networksecuritygroups/securityrules/write"
                                ):
                                    for condition in alert_rule.condition.all_of:
                                        if (
                                            condition.field == "operationName"
                                            and condition.equals.lower()
                                            == "microsoft.network/networksecuritygroups/securityrules/delete"
                                        ):
                                            report.status = "PASS"
                                            report.status_extended = f"There is an active log alert for 'Create, Update or Delete Network Security Group Rule' in subscription {subscription}."
                                            report.resource_name = alert_rule.name
                                            report.resource_id = alert_rule.id
                                            break
            findings.append(report)

        return findings
