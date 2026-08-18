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
            report.status_extended = f"There is not an active log alert for 'monitor activity log alert create update delete network sg rule' in subscription {subscription}."

            # We need to find if there are rules that cover write and delete operations
            write_covered = False
            delete_covered = False
            
            for alert_rule in alert_rules:
                if not alert_rule.enabled:
                    continue
                    
                is_administrative = False
                has_write = False
                has_delete = False
                has_all_ops = True
                
                for condition in alert_rule.condition.all_of:
                    if condition.field == "category" and condition.equals.lower() == "administrative":
                        is_administrative = True
                    if condition.field == "operationName":
                        has_all_ops = False
                        op_name = condition.equals.lower()
                        if op_name in ['microsoft.network/networksecuritygroups/securityrules/write']:
                            has_write = True
                        if op_name in ['microsoft.network/networksecuritygroups/securityrules/delete']:
                            has_delete = True
                            
                if is_administrative:
                    if has_write or has_all_ops:
                        write_covered = True
                    if has_delete or has_all_ops:
                        delete_covered = True
                        
            if write_covered and delete_covered:
                report.status = "PASS"
                report.status_extended = f"There is an active log alert for 'monitor activity log alert create update delete network sg rule' in subscription {subscription}."

            findings.append(report)

        return findings
