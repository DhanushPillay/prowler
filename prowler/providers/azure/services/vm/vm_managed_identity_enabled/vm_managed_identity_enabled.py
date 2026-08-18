from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.vm.vm_client import vm_client


class vm_managed_identity_enabled(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for subscription, vms in vm_client.virtual_machines.items():
            for vm in vms:
                report = Check_Report_Azure(metadata=self.metadata(), resource=vm)
                report.subscription = subscription
                report.status = "FAIL"
                report.status_extended = f"VM {vm.name} does not have a managed identity enabled."

                if vm.identity and vm.identity.type != "None":
                    report.status = "PASS"
                    report.status_extended = f"VM {vm.name} has a managed identity ({vm.identity.type}) enabled."

                findings.append(report)

        return findings
