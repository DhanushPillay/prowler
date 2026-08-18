from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.vm.vm_client import vm_client


class vm_encrypted_at_host(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for subscription, vms in vm_client.virtual_machines.items():
            for vm in vms:
                report = Check_Report_Azure(metadata=self.metadata(), resource=vm)
                report.subscription = subscription
                report.status = "FAIL"
                report.status_extended = f"VM {vm.name} does not have encryption at host enabled."

                if vm.security_profile and vm.security_profile.encryption_at_host:
                    report.status = "PASS"
                    report.status_extended = f"VM {vm.name} has encryption at host enabled."

                findings.append(report)

        return findings
