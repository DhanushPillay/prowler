from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.vm.vm_client import vm_client


class vm_availability_set_deployed(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription_id, virtual_machines in vm_client.virtual_machines.items():
            for vm_id, vm in virtual_machines.items():
                report = Check_Report_Azure(
                    metadata=self.metadata(),
                    resource_id=vm.resource_id,
                    resource_name=vm.resource_name,
                    subscription_id=subscription_id,
                    location=vm.location,
                )
                
                if vm.availability_set:
                    report.status = "PASS"
                    report.status_extended = f"VM {vm.resource_name} is deployed in an availability set."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"VM {vm.resource_name} is not deployed in an availability set."
                    
                findings.append(report)

        return findings
