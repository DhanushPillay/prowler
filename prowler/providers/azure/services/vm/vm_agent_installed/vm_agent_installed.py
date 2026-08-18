from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.vm.vm_client import vm_client


class vm_agent_installed(Check):
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
                
                agent_installed = False
                if vm.os_profile:
                    if vm.os_profile.windows_configuration and vm.os_profile.windows_configuration.provision_vm_agent:
                        agent_installed = True
                    if vm.linux_configuration and vm.linux_configuration.provision_vm_agent:
                        agent_installed = True

                if agent_installed:
                    report.status = "PASS"
                    report.status_extended = f"VM {vm.resource_name} has the VM agent installed."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"VM {vm.resource_name} does not have the VM agent installed."
                    
                findings.append(report)

        return findings
