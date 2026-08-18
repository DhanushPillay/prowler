from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.vm.vm_client import vm_client


class vm_guest_configuration_with_user_identity(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []
        for subscription_id, virtual_machines in vm_client.virtual_machines.items():
            for vm_id, vm in virtual_machines.items():
                
                guest_config_installed = False
                for extension in vm.extensions:
                    publisher = extension.publisher.lower()
                    ext_type = extension.type.lower()
                    if "guestconfiguration" in publisher or "guestconfiguration" in ext_type:
                        guest_config_installed = True
                        break

                if guest_config_installed:
                    report = Check_Report_Azure(
                        metadata=self.metadata(),
                        resource_id=vm.resource_id,
                        resource_name=vm.resource_name,
                        subscription_id=subscription_id,
                        location=vm.location,
                    )
                    
                    if vm.identity and "UserAssigned" in vm.identity.type:
                        report.status = "PASS"
                        report.status_extended = f"VM {vm.resource_name} has Guest Configuration installed and uses a User-Assigned Managed Identity."
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"VM {vm.resource_name} has Guest Configuration installed but does not have a User-Assigned Managed Identity."
                        
                    findings.append(report)

        return findings
