from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.vm.vm_client import vm_client


class vm_guest_configuration_with_no_managed_identity(Check):
    """Check if Virtual Machines with Guest Configuration have a system-assigned managed identity.

    This check verifies that Virtual Machines that have the Guest Configuration extension installed
    are configured with a system-assigned managed identity.
    """

    def execute(self) -> list[Check_Report_Azure]:
        """Execute vm_guest_configuration_with_no_managed_identity check.

        Returns:
            list[Check_Report_Azure]: List of findings for Virtual Machines.
        """
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
                        resource=vm,
                    )
                    report.subscription = subscription_id
                    report.resource_id = vm.resource_id
                    report.resource_name = vm.resource_name
                    report.location = vm.location

                    if vm.identity and "SystemAssigned" in vm.identity.type:
                        report.status = "PASS"
                        report.status_extended = f"VM {vm.resource_name} has Guest Configuration extension installed and has a system-assigned managed identity."
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"VM {vm.resource_name} has Guest Configuration extension installed but does not have a system-assigned managed identity."

                    findings.append(report)

        return findings

