from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.vm.vm_client import vm_client


class vm_guest_configuration_with_user_identity(Check):
    """Check if Virtual Machines with Guest Configuration use a user-assigned managed identity.

    This check verifies that Virtual Machines with the Guest Configuration extension installed
    are configured with a user-assigned managed identity.
    """

    def execute(self) -> list[Check_Report_Azure]:
        """Execute vm_guest_configuration_with_user_identity check.

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

                    if vm.identity and "UserAssigned" in vm.identity.type:
                        report.status = "PASS"
                        report.status_extended = f"VM {vm.resource_name} has Guest Configuration installed and uses a User-Assigned Managed Identity."
                    else:
                        report.status = "FAIL"
                        report.status_extended = f"VM {vm.resource_name} has Guest Configuration installed but does not have a User-Assigned Managed Identity."

                    findings.append(report)

        return findings

