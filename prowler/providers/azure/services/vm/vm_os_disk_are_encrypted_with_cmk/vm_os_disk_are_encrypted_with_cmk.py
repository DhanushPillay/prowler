from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.vm.vm_client import vm_client


class vm_os_disk_are_encrypted_with_cmk(Check):
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
                
                report.status = "PASS"
                report.status_extended = f"VM {vm.resource_name} OS disk is encrypted with Customer Managed Key (CMK)."
                
                os_disk = getattr(getattr(vm, "storage_profile", None), "os_disk", None)
                if os_disk and os_disk.managed_disk and os_disk.managed_disk.id:
                    # Look up disk in vm_client.disks
                    disk = None
                    # disk keys are disk.unique_id, which we don't have. We only have disk.resource_id (the full path)
                    # We can iterate through disks to find the matching resource_id
                    for d_id, d in vm_client.disks.get(subscription_id, {}).items():
                        if d.resource_id.lower() == os_disk.managed_disk.id.lower():
                            disk = d
                            break
                    
                    if disk:
                        if disk.encryption_type in ["EncryptionAtRestWithCustomerKey", "EncryptionAtRestWithPlatformAndCustomerKeys"]:
                            report.status = "PASS"
                            report.status_extended = f"VM {vm.resource_name} OS disk {disk.resource_name} is encrypted with a Customer Managed Key (CMK)."
                        else:
                            report.status = "FAIL"
                            report.status_extended = f"VM {vm.resource_name} OS disk {disk.resource_name} is not encrypted with a Customer Managed Key (CMK)."
                    else:
                        # Managed disk ID found, but not present in the disks dictionary
                        report.status = "FAIL"
                        report.status_extended = f"VM {vm.resource_name} OS disk is unmanaged or its encryption status could not be verified."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"VM {vm.resource_name} does not have a managed OS disk."
                    
                findings.append(report)

        return findings
