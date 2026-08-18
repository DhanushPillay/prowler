from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.compliance.okta_idaas_stig.models import OktaIDaaSSTIGModel
from prowler.lib.outputs.finding import Finding


class OktaIDaaSSTIG(ComplianceOutputBase):
    """
    This class represents the Okta IDaaS STIG compliance output.

    Attributes:
        - _data (list): A list to store transformed data from findings.
        - _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.

    Methods:
        - transform: Transforms findings into Okta IDaaS STIG compliance format.
    """


    @property
    def model(self):
        return OktaIDaaSSTIGModel

    def provider_identity_fields(self, finding: Finding) -> dict:
        if finding is None:
            return {
                "OrganizationDomain": "",
            }
        return {
            "OrganizationDomain": finding.account_name,
        }
