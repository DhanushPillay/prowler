from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.cis.models import M365CISModel
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.finding import Finding


class M365CIS(ComplianceOutputBase):
    """
    This class represents the Azure CIS compliance output.

    Attributes:
        - _data (list): A list to store transformed data from findings.
        - _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.

    Methods:
        - transform: Transforms findings into Azure CIS compliance format.
    """


    @property
    def model(self):
        return M365CISModel

    def provider_identity_fields(self, finding: Finding) -> dict:
        if finding is None:
            return {
                "TenantId": "",
                "Location": "",
            }
        return {
            "TenantId": finding.account_uid,
            "Location": finding.region,
        }
