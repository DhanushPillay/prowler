from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.ccc.models import CCC_GCPModel
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.finding import Finding


class CCC_GCP(ComplianceOutputBase):
    """
    This class represents the GCP CCC compliance output.

    Attributes:
        - _data (list): A list to store transformed data from findings.
        - _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.

    Methods:
        - transform: Transforms findings into GCP CCC compliance format.
    """


    @property
    def model(self):
        return CCC_GCPModel

    def provider_identity_fields(self, finding: Finding) -> dict:
        if finding is None:
            return {
                "ProjectId": "",
                "Location": "",
            }
        return {
            "ProjectId": finding.account_uid,
            "Location": finding.region,
        }
