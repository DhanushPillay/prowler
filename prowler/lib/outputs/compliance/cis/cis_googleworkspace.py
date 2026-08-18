from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.cis.models import GoogleWorkspaceCISModel
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.finding import Finding


class GoogleWorkspaceCIS(ComplianceOutputBase):
    """
    This class represents the Google Workspace CIS compliance output.

    Attributes:
        - _data (list): A list to store transformed data from findings.
        - _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.

    Methods:
        - transform: Transforms findings into Google Workspace CIS compliance format.
    """


    @property
    def model(self):
        return GoogleWorkspaceCISModel

    def provider_identity_fields(self, finding: Finding) -> dict:
        if finding is None:
            return {
                "Domain": "",
            }
        return {
            "Domain": finding.account_name,
        }
