from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.compliance.prowler_threatscore.models import (
    ProwlerThreatScoreGCPModel,
)
from prowler.lib.outputs.finding import Finding


class ProwlerThreatScoreGCP(ComplianceOutputBase):
    """
    This class represents the GCP Prowler ThreatScore compliance output.

    Attributes:
        - _data (list): A list to store transformed data from findings.
        - _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.

    Methods:
        - transform: Transforms findings into GCP Prowler ThreatScore compliance format.
    """


    @property
    def model(self):
        return ProwlerThreatScoreGCPModel

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
