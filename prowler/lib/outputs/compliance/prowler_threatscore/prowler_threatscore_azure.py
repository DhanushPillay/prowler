from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.compliance.prowler_threatscore.models import (
    ProwlerThreatScoreAzureModel,
)
from prowler.lib.outputs.finding import Finding


class ProwlerThreatScoreAzure(ComplianceOutputBase):
    """
    This class represents the Azure Prowler ThreatScore compliance output.

    Attributes:
        - _data (list): A list to store transformed data from findings.
        - _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.

    Methods:
        - transform: Transforms findings into Azure Prowler ThreatScore compliance format.
    """


    @property
    def model(self):
        return ProwlerThreatScoreAzureModel

    def provider_identity_fields(self, finding: Finding) -> dict:
        if finding is None:
            return {
                "SubscriptionId": "",
                "Location": "",
            }
        return {
            "SubscriptionId": finding.account_uid,
            "Location": finding.region,
        }
