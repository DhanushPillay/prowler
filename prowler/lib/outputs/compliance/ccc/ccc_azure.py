from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.ccc.models import CCC_AzureModel
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.finding import Finding


class CCC_Azure(ComplianceOutputBase):
    """
    This class represents the Azure CCC compliance output.

    Attributes:
        - _data (list): A list to store transformed data from findings.
        - _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.

    Methods:
        - transform: Transforms findings into Azure CCC compliance format.
    """


    @property
    def model(self):
        return CCC_AzureModel

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
