from typing import Type, Optional
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.compliance.ens.models import AzureENSModel
from prowler.lib.outputs.finding import Finding


class AzureENS(ComplianceOutputBase):
    """
    This class represents the Azure ENS compliance output.

    Attributes:
        - _data (list): A list to store transformed data from findings.
        - _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.

    Methods:
        - transform: Transforms findings into Azure ENS compliance format.
    """


    @property
    def model(self) -> Type[AzureENSModel]:
        """Returns the specific AzureENSModel."""
        return AzureENSModel

    def provider_identity_fields(self, finding: Optional[Finding]) -> dict:
        """Returns the provider specific fields for the compliance output."""
        if finding is None:
            return {
                "SubscriptionId": "",
                "Location": "",
            }
        return {
            "SubscriptionId": finding.account_name,
            "Location": finding.region,
        }
