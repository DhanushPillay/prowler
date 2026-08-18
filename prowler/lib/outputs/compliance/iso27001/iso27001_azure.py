from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.compliance.iso27001.models import AzureISO27001Model
from prowler.lib.outputs.finding import Finding


class AzureISO27001(ComplianceOutputBase):
    """
    This class represents the Azure ISO 27001 compliance output.

    Attributes:
        - _data (list): A list to store transformed data from findings.
        - _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.

    Methods:
        - transform: Transforms findings into Azure ISO 27001 compliance format.
    """


    @property
    def model(self):
        return AzureISO27001Model

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
