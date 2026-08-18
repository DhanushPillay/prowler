from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.asd_essential_eight.models import (
    ASDEssentialEightAWSModel,
)
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.finding import Finding


class ASDEssentialEightAWS(ComplianceOutputBase):
    """
    This class represents the AWS ASD Essential Eight compliance output.

    Attributes:
        - _data (list): A list to store transformed data from findings.
        - _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.

    Methods:
        - transform: Transforms findings into AWS Essential Eight compliance format.
    """


    @property
    def model(self):
        return ASDEssentialEightAWSModel

    def provider_identity_fields(self, finding: Finding) -> dict:
        if finding is None:
            return {
                "AccountId": "",
                "Region": "",
            }
        return {
            "AccountId": finding.account_uid,
            "Region": finding.region,
        }
