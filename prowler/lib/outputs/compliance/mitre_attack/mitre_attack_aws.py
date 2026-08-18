from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.compliance.mitre_attack.models import AWSMitreAttackModel
from prowler.lib.outputs.finding import Finding
from prowler.lib.outputs.utils import unroll_list


class AWSMitreAttack(ComplianceOutputBase):
    """
    This class represents the AWS MITRE ATT&CK compliance output.

    Attributes:
        - _data (list): A list to store transformed data from findings.
        - _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.

    Methods:
        - transform: Transforms findings into AWS MITRE ATT&CK compliance format.
    """


    @property
    def model(self):
        return AWSMitreAttackModel

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
