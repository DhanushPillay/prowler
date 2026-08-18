from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.cis.models import OracleCloudCISModel
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.finding import Finding


class OracleCloudCIS(ComplianceOutputBase):
    """
    This class represents the Oracle Cloud CIS compliance output.

    Attributes:
        - _data (list): A list to store transformed data from findings.
        - _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.

    Methods:
        - transform: Transforms findings into Oracle Cloud CIS compliance format.
    """


    @property
    def model(self):
        return OracleCloudCISModel

    def provider_identity_fields(self, finding: Finding) -> dict:
        if finding is None:
            return {
                "TenancyId": "",
                "Region": "",
            }
        return {
            "TenancyId": finding.account_uid,
            "Region": finding.region,
        }
