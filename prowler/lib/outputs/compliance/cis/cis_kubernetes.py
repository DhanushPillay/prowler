from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.cis.models import KubernetesCISModel
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.finding import Finding


class KubernetesCIS(ComplianceOutputBase):
    """
    This class represents the Kubernetes CIS compliance output.

    Attributes:
        - _data (list): A list to store transformed data from findings.
        - _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.

    Methods:
        - transform: Transforms findings into Kubernetes CIS compliance format.
    """


    @property
    def model(self):
        return KubernetesCISModel

    def provider_identity_fields(self, finding: Finding) -> dict:
        if finding is None:
            return {
                "Context": "",
                "Namespace": "",
            }
        return {
            "Context": finding.account_name,
            "Namespace": finding.region,
        }
