from typing import Type, Optional
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.compliance_output import ComplianceOutputBase
from prowler.lib.outputs.compliance.mitre_attack.models import AzureMitreAttackModel
from prowler.lib.outputs.finding import Finding
from prowler.lib.check.compliance_models import Mitre_Requirement
from prowler.lib.outputs.utils import unroll_list


class AzureMitreAttack(ComplianceOutputBase):
    """
    This class represents the Azure MITRE ATT&CK compliance output.

    Attributes:
        - _data (list): A list to store transformed data from findings.
        - _file_descriptor (TextIOWrapper): A file descriptor to write data to a file.

    Methods:
        - transform: Transforms findings into Azure MITRE ATT&CK compliance format.
    """


    @property
    def model(self) -> Type[AzureMitreAttackModel]:
        """Returns the specific AzureMitreAttackModel.

        Returns:
            Type[AzureMitreAttackModel]: The AzureMitreAttackModel class.
        """
        return AzureMitreAttackModel

    def provider_identity_fields(self, finding: Optional[Finding]) -> dict:
        """Returns the provider specific fields for the compliance output.

        Args:
            finding (Optional[Finding]): The finding to extract identity fields from, or None for manual checks.

        Returns:
            dict: A dictionary containing SubscriptionId and Location.
        """
        if finding is None:
            return {
                "SubscriptionId": "",
                "Location": "",
            }
        return {
            "SubscriptionId": finding.account_uid,
            "Location": finding.region,
        }

    def get_framework_specific_fields(self, requirement: Mitre_Requirement) -> dict[str, str]:
        """Returns framework-specific fields for the compliance output.

        Args:
            requirement (Mitre_Requirement): The MITRE requirement containing Tactics, SubTechniques, Platforms, TechniqueURL, and Name.

        Returns:
            dict[str, str]: A dictionary containing framework-specific fields.
        """
        return {
            "Requirements_Name": requirement.Name,
            "Requirements_Tactics": unroll_list(getattr(requirement, "Tactics", [])),
            "Requirements_SubTechniques": unroll_list(getattr(requirement, "SubTechniques", [])),
            "Requirements_Platforms": unroll_list(getattr(requirement, "Platforms", [])),
            "Requirements_TechniqueURL": getattr(requirement, "TechniqueURL", ""),
        }


