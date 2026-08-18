from datetime import datetime
from io import StringIO
from unittest import mock

from freezegun import freeze_time
from mock import patch

from prowler.lib.outputs.compliance.ens.ens_azure import AzureENS
from prowler.lib.outputs.compliance.ens.models import AzureENSModel
from tests.lib.outputs.compliance.fixtures import ENS_RD2022_AZURE
from tests.lib.outputs.fixtures.fixtures import generate_finding_output


class TestAzureENS:
    def test_output_transform(self):
        findings = [
            generate_finding_output(
                compliance={"ENS-RD2022": "op.exp.8.azure.ct.3"},
                provider="azure",
                region="global",
            ),
        ]

        output = AzureENS(findings, ENS_RD2022_AZURE)
        output_data = output.data[0]
        assert isinstance(output_data, AzureENSModel)
        assert output_data.Provider == "azure"
        assert output_data.Framework == ENS_RD2022_AZURE.Framework
        assert output_data.Name == ENS_RD2022_AZURE.Name
        assert output_data.SubscriptionId == "123456789012"
        assert output_data.Location == "global"
        assert output_data.Description == ENS_RD2022_AZURE.Description
        assert output_data.Requirements_Id == ENS_RD2022_AZURE.Requirements[0].Id
        assert (
            output_data.Requirements_Description
            == ENS_RD2022_AZURE.Requirements[0].Description
        )
        assert (
            output_data.Requirements_Attributes_IdGrupoControl
            == ENS_RD2022_AZURE.Requirements[0].Attributes[0].IdGrupoControl
        )
        assert (
            output_data.Requirements_Attributes_Marco
            == ENS_RD2022_AZURE.Requirements[0].Attributes[0].Marco
        )
        assert (
            output_data.Requirements_Attributes_Categoria
            == ENS_RD2022_AZURE.Requirements[0].Attributes[0].Categoria
        )
        assert (
            output_data.Requirements_Attributes_DescripcionControl
            == ENS_RD2022_AZURE.Requirements[0].Attributes[0].DescripcionControl
        )
        assert (
            output_data.Requirements_Attributes_Nivel
            == ENS_RD2022_AZURE.Requirements[0].Attributes[0].Nivel
        )
        assert (
            output_data.Requirements_Attributes_Tipo
            == ENS_RD2022_AZURE.Requirements[0].Attributes[0].Tipo
        )
        assert [
            output_data.Requirements_Attributes_Dimensiones
        ] == ENS_RD2022_AZURE.Requirements[0].Attributes[0].Dimensiones
        assert (
            output_data.Requirements_Attributes_ModoEjecucion
            == ENS_RD2022_AZURE.Requirements[0].Attributes[0].ModoEjecucion
        )
        assert output_data.Requirements_Attributes_Dependencias == ""
        assert output_data.Status == "PASS"
        assert output_data.StatusExtended == ""
        assert output_data.ResourceId == ""
        assert output_data.ResourceName == ""
        assert output_data.CheckId == "service_test_check_id"
        assert output_data.Muted is False
        # Test manual check
        output_data_manual = output.data[1]
        assert output_data_manual.Provider == "azure"
        assert output_data_manual.Framework == ENS_RD2022_AZURE.Framework
        assert output_data_manual.Name == ENS_RD2022_AZURE.Name
        assert output_data_manual.SubscriptionId == ""
        assert output_data_manual.Location == ""
        assert output_data_manual.Requirements_Id == ENS_RD2022_AZURE.Requirements[1].Id
        assert (
            output_data_manual.Requirements_Description
            == ENS_RD2022_AZURE.Requirements[1].Description
        )
        assert (
            output_data_manual.Requirements_Attributes_IdGrupoControl
            == ENS_RD2022_AZURE.Requirements[1].Attributes[0].IdGrupoControl
        )
        assert (
            output_data_manual.Requirements_Attributes_Marco
            == ENS_RD2022_AZURE.Requirements[1].Attributes[0].Marco
        )
        assert (
            output_data_manual.Requirements_Attributes_Categoria
            == ENS_RD2022_AZURE.Requirements[1].Attributes[0].Categoria
        )
        assert (
            output_data_manual.Requirements_Attributes_DescripcionControl
            == ENS_RD2022_AZURE.Requirements[1].Attributes[0].DescripcionControl
        )
        assert (
            output_data_manual.Requirements_Attributes_Nivel
            == ENS_RD2022_AZURE.Requirements[1].Attributes[0].Nivel
        )
        assert (
            output_data_manual.Requirements_Attributes_Tipo
            == ENS_RD2022_AZURE.Requirements[1].Attributes[0].Tipo
        )
        assert [
            output_data_manual.Requirements_Attributes_Dimensiones
        ] == ENS_RD2022_AZURE.Requirements[1].Attributes[0].Dimensiones
        assert (
            output_data_manual.Requirements_Attributes_ModoEjecucion
            == ENS_RD2022_AZURE.Requirements[1].Attributes[0].ModoEjecucion
        )
        assert output_data_manual.Status == "MANUAL"
        assert output_data_manual.StatusExtended == "Manual check"
        assert output_data_manual.ResourceId == "manual_check"
        assert output_data_manual.ResourceName == "Manual check"
        assert output_data_manual.CheckId == "manual"
        assert output_data_manual.Muted is False

    @freeze_time("2025-01-01 00:00:00")
    @mock.patch(
        "prowler.lib.outputs.compliance.compliance_output.timestamp", "2025-01-01 00:00:00"
    )
    def test_batch_write_data_to_file(self):
        mock_file = StringIO()
        findings = [
            generate_finding_output(
                compliance={"ENS-RD2022": "op.exp.8.azure.ct.3"},
                provider="azure",
                region="global",
            ),
        ]
        output = AzureENS(findings, ENS_RD2022_AZURE)
        output._file_descriptor = mock_file

        with patch.object(mock_file, "close", return_value=None):
            output.batch_write_data_to_file()

        assert content == expected_csv

    def test_output_transform_with_none_account_name(self):
        finding = generate_finding_output(
            compliance={"ENS-RD2022": "op.exp.8.azure.ct.3"},
            provider="azure",
            region="global",
        )
        finding.account_name = None
        output = AzureENS([finding], ENS_RD2022_AZURE)
        output_data = output.data[0]
        assert output_data.SubscriptionId == ""
        assert output_data.Location == "global"

