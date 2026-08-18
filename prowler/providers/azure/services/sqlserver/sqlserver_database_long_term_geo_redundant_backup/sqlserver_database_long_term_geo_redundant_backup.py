from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.sqlserver.sqlserver_client import sqlserver_client


class sqlserver_database_long_term_geo_redundant_backup(Check):
    """Check if SQL Database long-term geo-redundant backup is enabled.

    This check verifies that SQL Databases have long-term retention backup policies enabled.
    """

    def execute(self) -> list[Check_Report_Azure]:
        """Execute sqlserver_database_long_term_geo_redundant_backup check.

        Returns:
            list[Check_Report_Azure]: List of findings for SQL Databases.
        """
        findings = []
        for subscription_id, servers in sqlserver_client.sql_servers.items():
            for server in servers:
                for database in server.databases:
                    if database.name.lower() == "master":
                        continue

                    report = Check_Report_Azure(
                        metadata=self.metadata(),
                        resource=database,
                    )
                    report.subscription = subscription_id
                    report.resource_id = database.id
                    report.resource_name = database.name
                    report.location = database.location

                    ltr = database.ltr_policy
                    has_ltr = (
                        ltr is not None
                        and (
                            (ltr.weekly_retention and ltr.weekly_retention.upper() != "PT0S")
                            or (ltr.monthly_retention and ltr.monthly_retention.upper() != "PT0S")
                            or (ltr.yearly_retention and ltr.yearly_retention.upper() != "PT0S")
                        )
                    )

                    if has_ltr:
                        report.status = "PASS"
                        report.status_extended = (
                            f"SQL Database '{database.name}' on server '{server.name}' "
                            f"has long-term geo-redundant backup configured."
                        )
                    else:
                        report.status = "FAIL"
                        report.status_extended = (
                            f"SQL Database '{database.name}' on server '{server.name}' "
                            f"does not have long-term geo-redundant backup configured."
                        )

                    findings.append(report)

        return findings

