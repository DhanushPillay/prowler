import re

from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.sqlserver.sqlserver_client import sqlserver_client


def _retention_exceeds_90_days(retention: str) -> bool:
    if not retention or retention.upper() == "PT0S":
        return False
    match_days = re.match(r"^P(\d+)D$", retention, re.IGNORECASE)
    if match_days:
        return int(match_days.group(1)) > 90
    match_weeks = re.match(r"^P(\d+)W$", retention, re.IGNORECASE)
    if match_weeks:
        return int(match_weeks.group(1)) >= 13
    match_months = re.match(r"^P(\d+)M$", retention, re.IGNORECASE)
    if match_months:
        return int(match_months.group(1)) >= 3
    match_years = re.match(r"^P(\d+)Y$", retention, re.IGNORECASE)
    if match_years:
        return int(match_years.group(1)) >= 1
    return False


class sqlserver_database_retention_policy_exceeds_90_days(Check):
    """Check if SQL Database backup retention policy exceeds 90 days.

    This check verifies that SQL Databases have long-term retention configured for more than 90 days.
    """

    def execute(self) -> list[Check_Report_Azure]:
        """Execute sqlserver_database_retention_policy_exceeds_90_days check.

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
                    if ltr and (
                        _retention_exceeds_90_days(ltr.weekly_retention)
                        or _retention_exceeds_90_days(ltr.monthly_retention)
                        or _retention_exceeds_90_days(ltr.yearly_retention)
                    ):
                        report.status = "PASS"
                        report.status_extended = (
                            f"SQL Database '{database.name}' on server '{server.name}' "
                            f"has backup retention policy configured exceeding 90 days."
                        )
                    else:
                        report.status = "FAIL"
                        report.status_extended = (
                            f"SQL Database '{database.name}' on server '{server.name}' "
                            f"does not have backup retention policy configured exceeding 90 days."
                        )

                    findings.append(report)

        return findings
