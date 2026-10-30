import datetime
import unittest
from unittest.mock import mock_open, patch

with patch(
    "builtins.open",
    mock_open(read_data='{"secret_prefix": "", "ecs_cluster": "", "groups": {}}'),
):
    import handler as bootstrap

CHANGED = datetime.datetime(2026, 7, 31, 9, 0, 0)


class MysqlUserRowsTest(unittest.TestCase):
    def test_account_state_and_grant_option_are_reported(self):
        rows = bootstrap._mysql_user_rows(
            [
                ("admin", "%", "N", "N", CHANGED, "Y", None),
                ("legacy", "10.%", "Y", "Y", None, "N", "app,reports"),
            ],
            [],
        )

        self.assertEqual(
            rows,
            [
                {
                    "user": "admin",
                    "host": "%",
                    "locked": False,
                    "password_expired": False,
                    "password_last_changed": "2026-07-31 09:00:00",
                    "grant_option": True,
                    "grant_option_schemas": [],
                    "roles": [],
                },
                {
                    "user": "legacy",
                    "host": "10.%",
                    "locked": True,
                    "password_expired": True,
                    "password_last_changed": None,
                    "grant_option": False,
                    "grant_option_schemas": ["app", "reports"],
                    "roles": [],
                },
            ],
        )

    def test_roles_attach_to_their_grantee_only(self):
        rows = bootstrap._mysql_user_rows(
            [
                ("dba", "%", "N", "N", CHANGED, "N", None),
                ("app", "%", "N", "N", CHANGED, "N", None),
            ],
            [("dba", "%", "rds_superuser_role", "%", "Y")],
        )

        self.assertEqual(
            rows[0]["roles"], [{"role": "rds_superuser_role@%", "admin_option": True}]
        )
        self.assertEqual(rows[1]["roles"], [])

    def test_missing_role_table_reports_unknown_roles_not_none_granted(self):
        rows = bootstrap._mysql_user_rows(
            [("app", "%", "N", "N", CHANGED, "N", None)], None
        )

        self.assertIsNone(rows[0]["roles"])


if __name__ == "__main__":
    unittest.main()
