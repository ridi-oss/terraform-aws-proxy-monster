import os
import ssl
import unittest
import uuid
from dataclasses import replace
from unittest.mock import MagicMock, mock_open, patch

import pymysql

with patch(
    "builtins.open",
    mock_open(read_data='{"secret_prefix": "", "ecs_cluster": "", "groups": {}}'),
):
    import handler as bootstrap

ROOT_PASSWORD = "local-bootstrap-test"
DB = f"pmit{uuid.uuid4().hex[:8]}"


def insecure_tls(_group=None):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


@unittest.skipUnless(
    os.environ.get("MYSQL_TEST_PORT"),
    "set MYSQL_TEST_PORT for an isolated MySQL 8.0 instance",
)
class MysqlIntegrationTest(unittest.TestCase):
    @classmethod
    def connect(cls, user="root", password=ROOT_PASSWORD):
        return pymysql.connect(
            host="127.0.0.1",
            port=int(os.environ["MYSQL_TEST_PORT"]),
            user=user,
            password=password,
            ssl=insecure_tls(),
            autocommit=True,
        )

    @classmethod
    def root(cls, *statements):
        with cls.connect() as connection, connection.cursor() as cursor:
            rows = []
            for sql, *args in statements:
                cursor.execute(sql, *args)
                rows = cursor.fetchall()
            return rows

    @classmethod
    def setUpClass(cls):
        client = cls.root(("SELECT SUBSTRING_INDEX(USER(), '@', -1)",))[0][0]
        cls.host_pattern = client.split(".")[0] + ".%"
        cls.log_settings = cls.root(
            ("SELECT @@GLOBAL.log_output, @@GLOBAL.general_log",)
        )[0]
        cls.root(
            (f"CREATE DATABASE {DB}",),
            (f"CREATE TABLE {DB}.orders (id int)",),
            (f"CREATE TABLE {DB}.orders__deprecated_1 (id int)",),
            (f"CREATE PROCEDURE {DB}.noop() BEGIN END",),
            ("SET GLOBAL log_output = 'TABLE'",),
            ("SET GLOBAL general_log = 'ON'",),
        )

    @classmethod
    def tearDownClass(cls):
        log_output, general_log = cls.log_settings
        cls.root(
            ("SET GLOBAL general_log = %s", (general_log,)),
            ("SET GLOBAL log_output = %s", (log_output,)),
            (f"DROP DATABASE {DB}",),
        )

    def tearDown(self):
        self.root((f"DROP USER IF EXISTS {self.user}",))

    def setUp(self):
        self.group = bootstrap.Group(
            engine="mysql",
            database=DB,
            schemas=[DB],
            privileges=["SELECT", "INSERT"],
            system_schemas=[],
            system_routines=[f"{DB}.noop"],
            global_privileges=[],
            username=f"pm_{uuid.uuid4().hex[:12]}",
            host_pattern=self.host_pattern,
            datasources={"app-rw": "127.0.0.1"},
            serving=["app-rw"],
            drop_tables=[f"{DB}.*__deprecated*"],
        )
        self.user = f"'{self.group.username}'@'{self.host_pattern}'"

    def apply(self, password):
        with patch.object(bootstrap, "_tls_context", side_effect=insecure_tls):
            return bootstrap._provision_mysql(
                self.group,
                "127.0.0.1",
                int(os.environ["MYSQL_TEST_PORT"]),
                bootstrap.MasterCredential("root", bootstrap.Secret(ROOT_PASSWORD)),
                password,
            )

    def provision(self, password="first-password"):
        return self.apply(bootstrap.Secret(password))

    def credential_row(self):
        return self.root(
            (
                "SELECT authentication_string FROM mysql.user WHERE User = %s",
                (self.group.username,),
            )
        )

    def logged_statements(self):
        rows = self.root(
            (
                "SELECT CONVERT(argument USING utf8mb4) FROM mysql.general_log"
                " WHERE command_type = 'Query'",
            )
        )
        return [
            sql
            for (sql,) in rows
            if self.group.username in sql and "general_log" not in sql
        ]

    def test_provision_creates_a_login_with_table_level_drop(self):
        grants, skipped, _ = self.provision()
        self.assertEqual(skipped, [])
        self.assertIn(f"DROP ON {DB}.orders__deprecated_1", grants)
        with self.connect(self.group.username, "first-password") as connection:
            connection.cursor().execute(f"SELECT 1 FROM {DB}.orders")

    def test_grants_picks_up_a_new_table_without_touching_the_password(self):
        self.provision()
        credential = self.credential_row()
        table = f"orders__deprecated_{uuid.uuid4().hex[:8]}"
        self.root(
            (f"CREATE TABLE {DB}.{table} (id int)",), ("TRUNCATE mysql.general_log",)
        )

        grants, _, added = self.apply(None)

        self.assertEqual(added, [f"DROP ON {DB}.{table}"])
        self.assertIn(f"DROP ON {DB}.{table}", grants)
        self.assertEqual(self.credential_row(), credential)
        sent = self.logged_statements()
        self.assertTrue([sql for sql in sent if sql.startswith("GRANT DROP")])
        self.assertFalse(
            [sql for sql in sent if "IDENTIFIED" in sql or "REVOKE" in sql]
        )
        with self.connect(self.group.username, "first-password") as connection:
            connection.cursor().execute(f"DROP TABLE {DB}.{table}")

    def test_grants_restores_a_revoked_privilege(self):
        self.provision()
        self.root((f"REVOKE INSERT ON {DB}.* FROM {self.user}",))

        _, _, added = self.apply(None)

        self.assertEqual(added, [f"INSERT ON {DB}"])
        with self.connect(self.group.username, "first-password") as connection:
            connection.cursor().execute(f"INSERT INTO {DB}.orders VALUES (1)")
        self.assertEqual(self.apply(None)[2], [])

    def test_grants_restores_and_reports_a_revoked_routine_execute(self):
        self.assertIn(f"EXECUTE ON PROCEDURE {DB}.noop", self.provision()[0])
        self.root((f"REVOKE EXECUTE ON PROCEDURE {DB}.noop FROM {self.user}",))

        _, _, added = self.apply(None)

        self.assertEqual(added, [f"EXECUTE ON PROCEDURE {DB}.noop"])
        with self.connect(self.group.username, "first-password") as connection:
            connection.cursor().execute(f"CALL {DB}.noop()")

    def test_grants_keeps_an_extra_privilege_that_provision_removes(self):
        self.provision()
        self.root((f"GRANT DELETE ON {DB}.* TO {self.user}",))

        grants, _, added = self.apply(None)
        self.assertIn(f"DELETE ON {DB}", grants)
        self.assertEqual(added, [])

        grants, _, _ = self.provision("second-password")
        self.assertNotIn(f"DELETE ON {DB}", grants)

    def test_live_connection_keeps_working_across_grants(self):
        self.provision()
        with self.connect(self.group.username, "first-password") as connection:
            cursor = connection.cursor()
            cursor.execute(f"SELECT 1 FROM {DB}.orders")
            self.apply(None)
            cursor.execute(f"SELECT 1 FROM {DB}.orders")
            cursor.execute(f"INSERT INTO {DB}.orders VALUES (2)")

    def test_grants_refuses_a_missing_user_and_creates_nothing(self):
        with self.assertRaisesRegex(bootstrap.BootstrapError, "does not exist"):
            self.apply(None)
        self.assertEqual(self.credential_row(), ())

    def test_handler_grants_after_provision_keeps_the_published_password(self):
        publish = MagicMock(return_value=["app-rw"])
        restart = MagicMock(return_value=["proxy-app-rw"])
        master = bootstrap.MasterCredential("root", bootstrap.Secret(ROOT_PASSWORD))
        with (
            patch.dict(
                bootstrap.CONFIG.groups,
                {"it": replace(self.group, system_routines=[])},
            ),
            patch.object(
                bootstrap,
                "_resolve",
                return_value=(
                    "127.0.0.1",
                    int(os.environ["MYSQL_TEST_PORT"]),
                    {"127.0.0.1"},
                    master,
                ),
            ),
            patch.object(bootstrap, "_tls_context", side_effect=insecure_tls),
            patch.object(bootstrap, "_publish", publish),
            patch.object(bootstrap, "_restart_proxies", restart),
        ):
            provisioned = bootstrap.handler({"group": "it"}, None)
            published = publish.call_args.args[1].reveal()
            publish.reset_mock()
            restart.reset_mock()
            granted = bootstrap.handler({"action": "grants", "group": "it"}, None)

        self.assertTrue(provisioned["password_rotated"])
        self.assertFalse(granted["password_rotated"])
        self.assertEqual(granted["secrets_written"], [])
        self.assertEqual(granted["services_restarted"], [])
        self.assertEqual(granted["grants_added"], [])
        publish.assert_not_called()
        restart.assert_not_called()
        with self.connect(self.group.username, published) as connection:
            connection.cursor().execute(f"SELECT 1 FROM {DB}.orders")


if __name__ == "__main__":
    unittest.main()
