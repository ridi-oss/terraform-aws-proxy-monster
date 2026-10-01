import os
import unittest
import uuid
from dataclasses import replace
from unittest.mock import mock_open, patch

import pg8000.dbapi

with patch(
    "builtins.open",
    mock_open(read_data='{"secret_prefix": "", "ecs_cluster": "", "groups": {}}'),
):
    import handler as bootstrap


def make_group(**changes):
    return replace(
        bootstrap.Group(
            engine="postgres",
            database="postgres",
            schemas=["inherit_test"],
            privileges=["SELECT"],
            system_schemas=[],
            system_routines=[],
            global_privileges=[],
            username=f"proxy_{uuid.uuid4().hex[:12]}",
            host_pattern=None,
            datasources={},
            postgres_role="app_read",
        ),
        **changes,
    )


class PostgresRoleValidationTest(unittest.TestCase):
    def test_role_mode_rejects_mysql_self_membership_and_sql_fragments(self):
        for group in (
            make_group(engine="mysql"),
            make_group(username="app_read"),
            make_group(postgres_role='app_read"; SELECT 1'),
            make_group(postgres_role="x" * 64),
            make_group(postgres_role=""),
        ):
            with self.subTest(group=group), self.assertRaises(bootstrap.BootstrapError):
                bootstrap._validate(group, bootstrap.Secret("local-test-password"))


@unittest.skipUnless(
    os.environ.get("POSTGRES_TEST_PORT"),
    "set POSTGRES_TEST_PORT for an isolated PostgreSQL 16 instance",
)
class PostgresRoleIntegrationTest(unittest.TestCase):
    password = "local-bootstrap-test"

    @classmethod
    def connect(cls, username="postgres", password=None):
        return pg8000.dbapi.connect(
            host="127.0.0.1",
            port=int(os.environ["POSTGRES_TEST_PORT"]),
            database="postgres",
            user=username,
            password=password or cls.password,
            ssl_context=False,
        )

    @classmethod
    def setUpClass(cls):
        with cls.connect() as connection:
            cursor = connection.cursor()
            for name in ("app_owner", "app_read", "app_rw", "ungranted_role"):
                cursor.execute(f"CREATE ROLE {name} NOLOGIN")
            for name, attribute in (
                ("bootstrap_master", "CREATEROLE"),
                ("limited_master", "NOCREATEROLE"),
                ("noadmin_master", "CREATEROLE"),
            ):
                cursor.execute(
                    f"CREATE ROLE {name} LOGIN {attribute} PASSWORD '{cls.password}'"
                )
            cursor.execute(
                "GRANT app_read, app_rw, ungranted_role TO bootstrap_master WITH ADMIN TRUE"
            )
            cursor.execute("CREATE SCHEMA inherit_test AUTHORIZATION app_owner")
            cursor.execute("SET ROLE app_owner")
            cursor.execute(
                "CREATE TABLE inherit_test.users (id serial PRIMARY KEY, value text)"
            )
            cursor.execute("INSERT INTO inherit_test.users (value) VALUES ('fixture')")
            cursor.execute(
                "GRANT USAGE ON SCHEMA inherit_test TO app_read, app_rw, ungranted_role"
            )
            cursor.execute(
                "GRANT SELECT ON ALL TABLES IN SCHEMA inherit_test TO app_read"
            )
            cursor.execute(
                "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA inherit_test TO app_rw"
            )
            cursor.execute(
                "GRANT USAGE ON ALL SEQUENCES IN SCHEMA inherit_test TO app_rw"
            )
            cursor.execute(
                "ALTER DEFAULT PRIVILEGES IN SCHEMA inherit_test GRANT SELECT ON TABLES TO app_read"
            )
            cursor.execute(
                "ALTER DEFAULT PRIVILEGES IN SCHEMA inherit_test GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_rw"
            )
            cursor.execute(
                "ALTER DEFAULT PRIVILEGES IN SCHEMA inherit_test GRANT USAGE ON SEQUENCES TO app_rw"
            )
            connection.commit()

    def provision(self, group, master="bootstrap_master", password=None):
        with patch.object(bootstrap, "_tls_context", return_value=False):
            return bootstrap._provision_postgres(
                group,
                "127.0.0.1",
                int(os.environ["POSTGRES_TEST_PORT"]),
                bootstrap.MasterCredential(master, bootstrap.Secret(self.password)),
                bootstrap.Secret(password or self.password),
            )

    def query(self, sql, parameters=()):
        with self.connect() as connection:
            cursor = connection.cursor()
            cursor.execute(sql, parameters)
            return [list(row) for row in cursor.fetchall()]

    def assert_absent(self, group):
        self.assertEqual(
            self.query(
                "SELECT rolname FROM pg_roles WHERE rolname = %s", (group.username,)
            ),
            [],
        )

    def test_read_role_login_and_rotation_preserve_membership_and_object_acls(self):
        group = make_group()
        before = self.query(
            "SELECT relname, relowner, relacl::text FROM pg_class WHERE relnamespace = 'inherit_test'::regnamespace ORDER BY relname"
        )
        self.provision(group)
        with self.connect(group.username) as connection:
            cursor = connection.cursor()
            cursor.execute("SELECT value FROM inherit_test.users")
            self.assertEqual(cursor.fetchone()[0], "fixture")
            with self.assertRaises(pg8000.dbapi.DatabaseError) as failure:
                cursor.execute(
                    "INSERT INTO inherit_test.users (value) VALUES ('denied')"
                )
            self.assertEqual(failure.exception.args[0]["C"], "42501")
        rotated = "local-rotated-test-password"
        self.provision(group, password=rotated)
        with self.connect(group.username, rotated) as connection:
            connection.cursor().execute("SELECT value FROM inherit_test.users")
        with self.assertRaises(pg8000.dbapi.DatabaseError):
            self.connect(group.username)
        self.assertEqual(
            before,
            self.query(
                "SELECT relname, relowner, relacl::text FROM pg_class WHERE relnamespace = 'inherit_test'::regnamespace ORDER BY relname"
            ),
        )
        self.assertEqual(
            self.query(
                "SELECT r.rolname, a.inherit_option, a.set_option, a.admin_option FROM pg_auth_members a JOIN pg_roles r ON r.oid = a.roleid WHERE a.member = (SELECT oid FROM pg_roles WHERE rolname = %s)",
                (group.username,),
            ),
            [["app_read", True, True, False]],
        )

    def test_write_role_uses_sequences_and_future_owner_defaults_without_ddl(self):
        group = make_group(
            postgres_role="app_rw",
            privileges=["SELECT", "INSERT", "UPDATE", "DELETE"],
        )
        self.provision(group)
        with self.connect(group.username) as connection:
            cursor = connection.cursor()
            cursor.execute(
                "INSERT INTO inherit_test.users (value) VALUES ('write') RETURNING id"
            )
            row_id = cursor.fetchone()[0]
            cursor.execute(
                "UPDATE inherit_test.users SET value = 'updated' WHERE id = %s",
                (row_id,),
            )
            cursor.execute(
                "DELETE FROM inherit_test.users WHERE id = %s RETURNING id", (row_id,)
            )
            self.assertEqual(cursor.fetchone()[0], row_id)
            connection.commit()
            with self.assertRaises(pg8000.dbapi.DatabaseError) as failure:
                cursor.execute("CREATE TABLE inherit_test.denied (id int)")
            self.assertEqual(failure.exception.args[0]["C"], "42501")
        with self.connect() as connection:
            cursor = connection.cursor()
            cursor.execute("SET ROLE app_owner")
            cursor.execute(
                "CREATE TABLE inherit_test.future_table (id serial PRIMARY KEY)"
            )
            connection.commit()
        with self.connect(group.username) as connection:
            cursor = connection.cursor()
            cursor.execute(
                "INSERT INTO inherit_test.future_table DEFAULT VALUES RETURNING id"
            )
            self.assertGreater(cursor.fetchone()[0], 0)

    def test_missing_createrole_fails_before_creating_a_login(self):
        group = make_group()
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "master needs CREATEROLE"
        ):
            self.provision(group, master="limited_master")
        self.assert_absent(group)

    def test_missing_admin_option_rolls_back_new_login(self):
        group = make_group()
        with self.assertRaises(pg8000.dbapi.DatabaseError) as failure:
            self.provision(group, master="noadmin_master")
        self.assertEqual(failure.exception.args[0]["C"], "42501")
        self.assert_absent(group)

    def test_missing_role_or_incomplete_access_leaves_no_login(self):
        for role in ("missing_role", "ungranted_role"):
            group = make_group(postgres_role=role)
            with self.subTest(role=role), self.assertRaises(bootstrap.BootstrapError):
                self.provision(group)
            self.assert_absent(group)

    def test_unexpected_membership_is_preserved_and_password_is_not_rotated(self):
        group = make_group()
        with self.connect() as connection:
            cursor = connection.cursor()
            cursor.execute(
                f"CREATE ROLE {group.username} LOGIN PASSWORD '{self.password}'"
            )
            cursor.execute(f"GRANT app_rw TO {group.username}")
            connection.commit()
        with self.assertRaisesRegex(
            bootstrap.BootstrapError, "unexpected role membership"
        ):
            self.provision(group, password="unused-new-password")
        with self.connect(group.username) as connection:
            cursor = connection.cursor()
            cursor.execute("SELECT pg_has_role(CURRENT_USER, 'app_rw', 'USAGE')")
            self.assertTrue(cursor.fetchone()[0])

    def test_inspection_uses_read_only_transaction_and_returns_no_password_columns(
        self,
    ):
        group = make_group()
        master = bootstrap.MasterCredential(
            "limited_master", bootstrap.Secret(self.password)
        )
        with (
            patch.object(bootstrap, "_group", return_value=group),
            patch.object(
                bootstrap,
                "_resolve",
                return_value=(
                    "127.0.0.1",
                    int(os.environ["POSTGRES_TEST_PORT"]),
                    set(),
                    master,
                ),
            ),
            patch.object(bootstrap, "_tls_context", return_value=False),
        ):
            result = bootstrap.handler(
                {"action": "inspect-postgres-roles", "group": "test"}, None
            )
            self.assertEqual(result["current_user"], "limited_master")
            self.assertNotIn("password", str(result).lower())
            with (
                patch.object(
                    bootstrap,
                    "_postgres_role_state",
                    side_effect=lambda cursor: cursor.execute(
                        "CREATE TABLE inherit_test.forbidden (id int)"
                    ),
                ),
                self.assertRaisesRegex(
                    bootstrap.BootstrapError, "read-only transaction"
                ),
            ):
                bootstrap._inspect_postgres_roles({"group": "test"})


if __name__ == "__main__":
    unittest.main()
