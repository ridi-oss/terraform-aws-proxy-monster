import unittest
from dataclasses import replace
from unittest.mock import MagicMock, mock_open, patch

with patch(
    "builtins.open",
    mock_open(read_data='{"secret_prefix": "", "ecs_cluster": "", "groups": {}}'),
):
    import handler as bootstrap

MASTER = bootstrap.MasterCredential("admin", bootstrap.Secret("admin-password"))


def make_group(engine="mysql", **changes):
    return replace(
        bootstrap.Group(
            engine=engine,
            database="app",
            schemas=["app"],
            privileges=["SELECT", "INSERT"],
            system_schemas=[],
            system_routines=[],
            global_privileges=[],
            username="pmproxy_rw",
            host_pattern="10.25.%" if engine == "mysql" else None,
            datasources={"app-rw": "database.invalid"},
            serving=["app-rw"],
        ),
        **changes,
    )


def fake_cursor(user_exists, tables=()):
    cursor = MagicMock()

    def last_sql():
        return cursor.execute.call_args.args[0]

    def fetchone():
        sql = last_sql()
        if "FROM mysql.user" in sql or "FROM pg_roles WHERE rolname" in sql:
            return (1,) if user_exists else None
        return (True,)

    def fetchall():
        sql = last_sql()
        if "information_schema.TABLES" in sql:
            return [(name,) for name in tables]
        return []

    cursor.fetchone.side_effect = fetchone
    cursor.fetchall.side_effect = fetchall
    return cursor


def statements(cursor):
    return [call.args[0] for call in cursor.execute.call_args_list]


class HandlerRotationTest(unittest.TestCase):
    def invoke(self, event, engine="mysql"):
        group = make_group(engine)
        engine_call = MagicMock(
            return_value=([], []) if engine == "mysql" else ["app: SELECT"]
        )
        publish = MagicMock(return_value=["app-rw"])
        restart = MagicMock(return_value=["proxy-app-rw"])
        with (
            patch.dict(bootstrap.CONFIG.groups, {"app": group}),
            patch.object(
                bootstrap,
                "_resolve",
                return_value=("database.invalid", 3306, {"database.invalid"}, MASTER),
            ),
            patch.object(bootstrap, f"_provision_{engine}", engine_call),
            patch.object(bootstrap, "_publish", publish),
            patch.object(bootstrap, "_restart_proxies", restart),
        ):
            result = bootstrap.handler(event, None)
        return result, engine_call.call_args.args[4], publish, restart

    def test_grants_action_neither_publishes_nor_restarts(self):
        for engine in ("mysql", "postgres"):
            with self.subTest(engine=engine):
                result, password, publish, restart = self.invoke(
                    {"action": "grants", "group": "app"}, engine
                )
                self.assertIsNone(password)
                publish.assert_not_called()
                restart.assert_not_called()
                self.assertFalse(result["password_rotated"])
                self.assertEqual(result["secrets_written"], [])
                self.assertEqual(result["services_restarted"], [])

    def test_default_event_still_rotates_publishes_and_restarts(self):
        for event in ({"group": "app"}, {"action": "provision", "group": "app"}):
            with self.subTest(event=event):
                result, password, publish, restart = self.invoke(event)
                self.assertIsInstance(password, bootstrap.Secret)
                publish.assert_called_once()
                self.assertIs(publish.call_args.args[1], password)
                restart.assert_called_once()
                self.assertTrue(result["password_rotated"])
                self.assertEqual(result["secrets_written"], ["app-rw"])
                self.assertEqual(result["services_restarted"], ["proxy-app-rw"])

    def test_misspelled_action_is_rejected(self):
        with self.assertRaisesRegex(bootstrap.BootstrapError, "unknown action"):
            bootstrap.handler({"action": "grant", "group": "app"}, None)


class MysqlGrantsTest(unittest.TestCase):
    def provision(self, password, user_exists=True, tables=()):
        cursor = fake_cursor(user_exists, tables)
        connection = MagicMock()
        connection.__enter__.return_value.cursor.return_value.__enter__.return_value = (
            cursor
        )
        group = make_group(drop_tables=["app.*__deprecated*"])
        with (
            patch.object(bootstrap.pymysql, "connect", return_value=connection),
            patch.object(bootstrap, "_tls_context", return_value=None),
        ):
            result = bootstrap._provision_mysql(
                group, "database.invalid", 3306, MASTER, password
            )
        return statements(cursor), result

    def test_grants_reapply_drop_tables_without_setting_a_password(self):
        sql, (_, skipped) = self.provision(None, tables=["orders__deprecated_1"])
        self.assertFalse([s for s in sql if "IDENTIFIED BY" in s])
        self.assertFalse([s for s in sql if s.startswith("CREATE USER")])
        self.assertIn(
            "GRANT DROP ON `app`.`orders__deprecated_1` TO 'pmproxy_rw'@'10.25.%'", sql
        )
        self.assertEqual(skipped, [])

    def test_grants_fail_when_the_user_does_not_exist(self):
        cursor = fake_cursor(user_exists=False)
        connection = MagicMock()
        connection.__enter__.return_value.cursor.return_value.__enter__.return_value = (
            cursor
        )
        with (
            patch.object(bootstrap.pymysql, "connect", return_value=connection),
            patch.object(bootstrap, "_tls_context", return_value=None),
            self.assertRaisesRegex(bootstrap.BootstrapError, "does not exist"),
        ):
            bootstrap._provision_mysql(
                make_group(), "database.invalid", 3306, MASTER, None
            )
        self.assertFalse(
            [
                s
                for s in statements(cursor)
                if s.startswith(("CREATE", "GRANT", "REVOKE"))
            ]
        )

    def test_rotation_still_creates_and_sets_the_password(self):
        sql, _ = self.provision(bootstrap.Secret("test-password"), user_exists=False)
        self.assertTrue([s for s in sql if s.startswith("CREATE USER IF NOT EXISTS")])
        self.assertTrue([s for s in sql if s.startswith("ALTER USER")])


class PostgresGrantsTest(unittest.TestCase):
    def provision(self, group, password, user_exists=True):
        cursor = fake_cursor(user_exists)
        connection = MagicMock()
        connection.__enter__.return_value.cursor.return_value = cursor
        with (
            patch.object(bootstrap.pg8000.dbapi, "connect", return_value=connection),
            patch.object(bootstrap, "_tls_context", return_value=None),
            patch.object(
                bootstrap, "_check_postgres_inheritance", return_value=user_exists
            ),
            patch.object(bootstrap, "_verify_postgres_inherited_access"),
        ):
            try:
                bootstrap._provision_postgres(
                    group, "database.invalid", 5432, MASTER, password
                )
            finally:
                self.committed = connection.__enter__.return_value.commit.called
        return statements(cursor)

    def groups(self):
        return {
            "direct": make_group("postgres"),
            "inherited": make_group("postgres", postgres_role="app_read"),
        }

    def test_grants_alter_no_password(self):
        for name, group in self.groups().items():
            with self.subTest(path=name):
                sql = self.provision(group, None)
                alters = [s for s in sql if s.startswith("ALTER ROLE")]
                self.assertTrue(alters)
                self.assertFalse([s for s in alters if "PASSWORD" in s])
                self.assertFalse([s for s in sql if s.startswith("CREATE ROLE")])
                self.assertTrue(self.committed)

    def test_grants_fail_when_the_role_does_not_exist(self):
        for name, group in self.groups().items():
            with (
                self.subTest(path=name),
                self.assertRaisesRegex(bootstrap.BootstrapError, "does not exist"),
            ):
                self.provision(group, None, user_exists=False)
            self.assertFalse(self.committed)

    def test_rotation_still_sets_a_scram_password(self):
        for name, group in self.groups().items():
            with self.subTest(path=name):
                sql = self.provision(group, bootstrap.Secret("test-password"))
                self.assertTrue(
                    [
                        s
                        for s in sql
                        if s.startswith("ALTER ROLE") and "SCRAM-SHA-256$" in s
                    ]
                )


if __name__ == "__main__":
    unittest.main()
