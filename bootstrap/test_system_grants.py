import unittest
from unittest.mock import MagicMock, mock_open, patch

with patch(
    "builtins.open",
    mock_open(read_data='{"secret_prefix": "", "ecs_cluster": "", "groups": {}}'),
):
    import handler as bootstrap


def make_group(engine="mysql", system_schemas=None, drop_tables=()):
    return bootstrap.Group(
        engine=engine,
        database="app",
        schemas=["app"],
        privileges=["SELECT", "INSERT", "CREATE", "GRANT OPTION"],
        system_schemas=["mysql"] if system_schemas is None else system_schemas,
        system_routines=[],
        global_privileges=[],
        username="pmproxy_rw",
        host_pattern="10.25.%",
        datasources={},
        drop_tables=list(drop_tables),
    )


class SystemGrantsTest(unittest.TestCase):
    def test_mysql_catalog_is_allowed_for_show_grants(self):
        bootstrap._validate(make_group(), bootstrap.Secret("test-password"))

    def test_unknown_system_schema_is_rejected(self):
        for schema in ["application", "mysql.*", "mysql; DROP USER other"]:
            with (
                self.subTest(schema=schema),
                self.assertRaisesRegex(bootstrap.BootstrapError, "system schema"),
            ):
                bootstrap._validate(
                    make_group(system_schemas=[schema]),
                    bootstrap.Secret("test-password"),
                )

    def test_drop_table_outside_group_schemas_is_rejected(self):
        for table in ["other.t", "app", "app.t; DROP USER other"]:
            with (
                self.subTest(table=table),
                self.assertRaisesRegex(bootstrap.BootstrapError, "drop table"),
            ):
                bootstrap._validate(
                    make_group(drop_tables=[table]), bootstrap.Secret("test-password")
                )

    def test_postgres_rejects_mysql_catalog(self):
        with self.assertRaisesRegex(bootstrap.BootstrapError, "MySQL-only"):
            bootstrap._validate(
                make_group(engine="postgres"), bootstrap.Secret("test-password")
            )

    def test_postgres_without_mysql_privileges_remains_valid(self):
        bootstrap._validate(
            make_group(engine="postgres", system_schemas=[]),
            bootstrap.Secret("test-password"),
        )

    def provision_statements(self, group, tables=()):
        return self.provision(group, tables)[0]

    def provision(self, group, tables=()):
        cursor = MagicMock()

        def fetchall():
            sql, *args = cursor.execute.call_args.args
            if "information_schema.TABLES" not in sql:
                return []
            schema, _ = args[0]
            return [
                (name,)
                for table in tables
                for table_schema, _, name in [table.partition(".")]
                if table_schema == schema
            ]

        cursor.fetchall.side_effect = fetchall
        connection = MagicMock()
        connection.__enter__.return_value.cursor.return_value.__enter__.return_value = (
            cursor
        )
        with (
            patch.object(bootstrap.pymysql, "connect", return_value=connection),
            patch.object(bootstrap, "_tls_context", return_value=None),
        ):
            _, skipped = bootstrap._provision_mysql(
                group,
                "database.invalid",
                3306,
                bootstrap.MasterCredential("admin", bootstrap.Secret("admin-password")),
                bootstrap.Secret("test-password"),
            )
        return [call.args[0] for call in cursor.execute.call_args_list], skipped

    def test_mysql_catalog_receives_select_without_application_writes_or_grant_option(
        self,
    ):
        group = make_group()
        group.global_privileges.append("PROCESS")
        statements = self.provision_statements(group)
        catalog_grants = [
            sql
            for sql in statements
            if sql.startswith("GRANT ") and "ON `mysql`." in sql
        ]
        self.assertEqual(
            catalog_grants,
            ["GRANT SELECT ON `mysql`.* TO 'pmproxy_rw'@'10.25.%'"],
        )
        self.assertIn(
            "GRANT SELECT, INSERT, CREATE, GRANT OPTION ON `app`.* TO 'pmproxy_rw'@'10.25.%'",
            statements,
        )
        self.assertIn("GRANT PROCESS ON *.* TO 'pmproxy_rw'@'10.25.%'", statements)

    def test_catalog_read_is_opt_in_and_routine_execute_remains_scoped(self):
        group = make_group(system_schemas=[])
        group.system_routines.append("mysql.rds_kill")
        statements = self.provision_statements(group)
        self.assertNotIn(
            "GRANT SELECT ON `mysql`.* TO 'pmproxy_rw'@'10.25.%'", statements
        )
        self.assertIn(
            "GRANT EXECUTE ON PROCEDURE `mysql`.`rds_kill` TO 'pmproxy_rw'@'10.25.%'",
            statements,
        )

    def test_drop_is_granted_per_table_and_never_schema_wide(self):
        statements = self.provision_statements(
            make_group(system_schemas=[], drop_tables=["app.t"]), tables=["app.t"]
        )
        self.assertIn("GRANT DROP ON `app`.`t` TO 'pmproxy_rw'@'10.25.%'", statements)
        self.assertFalse(
            [sql for sql in statements if "DROP" in sql and "ON `app`.*" in sql]
        )

    def test_missing_drop_table_is_skipped_not_fatal(self):
        statements, skipped = self.provision(
            make_group(system_schemas=[], drop_tables=["app.gone", "app.kept"]),
            tables=["app.kept"],
        )
        self.assertEqual(skipped, ["app.gone"])
        self.assertIn(
            "GRANT DROP ON `app`.`kept` TO 'pmproxy_rw'@'10.25.%'", statements
        )
        self.assertFalse([sql for sql in statements if "`gone`" in sql])

    def test_drop_pattern_expands_to_existing_tables_only(self):
        statements, skipped = self.provision(
            make_group(system_schemas=[], drop_tables=["app.*_dropme_20260929"]),
            tables=["app.a_dropme_20260929", "app.b_dropme_20260929", "app.live"],
        )
        drops = [sql for sql in statements if sql.startswith("GRANT DROP")]
        self.assertEqual(
            drops,
            [
                "GRANT DROP ON `app`.`a_dropme_20260929` TO 'pmproxy_rw'@'10.25.%'",
                "GRANT DROP ON `app`.`b_dropme_20260929` TO 'pmproxy_rw'@'10.25.%'",
            ],
        )
        self.assertEqual(skipped, [])

    def test_drop_pattern_escapes_underscore_independent_of_sql_mode(self):
        self.assertEqual(
            bootstrap._resolve_drop_tables(
                cursor := MagicMock(fetchall=MagicMock(return_value=[])),
                make_group(drop_tables=["app.t_x*"]),
            ),
            ([], ["app.t_x*"]),
        )
        sql, args = cursor.execute.call_args.args
        self.assertIn("LIKE %s ESCAPE '!'", sql)
        self.assertEqual(args, ("app", "t!_x%"))

    def test_drop_pattern_is_rechecked_when_the_server_over_matches(self):
        statements, _ = self.provision(
            make_group(system_schemas=[], drop_tables=["app.t_x*"]),
            tables=["app.t_x1", "app.tax1", "app.T_X1"],
        )
        drops = [sql for sql in statements if sql.startswith("GRANT DROP")]
        self.assertEqual(
            drops, ["GRANT DROP ON `app`.`t_x1` TO 'pmproxy_rw'@'10.25.%'"]
        )

    def test_drop_pattern_never_grants_a_catalog_name_outside_bare_identifiers(self):
        statements, skipped = self.provision(
            make_group(system_schemas=[], drop_tables=["app.t*"]),
            tables=["app.t`; DROP USER x; --"],
        )
        self.assertFalse([sql for sql in statements if sql.startswith("GRANT DROP")])
        self.assertEqual(skipped, ["app.t*"])

    def test_bare_star_drop_pattern_is_rejected(self):
        for table in ["app.*", "app.**"]:
            with (
                self.subTest(table=table),
                self.assertRaisesRegex(bootstrap.BootstrapError, "drop table"),
            ):
                bootstrap._validate(
                    make_group(drop_tables=[table]), bootstrap.Secret("test-password")
                )

    def test_drop_tables_resolve_before_password_change(self):
        statements = self.provision_statements(
            make_group(system_schemas=[], drop_tables=["app.t"]), tables=["app.t"]
        )
        resolve = next(
            i for i, sql in enumerate(statements) if "information_schema.TABLES" in sql
        )
        alter = next(
            i for i, sql in enumerate(statements) if sql.startswith("ALTER USER")
        )
        self.assertLess(resolve, alter)


if __name__ == "__main__":
    unittest.main()
