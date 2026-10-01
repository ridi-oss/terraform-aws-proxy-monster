"""Provision the proxy-monster backend account on one RDS target and publish its credential.

The same master connection also answers a read-only action reporting the accounts a target holds,
which no path through the proxy can: the shipped system.critical-guard policy forbids mysql.user.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import ssl
from dataclasses import dataclass, field
from typing import Any, Never

import boto3
import pg8000.dbapi
import pymysql

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

RDS_CA_BUNDLE = os.path.join(os.path.dirname(__file__), "rds-global-bundle.pem")
# Written into the deployment package by build.sh: the group set outgrew what
# UpdateFunctionConfiguration accepts in an environment variable.
BOOTSTRAP_CONFIG = os.path.join(os.path.dirname(__file__), "bootstrap-config.json")

BARE_IDENTIFIER = re.compile(r"\A[A-Za-z0-9_]{1,64}\Z")
# The leading octet is required so the pattern cannot be a bare "%".
HOST_PATTERN = re.compile(r"\A[0-9]{1,3}\.[0-9.%_]{1,28}\Z")
# A quote-free, backslash-free alphabet keeps SASLprep a no-op and _scrub an exact match.
PASSWORD_ALPHABET = re.compile(r"\A[A-Za-z0-9_-]+\Z")
# Coarse on purpose: the Terraform validation holds the per-engine allowlist.
PRIVILEGE_KEYWORD = re.compile(r"\A[A-Z]+( [A-Z]+){0,2}\Z")
GLOBAL_PRIVILEGES = frozenset({"CREATE USER", "PROCESS", "REPLICATION CLIENT"})
SYSTEM_SCHEMAS = frozenset({"mysql", "performance_schema", "sys"})
SYSTEM_ROUTINES = frozenset({"mysql.rds_kill", "mysql.rds_kill_query"})
DROP_TABLE = re.compile(
    r"\A[A-Za-z0-9_]{1,64}\.(?=[A-Za-z0-9_*]*[A-Za-z0-9_])[A-Za-z0-9_*]{1,64}\Z"
)

# Columns are named, never *: these relations also hold authentication_string and rolpassword.
MYSQL_USERS_SQL = "SELECT User, Host FROM mysql.user ORDER BY User, Host"
POSTGRES_USERS_SQL = (
    "SELECT rolname FROM pg_catalog.pg_roles WHERE rolcanlogin ORDER BY rolname"
)
# Every role a schema-wide GRANT has to speak for: the schema's own owner, plus the owner of each
# relation ON ALL TABLES expands to (tables, views, matviews, foreign and partitioned tables).
POSTGRES_SCHEMA_OWNERS_SQL = (
    "SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = %s"
    " UNION"
    " SELECT pg_get_userbyid(c.relowner) FROM pg_class c"
    " JOIN pg_namespace n ON n.oid = c.relnamespace"
    " WHERE n.nspname = %s AND c.relkind IN ('r', 'v', 'm', 'f', 'p')"
)

# Sequence owners, needed only by a group that also grants ON ALL SEQUENCES: that GRANT is checked
# per sequence against the sequence's own owner, exactly as the table grant is.
POSTGRES_SEQUENCE_OWNERS_SQL = (
    "SELECT pg_get_userbyid(c.relowner) FROM pg_class c"
    " JOIN pg_namespace n ON n.oid = c.relnamespace"
    " WHERE n.nspname = %s AND c.relkind = 'S'"
)

# Table privileges that imply the group also needs USAGE on the schema's sequences.
POSTGRES_SEQUENCE_WRITERS = frozenset({"INSERT", "UPDATE"})

# Whether the master already holds a membership in a role directly, whatever that membership
# inherits. pg_has_role reads the inherited privilege, which is the narrower question.
POSTGRES_DIRECT_MEMBERSHIP_SQL = (
    "SELECT 1 FROM pg_auth_members"
    " WHERE roleid = (SELECT oid FROM pg_roles WHERE rolname = %s)"
    " AND member = (SELECT oid FROM pg_roles WHERE rolname = CURRENT_USER)"
)


class BootstrapError(Exception):
    """Raised with a message already scrubbed of credential material."""


class Secret:
    """Opaque password box: the value moves only through reveal()."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "Secret(***)"

    def __str__(self) -> Never:
        raise TypeError("secret cannot be interpolated; use reveal()")


@dataclass(frozen=True, slots=True)
class Group:
    engine: str
    database: str
    schemas: list[str]
    privileges: list[str]
    system_schemas: list[str]
    system_routines: list[str]
    global_privileges: list[str]
    username: str
    host_pattern: str | None
    datasources: dict[str, str]
    reader_role_arn: str | None = None
    rds_kind: str | None = None
    rds_identifier: str | None = None
    external_host: str | None = None
    external_port: int | None = None
    master_secret_name: str | None = None
    external_ca_pem: str | None = None
    external_ca_strict_extensions: bool = True
    drop_tables: list[str] = field(default_factory=list)
    postgres_role: str | None = None

    @property
    def external(self) -> bool:
        return self.external_host is not None

    @property
    def label(self) -> str:
        """What to name the target in errors and logs, whichever way it is backed."""
        return self.rds_identifier or f"{self.external_host}:{self.external_port}"


@dataclass(frozen=True, slots=True)
class Config:
    secret_prefix: str
    ecs_cluster: str
    groups: dict[str, Group]


@dataclass(frozen=True, slots=True)
class MasterCredential:
    username: str
    password: Secret


with open(BOOTSTRAP_CONFIG, encoding="utf-8") as _config_file:
    _raw: dict[str, Any] = json.load(_config_file)
CONFIG = Config(
    secret_prefix=_raw["secret_prefix"],
    ecs_cluster=_raw["ecs_cluster"],
    groups={name: Group(**g) for name, g in _raw["groups"].items()},
)


def handler(event: dict[str, Any] | None, _context: object) -> dict[str, Any]:
    event = event or {}
    # Absent means provision, so {"group": name} keeps its meaning; a misspelled one must not
    # reach it, since provisioning rotates the password and redeploys the proxies.
    match event.get("action", "provision"):
        case "provision":
            return _provision(event)
        case "list-users":
            return _list_users(event)
        case "inspect-postgres-roles":
            return _inspect_postgres_roles(event)
        case action:
            raise BootstrapError(
                f"unknown action {action!r}; expected 'provision', 'list-users',"
                " or 'inspect-postgres-roles'"
            )


def _provision(event: dict[str, Any]) -> dict[str, Any]:
    group_name = event.get("group", "")
    group = _group(group_name)

    LOGGER.info("bootstrapping group %s (%s)", group_name, group.label)
    password = Secret(secrets.token_urlsafe(32))
    _validate(group, password)

    endpoint, port, allowed_hosts, master = _resolve(group)
    _check_datasource_hosts(group, allowed_hosts)

    try:
        match group.engine:
            case "mysql":
                grants, drop_tables_skipped = _provision_mysql(
                    group, endpoint, port, master, password
                )
            case "postgres":
                grants = _provision_postgres(group, endpoint, port, master, password)
                drop_tables_skipped = []
            case engine:
                raise BootstrapError(f"unknown engine {engine!r}")
    except Exception as exc:  # noqa: BLE001
        raise BootstrapError(
            _scrub(
                f"{type(exc).__name__}: {exc}",
                (master.password.reveal(), password.reveal()),
            )
        ) from None

    written = _publish(group, password)
    restarted = _restart_proxies(group)

    return {
        "group": group_name,
        "target": group.label,
        # Kept beside target, null off RDS, so a consumer reading the older key still resolves.
        "rds_identifier": group.rds_identifier,
        "engine": group.engine,
        "endpoint": endpoint,
        "username": group.username,
        "secrets_written": written,
        "services_restarted": restarted,
        "grants": grants,
        "drop_tables_skipped": drop_tables_skipped,
    }


def _group(group_name: str) -> Group:
    group = CONFIG.groups.get(group_name)
    if group is None:
        raise BootstrapError(
            f"unknown group {group_name!r}; declared groups: {sorted(CONFIG.groups)}"
        )
    return group


def _list_users(event: dict[str, Any]) -> dict[str, Any]:
    """Report the accounts a target DB holds. Writes nothing: no CREATE USER, GRANT, or redeploy."""
    group_name = event.get("group", "")
    if group_name:
        _group(group_name)
        names = [group_name]
    else:
        names = _representative_groups()
    return {"action": "list-users", "targets": [_target_users(name) for name in names]}


def _representative_groups() -> list[str]:
    """One group per distinct target, so a fleet sweep reads each DB once.

    Keyed on the reader role too, not just the identifier: one identifier can name a cluster in both
    a dev and a prod account.
    """
    seen: dict[tuple[str | None, str | None, str | None], str] = {}
    for name in sorted(CONFIG.groups):
        group = CONFIG.groups[name]
        seen.setdefault(
            (group.reader_role_arn, group.rds_kind, group.rds_identifier)
            if group.external_host is None
            else (None, None, group.label),
            name,
        )
    return list(seen.values())


def _target_users(group_name: str) -> dict[str, Any]:
    """One target's accounts, or its own error: a sweep outlives one unreachable DB."""
    group = CONFIG.groups[group_name]
    entry: dict[str, Any] = {
        "group": group_name,
        "target": group.label,
        "rds_identifier": group.rds_identifier,
        "engine": group.engine,
    }
    master: MasterCredential | None = None
    try:
        endpoint, port, _hosts, master = _resolve(group)
        users = _read_users(group, endpoint, port, master)
    except Exception as exc:  # noqa: BLE001
        entry["error"] = _scrub(
            f"{type(exc).__name__}: {exc}",
            (master.password.reveal(),) if master else (),
        )
        return entry

    # The count, never the rows: this log group keeps 365 days.
    LOGGER.info("listed %d accounts on %s (%s)", len(users), group_name, group.label)
    return entry | {"endpoint": endpoint, "count": len(users), "users": users}


def _read_users(
    group: Group, endpoint: str, port: int, master: MasterCredential
) -> list[dict[str, str | None]]:
    match group.engine:
        case "mysql":
            with (
                pymysql.connect(
                    host=endpoint,
                    port=port,
                    user=master.username,
                    password=master.password.reveal(),
                    database=group.database,
                    ssl=_tls_context(group),
                    connect_timeout=15,
                    # Bounded so a stalled target costs one entry's error, not the whole sweep:
                    # six targets stay under the function's 300s even at both limits.
                    read_timeout=15,
                ) as connection,
                connection.cursor() as cursor,
            ):
                cursor.execute(MYSQL_USERS_SQL)
                return [{"user": row[0], "host": row[1]} for row in cursor.fetchall()]
        case "postgres":
            with pg8000.dbapi.connect(
                host=endpoint,
                port=port,
                user=master.username,
                password=master.password.reveal(),
                database=group.database,
                ssl_context=_tls_context(group),
                timeout=15,
            ) as connection:
                cursor = connection.cursor()
                cursor.execute(POSTGRES_USERS_SQL)
                return [{"user": row[0], "host": None} for row in cursor.fetchall()]
        case engine:
            raise BootstrapError(f"unknown engine {engine!r}")


def _validate(group: Group, password: Secret) -> None:
    if group.postgres_role is not None and (
        group.engine != "postgres"
        or not re.fullmatch(r"[A-Za-z0-9_]{1,63}", group.postgres_role)
        or group.postgres_role == group.username
    ):
        raise BootstrapError("postgres_role must name a distinct PostgreSQL role")
    for name in ("database", "username"):
        if not BARE_IDENTIFIER.match(getattr(group, name)):
            raise BootstrapError(f"group {name} is not a bare identifier")
    if not group.schemas:
        raise BootstrapError("group names no schema, which would grant nothing")
    for schema in group.schemas:
        if not BARE_IDENTIFIER.match(schema):
            raise BootstrapError("group schema is not a bare identifier")
    if not group.privileges:
        raise BootstrapError("group names no privilege, which would grant nothing")
    for privilege in group.privileges:
        if not PRIVILEGE_KEYWORD.match(privilege):
            raise BootstrapError("group privilege is not a bare keyword")
    for schema in group.system_schemas:
        if schema not in SYSTEM_SCHEMAS:
            raise BootstrapError("group system schema is not a grantable system schema")
    for routine in group.system_routines:
        if routine not in SYSTEM_ROUTINES:
            raise BootstrapError("group system routine is not grantable")
    for privilege in group.global_privileges:
        if privilege not in GLOBAL_PRIVILEGES:
            raise BootstrapError("group global privilege is not grantable ON *.*")
    for table in group.drop_tables:
        if not DROP_TABLE.match(table) or table.partition(".")[0] not in group.schemas:
            raise BootstrapError(
                "group drop table is not schema.table within the group's schemas"
            )
    if group.engine != "mysql" and (
        group.system_schemas
        or group.system_routines
        or group.global_privileges
        or group.drop_tables
    ):
        raise BootstrapError(
            "system_schemas, system_routines, global_privileges and drop_tables are"
            " MySQL-only: PostgreSQL's catalogs need no grant and DROP is not grantable"
        )
    if group.engine == "mysql" and not HOST_PATTERN.match(group.host_pattern or ""):
        raise BootstrapError("host_pattern is not an address pattern")
    if not PASSWORD_ALPHABET.match(password.reveal()):
        raise BootstrapError("generated password left the expected alphabet")


def _resolve(group: Group) -> tuple[str, int, set[str], MasterCredential]:
    """Endpoint, port, every host the target answers on, and the master credential.

    An external target has no API to ask, so the configured endpoint is the only one it answers on.
    """
    if group.external_host is not None:
        if group.external_port is None or group.master_secret_name is None:
            raise BootstrapError(
                f"external group {group.label} is missing a port or master secret"
            )
        master = _master_credential(boto3.Session(), group.master_secret_name)
        return group.external_host, group.external_port, {group.external_host}, master

    session = _assume(group)
    endpoint, port, hosts, master_secret_arn = _describe(session, group)
    return endpoint, port, hosts, _master_credential(session, master_secret_arn)


def _assume(group: Group) -> Any:
    if group.reader_role_arn is None:
        raise BootstrapError(f"group {group.label} has no reader role to assume")
    assumed = boto3.client("sts").assume_role(
        RoleArn=group.reader_role_arn, RoleSessionName="proxy-monster-bootstrap"
    )["Credentials"]
    return boto3.Session(
        aws_access_key_id=assumed["AccessKeyId"],
        aws_secret_access_key=assumed["SecretAccessKey"],
        aws_session_token=assumed["SessionToken"],
    )


def _describe(session: Any, group: Group) -> tuple[str, int, set[str], str]:
    """Writer endpoint, port, every endpoint the target answers on, and the master secret ARN."""
    rds = session.client("rds")

    if group.rds_kind == "cluster":
        cluster = rds.describe_db_clusters(DBClusterIdentifier=group.rds_identifier)[
            "DBClusters"
        ][0]
        _require_active_secret(cluster, group)
        hosts = {cluster["Endpoint"], cluster["ReaderEndpoint"]}
        members = [
            m["DBInstanceIdentifier"] for m in cluster.get("DBClusterMembers", [])
        ]
        for member in members:
            instance = rds.describe_db_instances(DBInstanceIdentifier=member)[
                "DBInstances"
            ][0]
            hosts.add(instance["Endpoint"]["Address"])
        return (
            cluster["Endpoint"],
            cluster["Port"],
            hosts,
            cluster["MasterUserSecret"]["SecretArn"],
        )

    instance = rds.describe_db_instances(DBInstanceIdentifier=group.rds_identifier)[
        "DBInstances"
    ][0]
    _require_active_secret(instance, group)
    return (
        instance["Endpoint"]["Address"],
        instance["Endpoint"]["Port"],
        {instance["Endpoint"]["Address"]},
        instance["MasterUserSecret"]["SecretArn"],
    )


def _require_active_secret(target: dict[str, Any], group: Group) -> None:
    secret = target.get("MasterUserSecret")
    if not secret:
        raise BootstrapError(
            f"{group.rds_identifier} does not have managed master credentials enabled"
        )
    if secret.get("SecretStatus") != "active":
        raise BootstrapError(
            f"{group.rds_identifier} master secret is {secret.get('SecretStatus')!r}, not 'active'"
        )


def _check_datasource_hosts(group: Group, allowed_hosts: set[str]) -> None:
    stray = {
        key: host
        for key, host in group.datasources.items()
        if host not in allowed_hosts
    }
    if stray:
        raise BootstrapError(
            f"datasources {sorted(stray)} do not point at {group.label}"
        )


def _master_credential(session: Any, secret_id: str) -> MasterCredential:
    """secret_id is an ARN for an RDS-managed secret and a name for a hand-filled one."""
    payload = json.loads(
        session.client("secretsmanager").get_secret_value(SecretId=secret_id)[
            "SecretString"
        ]
    )
    return MasterCredential(
        username=payload["username"],
        password=Secret(payload["password"]),
    )


def _escape_db_pattern(schema: str) -> str:
    """Escape a GRANT database part: _ and % are wildcards there, unsuppressed by backticks."""
    return schema.replace("\\", "\\\\").replace("_", r"\_").replace("%", r"\%")


def _tls_context(group: Group) -> ssl.SSLContext:
    """Verified TLS against the bundled RDS CA, or an external target's own CA; client-side only.

    Hostname checking is off for the latter: Cloud SQL names the instance `project:instance` in its
    certificate, which no address the function can dial will ever match. The chain is still verified.

    VERIFY_X509_STRICT is dropped only where a group asks for it: a Cloud SQL per-instance CA carries
    no Subject Key Identifier, so its leaf carries no Authority Key Identifier and strict rejects the
    handshake. The chain is still verified against the pinned CA.
    """
    if group.external_ca_pem is None:
        return ssl.create_default_context(cafile=RDS_CA_BUNDLE)

    context = ssl.create_default_context(cadata=group.external_ca_pem)
    context.check_hostname = False
    if not group.external_ca_strict_extensions:
        context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    return context


def _provision_mysql(
    group: Group,
    endpoint: str,
    port: int,
    master: MasterCredential,
    password: Secret,
) -> tuple[list[str], list[str]]:
    user = f"'{group.username}'@'{group.host_pattern}'"
    # PyMySQL interpolates client-side: double a literal % only in statements that carry args.
    user_escaped = user.replace("%", "%%")
    privileges = ", ".join(group.privileges)

    with (
        pymysql.connect(
            host=endpoint,
            port=port,
            user=master.username,
            password=master.password.reveal(),
            database=group.database,
            ssl=_tls_context(group),
            connect_timeout=15,
            autocommit=True,
        ) as connection,
        connection.cursor() as cursor,
    ):
        drop_tables, drop_tables_skipped = _resolve_drop_tables(cursor, group)
        cursor.execute(
            f"CREATE USER IF NOT EXISTS {user_escaped} IDENTIFIED BY %s",
            (password.reveal(),),
        )
        cursor.execute(
            f"ALTER USER {user_escaped} IDENTIFIED BY %s", (password.reveal(),)
        )
        cursor.execute(f"REVOKE ALL PRIVILEGES, GRANT OPTION FROM {user}")
        for schema in group.schemas:
            cursor.execute(
                f"GRANT {privileges} ON `{_escape_db_pattern(schema)}`.* TO {user}"
            )
        for schema in group.system_schemas:
            cursor.execute(
                f"GRANT SELECT ON `{_escape_db_pattern(schema)}`.* TO {user}"
            )
        for routine in group.system_routines:
            schema, _, name = routine.partition(".")
            cursor.execute(f"GRANT EXECUTE ON PROCEDURE `{schema}`.`{name}` TO {user}")
        # Table-level grant names are literal, so no wildcard escaping.
        for schema, name in drop_tables:
            cursor.execute(f"GRANT DROP ON `{schema}`.`{name}` TO {user}")
        # The sole unscoped grant, because MySQL has no schema-level form of these.
        if group.global_privileges:
            cursor.execute(
                f"GRANT {', '.join(group.global_privileges)} ON *.* TO {user}"
            )
        # Not SHOW GRANTS: MariaDB still emits "IDENTIFIED VIA ... USING '*<hash>'" there.
        cursor.execute(
            "SELECT PRIVILEGE_TYPE, TABLE_SCHEMA, IS_GRANTABLE"
            " FROM information_schema.SCHEMA_PRIVILEGES"
            " WHERE GRANTEE = %s ORDER BY TABLE_SCHEMA, PRIVILEGE_TYPE",
            (user,),
        )
        schema_rows = cursor.fetchall()
        grants = [f"{row[0]} ON {row[1]}" for row in schema_rows]
        # The view carries no GRANT OPTION row: grantability rides on every other row instead.
        grants += [
            f"GRANT OPTION ON {schema}"
            for schema in sorted({row[1] for row in schema_rows if row[2] == "YES"})
        ]
        cursor.execute(
            "SELECT PRIVILEGE_TYPE, TABLE_SCHEMA, TABLE_NAME"
            " FROM information_schema.TABLE_PRIVILEGES"
            " WHERE GRANTEE = %s ORDER BY TABLE_SCHEMA, TABLE_NAME, PRIVILEGE_TYPE",
            (user,),
        )
        grants += [f"{row[0]} ON {row[1]}.{row[2]}" for row in cursor.fetchall()]
        cursor.execute(
            "SELECT PRIVILEGE_TYPE FROM information_schema.USER_PRIVILEGES"
            " WHERE GRANTEE = %s AND PRIVILEGE_TYPE <> 'USAGE' ORDER BY PRIVILEGE_TYPE",
            (user,),
        )
        grants += [f"{row[0]} ON *.*" for row in cursor.fetchall()]
        return grants, drop_tables_skipped


def _resolve_drop_tables(
    cursor: Any, group: Group
) -> tuple[list[tuple[str, str]], list[str]]:
    """Expand drop_tables to the base tables that exist now, before any password change."""
    resolved: set[tuple[str, str]] = set()
    skipped = []
    for entry in group.drop_tables:
        schema, _, name = entry.partition(".")
        glob = re.compile(".*".join(map(re.escape, name.split("*"))))
        cursor.execute(
            "SELECT TABLE_NAME FROM information_schema.TABLES"
            " WHERE TABLE_SCHEMA = %s AND TABLE_NAME LIKE %s ESCAPE '!'"
            " AND TABLE_TYPE = 'BASE TABLE'",
            (schema, name.replace("_", "!_").replace("*", "%")),
        )
        matches = [
            (schema, row[0])
            for row in cursor.fetchall()
            if BARE_IDENTIFIER.match(row[0]) and glob.fullmatch(row[0])
        ]
        if not matches:
            LOGGER.warning("drop table %s matches no base table; skipped", entry)
            skipped.append(entry)
        resolved.update(matches)
    return sorted(resolved), skipped


def _scram_verifier(password: Secret) -> str:
    """Build what ALTER ROLE stores, so the password itself never reaches the server log."""
    iterations = 4096
    salt = secrets.token_bytes(16)
    salted = hashlib.pbkdf2_hmac("sha256", password.reveal().encode(), salt, iterations)
    stored_key = hashlib.sha256(
        hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    )
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256)
    return (
        f"SCRAM-SHA-256${iterations}:{base64.b64encode(salt).decode()}"
        f"${base64.b64encode(stored_key.digest()).decode()}"
        f":{base64.b64encode(server_key.digest()).decode()}"
    )


def _provision_postgres(
    group: Group,
    endpoint: str,
    port: int,
    master: MasterCredential,
    password: Secret,
) -> list[str]:
    if group.postgres_role is not None:
        return _provision_postgres_inherited(group, endpoint, port, master, password)
    username = group.username
    privileges = ", ".join(group.privileges)
    # Inserting into a serial column calls nextval, which needs USAGE on the sequence: the table
    # grant alone leaves the insert failing on "permission denied for sequence". An identity column
    # needs nothing extra, and which of the two a table uses is not visible from here.
    grant_sequences = bool(POSTGRES_SEQUENCE_WRITERS.intersection(group.privileges))

    with pg8000.dbapi.connect(
        host=endpoint,
        port=port,
        user=master.username,
        password=master.password.reveal(),
        database=group.database,
        ssl_context=_tls_context(group),
        timeout=15,
    ) as connection:
        # One transaction, not autocommit: this borrows the owner roles it grants through, and a
        # timeout or a lost connection partway would otherwise leave the master holding them.
        # PostgreSQL runs all of this transactionally and a membership is visible to the statements
        # that follow it, so nothing here needs its own commit.
        cursor = connection.cursor()
        try:
            cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (username,))
            if cursor.fetchone() is None:
                cursor.execute(f'CREATE ROLE "{username}" LOGIN')
            # SUPERUSER, REPLICATION, and BYPASSRLS need real superuser even to write the NO- form.
            cursor.execute(
                f'ALTER ROLE "{username}" WITH LOGIN NOCREATEDB NOCREATEROLE'
                f" PASSWORD '{_scram_verifier(password)}'"
            )
            cursor.execute(
                "SELECT pg_get_userbyid(roleid) FROM pg_auth_members"
                " WHERE member = (SELECT oid FROM pg_roles WHERE rolname = %s)",
                (username,),
            )
            for (member_of,) in cursor.fetchall():
                cursor.execute(f'REVOKE {_quote_ident(member_of)} FROM "{username}"')
            cursor.execute(
                f'GRANT CONNECT ON DATABASE "{group.database}" TO "{username}"'
            )
            for schema in group.schemas:
                cursor.execute(f'GRANT USAGE ON SCHEMA "{schema}" TO "{username}"')
                table_owners = _schema_owners(cursor, schema) - {master.username}
                # Kept apart from the table owners: a role owning only a sequence today must not
                # collect a default privilege on the tables it creates later.
                sequence_owners = (
                    _sequence_owners(cursor, schema) - {master.username}
                    if grant_sequences
                    else set()
                )
                borrowed = _borrow_roles(cursor, table_owners | sequence_owners)
                cursor.execute(
                    f'GRANT {privileges} ON ALL TABLES IN SCHEMA "{schema}" TO "{username}"'
                )
                cursor.execute(
                    f'ALTER DEFAULT PRIVILEGES IN SCHEMA "{schema}"'
                    f' GRANT {privileges} ON TABLES TO "{username}"'
                )
                if grant_sequences:
                    cursor.execute(
                        f'GRANT USAGE ON ALL SEQUENCES IN SCHEMA "{schema}"'
                        f' TO "{username}"'
                    )
                    cursor.execute(
                        f'ALTER DEFAULT PRIVILEGES IN SCHEMA "{schema}"'
                        f' GRANT USAGE ON SEQUENCES TO "{username}"'
                    )
                for owner in sorted(table_owners):
                    cursor.execute(
                        f"ALTER DEFAULT PRIVILEGES FOR ROLE {_quote_ident(owner)}"
                        f' IN SCHEMA "{schema}"'
                        f' GRANT {privileges} ON TABLES TO "{username}"'
                    )
                if grant_sequences:
                    # A table owner is in here too: the sequence behind a serial column is created
                    # by whoever creates the table.
                    for owner in sorted(table_owners | sequence_owners):
                        cursor.execute(
                            f"ALTER DEFAULT PRIVILEGES FOR ROLE {_quote_ident(owner)}"
                            f' IN SCHEMA "{schema}"'
                            f' GRANT USAGE ON SEQUENCES TO "{username}"'
                        )
                # Unwind only what this run added, so a pre-existing membership survives.
                for owner in borrowed:
                    cursor.execute(f"REVOKE {_quote_ident(owner)} FROM CURRENT_USER")
            cursor.execute(
                "SELECT DISTINCT table_schema, privilege_type"
                " FROM information_schema.role_table_grants WHERE grantee = %s",
                (username,),
            )
            grants = [f"{row[0]}: {row[1]}" for row in cursor.fetchall()]
            if grant_sequences:
                cursor.execute(
                    "SELECT DISTINCT object_schema, privilege_type"
                    " FROM information_schema.role_usage_grants"
                    " WHERE grantee = %s AND object_type = 'SEQUENCE'",
                    (username,),
                )
                grants += [f"{row[0]}: SEQUENCE {row[1]}" for row in cursor.fetchall()]
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        return grants


def _postgres_role_state(cursor: Any) -> dict[str, Any]:
    cursor.execute("SELECT CURRENT_USER, current_setting('server_version_num')::int")
    current_user, version = cursor.fetchone()
    if version < 160000:
        raise BootstrapError("PostgreSQL role inheritance requires version 16 or newer")
    cursor.execute(
        "SELECT rolname, rolcanlogin, rolsuper, rolcreaterole, rolcreatedb,"
        " rolreplication, rolbypassrls FROM pg_catalog.pg_roles ORDER BY rolname"
    )
    columns = [column[0] for column in cursor.description]
    roles = [dict(zip(columns, row, strict=True)) for row in cursor.fetchall()]
    cursor.execute(
        "SELECT m.rolname AS member, r.rolname AS role, a.admin_option,"
        " a.inherit_option, a.set_option FROM pg_catalog.pg_auth_members a"
        " JOIN pg_catalog.pg_roles m ON m.oid = a.member"
        " JOIN pg_catalog.pg_roles r ON r.oid = a.roleid"
        " ORDER BY m.rolname, r.rolname"
    )
    columns = [column[0] for column in cursor.description]
    memberships = [dict(zip(columns, row, strict=True)) for row in cursor.fetchall()]
    return {"current_user": current_user, "roles": roles, "memberships": memberships}


def _inspect_postgres_roles(event: dict[str, Any]) -> dict[str, Any]:
    group_name = event.get("group", "")
    group = _group(group_name)
    if group.engine != "postgres":
        raise BootstrapError("inspect-postgres-roles requires a PostgreSQL group")
    endpoint, port, _hosts, master = _resolve(group)
    try:
        with pg8000.dbapi.connect(
            host=endpoint,
            port=port,
            user=master.username,
            password=master.password.reveal(),
            database=group.database,
            ssl_context=_tls_context(group),
            timeout=15,
        ) as connection:
            cursor = connection.cursor()
            cursor.execute("SET TRANSACTION READ ONLY")
            state = _postgres_role_state(cursor)
            connection.rollback()
    except Exception as exc:  # noqa: BLE001
        raise BootstrapError(_scrub(str(exc), (master.password.reveal(),))) from None
    return {"action": "inspect-postgres-roles", "group": group_name, **state}


def _check_postgres_inheritance(cursor: Any, group: Group) -> bool:
    state = _postgres_role_state(cursor)
    roles = {role["rolname"]: role for role in state["roles"]}
    parent = roles.get(group.postgres_role)
    if parent is None or parent["rolcanlogin"]:
        raise BootstrapError("postgres_role must already exist as a NOLOGIN role")
    for name in (group.postgres_role, group.username):
        role = roles.get(name)
        if role and any(
            role[attr]
            for attr in (
                "rolsuper",
                "rolcreaterole",
                "rolcreatedb",
                "rolreplication",
                "rolbypassrls",
            )
        ):
            raise BootstrapError(f"role {name!r} has privileged attributes")
    for membership in state["memberships"]:
        if membership["member"] == group.username and (
            membership["role"] != group.postgres_role or membership["admin_option"]
        ):
            raise BootstrapError(
                "proxy account has unexpected role membership; review it before provisioning"
            )
    master = roles[state["current_user"]]
    if not (master["rolsuper"] or master["rolcreaterole"]):
        raise BootstrapError(
            "master needs CREATEROLE to manage the proxy login; role inheritance does not supply it"
        )
    return group.username in roles


def _verify_postgres_inherited_access(cursor: Any, group: Group) -> None:
    cursor.execute(
        "SELECT has_database_privilege(%s, current_database(), 'CONNECT'),"
        " pg_has_role(%s, %s, 'USAGE')",
        (group.username, group.username, group.postgres_role),
    )
    if not all(cursor.fetchone()):
        raise BootstrapError("proxy account lacks inherited role or database CONNECT")
    for schema in group.schemas:
        cursor.execute(
            "SELECT has_schema_privilege(%s, %s, 'USAGE')", (group.username, schema)
        )
        if not cursor.fetchone()[0]:
            raise BootstrapError(f"inherited role lacks USAGE on schema {schema!r}")
        for privilege in group.privileges:
            cursor.execute(
                "SELECT count(*), bool_and(has_table_privilege(%s, c.oid, %s))"
                " FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace"
                " WHERE n.nspname = %s AND c.relkind IN ('r', 'v', 'm', 'f', 'p')",
                (group.username, privilege, schema),
            )
            count, granted = cursor.fetchone()
            if not count or not granted:
                raise BootstrapError(
                    f"inherited role lacks {privilege} on tables in {schema!r}"
                )
        if POSTGRES_SEQUENCE_WRITERS.intersection(group.privileges):
            cursor.execute(
                "SELECT COALESCE(bool_and(has_sequence_privilege(%s, c.oid, 'USAGE')), true)"
                " FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace"
                " WHERE n.nspname = %s AND c.relkind = 'S'",
                (group.username, schema),
            )
            if not cursor.fetchone()[0]:
                raise BootstrapError(
                    f"inherited role lacks sequence USAGE in {schema!r}"
                )


def _provision_postgres_inherited(
    group: Group, endpoint: str, port: int, master: MasterCredential, password: Secret
) -> list[str]:
    if group.postgres_role is None:
        raise BootstrapError("postgres_role is required for inherited provisioning")
    with pg8000.dbapi.connect(
        host=endpoint,
        port=port,
        user=master.username,
        password=master.password.reveal(),
        database=group.database,
        ssl_context=_tls_context(group),
        timeout=15,
    ) as connection:
        cursor = connection.cursor()
        try:
            exists = _check_postgres_inheritance(cursor, group)
            username = _quote_ident(group.username)
            if not exists:
                cursor.execute(f"CREATE ROLE {username} LOGIN")
            cursor.execute(
                f"ALTER ROLE {username} WITH LOGIN INHERIT"
                f" PASSWORD '{_scram_verifier(password)}'"
            )
            for option in ("INHERIT TRUE", "SET TRUE", "ADMIN FALSE"):
                cursor.execute(
                    f"GRANT {_quote_ident(group.postgres_role)} TO {username} WITH {option}"
                )
            _verify_postgres_inherited_access(cursor, group)
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
    return [f"ROLE {group.postgres_role}: INHERIT TRUE, SET TRUE, ADMIN FALSE"]


def _quote_ident(name: str) -> str:
    """Quote a name read back from the catalog, which BARE_IDENTIFIER is too narrow to hold.

    A role may legally carry a dot, a space, "$", or Unicode, and rejecting one would abort a run
    that has already rotated the password. Config-sourced identifiers keep the stricter pattern.
    """
    if not name or "\x00" in name:
        raise BootstrapError("catalog identifier is empty or holds a NUL")
    escaped = name.replace('"', '""')
    return f'"{escaped}"'


def _schema_owners(cursor: Any, schema: str) -> set[str]:
    cursor.execute(POSTGRES_SCHEMA_OWNERS_SQL, (schema, schema))
    return _borrowable(cursor.fetchall())


def _sequence_owners(cursor: Any, schema: str) -> set[str]:
    cursor.execute(POSTGRES_SEQUENCE_OWNERS_SQL, (schema,))
    return _borrowable(cursor.fetchall())


def _borrowable(rows: list[Any]) -> set[str]:
    # pg_database_owner, what owns public since 15, rejects explicit members outright, so borrowing
    # it could only fail. Every other predefined role is left in: one can own a relation.
    return {row[0] for row in rows} - {"pg_database_owner"}


def _borrow_roles(cursor: Any, owners: set[str]) -> list[str]:
    """Take membership in the owners this master lacks, so a schema-wide GRANT can speak for them.

    A GRANT expands per relation and each one is checked against its own owner, so a master that
    owns none of them (any external target, where the DB predates proxy-monster) grants nothing
    without this. Borrowing needs ADMIN OPTION on the role, which is the master's real bar.
    """
    borrowed = []
    for owner in sorted(owners):
        cursor.execute("SELECT pg_has_role(CURRENT_USER, %s, 'USAGE')", (owner,))
        if cursor.fetchone()[0]:
            continue
        # A NOINHERIT membership confers no USAGE, so this point is also reached with the membership
        # already in place. GRANT then updates it rather than adding one, and revoking it at the end
        # would delete what this run never created.
        cursor.execute(POSTGRES_DIRECT_MEMBERSHIP_SQL, (owner,))
        held = cursor.fetchone() is not None
        cursor.execute(f"GRANT {_quote_ident(owner)} TO CURRENT_USER")
        if not held:
            borrowed.append(owner)
    return borrowed


def _publish(group: Group, password: Secret) -> list[str]:
    client = boto3.client("secretsmanager")
    payload = json.dumps(
        {
            "username": group.username,
            "password": password.reveal(),
        }
    )
    written = []
    for key in sorted(group.datasources):
        secret_id = f"{CONFIG.secret_prefix}{key}"
        client.put_secret_value(SecretId=secret_id, SecretString=payload)
        written.append(secret_id)
    return written


def _restart_proxies(group: Group) -> list[str]:
    """ECS reads the secret at task start only, so rotation reaches the proxies via redeploy."""
    client = boto3.client("ecs")
    restarted = []
    for key in sorted(group.datasources):
        client.update_service(
            cluster=CONFIG.ecs_cluster,
            service=f"proxy-{key}",
            forceNewDeployment=True,
        )
        restarted.append(f"proxy-{key}")
    return restarted


def _scrub(message: str, values: tuple[str, ...]) -> str:
    for value in values:
        if value:
            message = message.replace(value, "***")
    return message
