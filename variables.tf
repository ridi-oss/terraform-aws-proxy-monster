variable "audit_bucket_name" {
  type        = string
  description = "Name of the S3 Object-Lock (WORM) bucket for the auditmon export trail."
}

variable "audit_lock_mode" {
  type        = string
  description = "Object-Lock retention mode for the audit WORM bucket. COMPLIANCE cannot be shortened, overridden, or deleted by any principal including the account root, and blocks emptying or deleting the bucket until every lock expires; GOVERNANCE can be bypassed with s3:BypassGovernanceRetention. Use COMPLIANCE once production data is brokered."
  default     = "GOVERNANCE"

  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.audit_lock_mode)
    error_message = "audit_lock_mode must be \"GOVERNANCE\" or \"COMPLIANCE\"."
  }
}

variable "audit_retention_days" {
  type        = number
  description = "Default Object-Lock retention in days for the audit WORM bucket."
  default     = 30
}

variable "aurora_max_capacity" {
  type        = number
  description = "Serverless v2 ACU ceiling for the control-plane store. Scale it with the datasource count: every brokered query reaches this cluster through the control plane's Decide call, and each proxy pushes a full catalog at boot."
  default     = 4
}

variable "bootstrap_client_host_pattern" {
  type        = string
  description = <<-EOT
    MySQL host pattern for the bootstrapped account, covering the proxy task subnets
    (e.g. "10.0.%"). Required once a target_credential_groups entry is MySQL; PostgreSQL ignores it.
  EOT
  default     = null

  validation {
    condition     = var.bootstrap_client_host_pattern == null || can(regex("^[0-9]{1,3}\\.[0-9.%_]{1,28}$", var.bootstrap_client_host_pattern))
    error_message = "bootstrap_client_host_pattern must contain only digits, dots, and the SQL wildcards % and _; it is interpolated into CREATE USER."
  }

  validation {
    condition     = !anytrue([for g in var.target_credential_groups : g.engine == "mysql"]) || var.bootstrap_client_host_pattern != null
    error_message = "bootstrap_client_host_pattern is required when a target_credential_groups entry is MySQL."
  }
}

variable "bootstrap_security_group_ids" {
  type        = list(string)
  description = "Extra security groups on the bootstrap function's ENIs, for backend reachability (e.g. a group the target DB already admits)."
  default     = []
}

variable "console_cert_domain" {
  type        = string
  description = "ACM certificate domain to look up for the console HTTPS listener. Null derives the immediate-parent wildcard of console_hostname (pm.dev.example.com -> *.dev.example.com). Set it when the ISSUED cert's primary domain is not that wildcard (pm.example.com served by an example.com cert with a *.example.com SAN): the aws_acm_certificate data source matches the primary domain, not SANs."
  default     = null
}

variable "console_extra_ingress_cidrs" {
  type        = map(string)
  description = "Extra CIDR sources admitted to the console ALB on 80/443, keyed by rule-name suffix, for clients outside the service VPC (e.g. a VDI or VPN VPC)."
  default     = {}
}

variable "instance" {
  type = object({
    name        = optional(string)
    description = optional(string, "")
  })
  description = <<-EOT
    How this deployment introduces itself to users and MCP agents. name is the MCP install name
    (pmon-<name>): lowercase letters, digits and inner hyphens, at most 40; null derives it from the
    console hostname's first label. description is one line, at most 500 characters.
  EOT
  default     = {}

  validation {
    condition     = var.instance.name == null || can(regex("^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$", var.instance.name))
    error_message = "instance.name must be 1-40 lowercase letters, digits and inner hyphens."
  }

  validation {
    condition     = length(var.instance.description) <= 500 && !can(regex("\\p{Cc}", var.instance.description))
    error_message = "instance.description must be one line of at most 500 characters."
  }
}

variable "console_hostname" {
  type        = string
  description = "Public FQDN of the web console (ALB host); its immediate-parent wildcard ACM cert must exist (e.g. pm.dev.example.com -> *.dev.example.com). The DNS record is the caller's: point it at console_alb_dns_name."
}

variable "control_plane_task_size" {
  type = object({
    cpu    = number
    memory = number
  })
  default = {
    cpu    = 1024
    memory = 2048
  }
  description = <<-EOT
    Fargate task size for the control-plane service. Default 1024 / 2048.

    The service is pinned to one task and cannot scale out, so burst capacity is vertical only:
    every console query, every proxy Events stream, and the policy engine share this one task.
    Size it from the peak, not the average, and keep to a documented Fargate cpu/memory pair.
  EOT
}

variable "database_subnets" {
  type        = list(string)
  description = "Subnet IDs for the Aurora PostgreSQL control-plane store."
}

variable "datasources" {
  type = map(object({
    engine    = string
    wire_port = number
    target = optional(object({
      host = string
      port = number
      db   = string
      tls  = optional(string, "disable")
      ca   = optional(string)
    }))
    tags                     = optional(string, "")
    description              = optional(string, "")
    extra_security_group_ids = optional(list(string), [])
    credential_group         = optional(string)
    athena = optional(object({
      workgroup = string
      database  = string
      catalog   = optional(string, "AwsDataCatalog")
      # S3 prefixes ("bucket/key/", or "bucket/" for a whole bucket) the proxy's task role may use: the
      # workgroup's query-result location read-write, and every table location the datasource serves
      # read-only. Athena reads table data as the caller, so these bound what the datasource can see
      # regardless of policy.
      result_prefix = string
      data_prefixes = list(string)
    }))
  }))
  description = <<-EOT
    Wire proxies, one ECS service + NLB listener per datasource; key = PM_DATASOURCE_NAME.
    A mysql/postgres datasource dials target with a credentials secret; credential_group names a
    target_credential_groups entry and the bootstrap function then fills and seals that secret, left
    null it stays a hand-filled shell. An athena datasource has no target and no secret: the proxy's
    task role calls Athena in this account on the athena block's workgroup, catalog and database.
    description is one line, at most 500 characters, shown to MCP agents.
    target.tls is the proxy's TLS toward the target DB (PM_TARGET_TLS): disable, require, verify-ca
    or verify-full. verify-full checks the certificate against target.host, so that must be the
    name on the certificate (for RDS, the endpoint). target.ca (PM_TARGET_CA) is a comma list of
    "system", "rds", or a PEM file path inside the container; with verify-full, unset means
    system,rds. verify-ca checks only the chain, so it needs a PEM path to a CA that signs nothing
    but this target, never system or rds.
  EOT

  validation {
    condition     = alltrue([for ds in var.datasources : length(ds.description) <= 500 && !can(regex("\\p{Cc}", ds.description))])
    error_message = "datasources[*].description must be one line of at most 500 characters."
  }

  validation {
    condition     = alltrue([for ds in var.datasources : contains(["mysql", "postgres", "athena"], ds.engine)])
    error_message = "datasources[*].engine must be \"mysql\", \"postgres\" or \"athena\"."
  }

  validation {
    condition = alltrue([
      for ds in var.datasources :
      ds.engine == "athena" ? (ds.athena != null && ds.target == null && ds.credential_group == null) : (ds.athena == null && ds.target != null)
    ])
    error_message = "An athena datasource sets athena and neither target nor credential_group; a mysql/postgres datasource sets target and not athena."
  }

  # The prefixes become IAM resource ARNs with "*" appended: "bucket" alone would also match
  # "bucket-other", and a "*" inside would widen the grant.
  validation {
    condition = alltrue([
      for ds in var.datasources : alltrue([
        for prefix in concat([ds.athena.result_prefix], ds.athena.data_prefixes) :
        can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]/([^*?]+/)?$", prefix))
      ]) && length(ds.athena.data_prefixes) > 0
      if ds.athena != null
    ])
    error_message = "athena.result_prefix and each athena.data_prefixes entry must be \"bucket/\" or \"bucket/key/\" with no wildcards, and data_prefixes must not be empty."
  }

  validation {
    condition = alltrue([
      for ds in var.datasources :
      can(regex("^[A-Za-z0-9._-]{1,128}$", ds.athena.workgroup)) && ds.athena.catalog == "AwsDataCatalog"
      if ds.athena != null
    ])
    error_message = "athena.workgroup must be an Athena workgroup name, and athena.catalog must be AwsDataCatalog: the task role reaches only this account's Glue catalog."
  }

  validation {
    condition     = alltrue([for ds in var.datasources : ds.target == null || contains(["disable", "require", "verify-ca", "verify-full"], try(ds.target.tls, ""))])
    error_message = "datasources[*].target.tls must be disable, require, verify-ca or verify-full."
  }

  validation {
    condition     = alltrue([for ds in var.datasources : try(ds.target.ca, null) == null || contains(["verify-ca", "verify-full"], try(ds.target.tls, ""))])
    error_message = "datasources[*].target.ca is read only with target.tls verify-ca or verify-full; the proxy refuses to start otherwise."
  }

  validation {
    condition = alltrue([
      for ds in var.datasources :
      try(ds.target.tls, "") != "verify-ca" || (
        try(ds.target.ca, null) != null && alltrue([
          for source in split(",", try(ds.target.ca, "")) : !contains(["", "system", "rds"], trimspace(source))
        ])
      )
    ])
    error_message = "datasources[*].target.tls verify-ca needs target.ca naming PEM files only: the proxy refuses system and rds there, since those CAs sign other servers too."
  }

  validation {
    condition = alltrue([
      for ds in var.datasources :
      ds.credential_group == null || contains(keys(var.target_credential_groups), coalesce(ds.credential_group, ""))
    ])
    error_message = "datasources[*].credential_group must name a key of target_credential_groups."
  }

  validation {
    condition = alltrue([
      for ds in var.datasources :
      ds.credential_group == null || ds.engine == try(var.target_credential_groups[ds.credential_group].engine, ds.engine)
    ])
    error_message = "datasources[*].engine must match the engine of its credential_group."
  }

  # The RDS counterpart is _check_datasource_hosts at bootstrap time, which needs describe_db_clusters
  # to resolve an identifier into endpoints. An external group carries its endpoint literally, so the
  # same mismatch is catchable here instead of one Lambda run later.
  validation {
    condition = alltrue([
      for ds in var.datasources :
      ds.target.host == var.target_credential_groups[ds.credential_group].external_host &&
      ds.target.port == var.target_credential_groups[ds.credential_group].external_port
      if ds.target != null && try(var.target_credential_groups[ds.credential_group].external_host, null) != null
    ])
    error_message = "A datasource on an external credential_group must dial that group's external_host and external_port. The function creates one account on the group's endpoint and publishes it to every datasource in the group, so one pointing elsewhere would be sealed with a credential for a different server."
  }

  # Each entry gets its own NLB target group, whose name the API caps at 32 characters. The name is
  # derived from the wire port rather than the key precisely so a descriptive key cannot overrun it, and
  # this states the remaining bound here — a duplicate port would otherwise collide inside the NLB module
  # and surface as a confusing name conflict several layers down.
  validation {
    condition     = length(distinct([for ds in var.datasources : ds.wire_port])) == length(var.datasources)
    error_message = "datasources[*].wire_port must be unique: each one names its own NLB listener and target group."
  }
}

variable "db_master_password_version" {
  type        = number
  description = "Bump to rotate the self-managed Aurora master password. Requires a control-plane force-new-deployment afterwards (the credential is cached at task boot)."
  default     = 1
}

variable "enable_lb_deletion_protection" {
  type        = bool
  description = "Deletion protection on both load balancers. The internal NLB's DNS name is the SAN of the wire TLS certificate and every proxy's PM_ADVERTISE_ADDR, so recreating it silently breaks every wire client."
  default     = false
}

variable "images" {
  type = object({
    control_plane = string
    proxy         = string
    web           = string
    auditmon      = string
  })
  description = "Full container image URIs (including tag) for the proxy-monster components."
}

variable "name" {
  type        = string
  description = "Resource name prefix (ECS cluster, load balancers, secrets)."
  default     = "proxy-monster"
}

variable "oidc" {
  type = object({
    issuer    = string
    client_id = string
    group_map = string
  })
  description = <<-EOT
    OIDC SSO client for the console (the client secret is filled manually into the
    <name>/oidc-client-secret secret). null disables SSO wiring until the IdP app exists.

    group_map maps IdP groups to proxy-monster roles: "idp-group=role,idp-group=role".
    Required, not optional. Without it the control plane runs in passthrough mode, which
    filters reserved `system:*` names so an IdP group can never confer admin merely by being
    named `system:admin`. The result is a user who signs in successfully, resolves to no
    roles, and is denied every query, with nothing in the UI explaining why. An explicit map
    is the only way an IdP group grants a system role.
    e.g. "proxy-monster-admin=system:admin,proxy-monster-developers=developers"
  EOT
  default     = null

  # A required key still accepts "", which the control plane parses identically to unset — the
  # passthrough footgun this field exists to prevent. Shape-check it too: at least one
  # non-empty group=role pair.
  validation {
    condition     = var.oidc == null || can(regex("^[^=,[:space:]]+=[^=,[:space:]]+(,[^=,[:space:]]+=[^=,[:space:]]+)*$", var.oidc.group_map))
    error_message = "oidc.group_map must be a non-empty comma-separated list of idp-group=role pairs, e.g. \"proxy-monster-admin=system:admin\". Empty parses as passthrough, which filters system:* roles and leaves SSO users with none."
  }
}

variable "private_subnets" {
  type        = list(string)
  description = "Subnet IDs for the ECS services and both (internal) load balancers."
}

variable "proxy_runtime_gid" {
  type        = number
  description = "Group id the proxy image runs as. The init container gives the TLS key to this group, and the proxy cannot read it — so it cannot serve TLS and pmon cannot broker — if this disagrees with the image's own user. Changing the image's USER means changing this."
  default     = 10001
}

variable "rds_admin_key_enabler_role_arns" {
  type        = map(list(string))
  description = <<-EOT
    Roles allowed to enable managed master credentials against each rds-admin key, keyed by
    aws_account_alias; in practice the role that runs terraform apply there. Drop an entry to [] once
    its targets report SecretStatus active.
  EOT
  default     = {}
}

variable "result_key_version" {
  type        = number
  description = "Bump to regenerate PM_RESULT_KEY. Separate from secret_rotation_version because it encrypts data at rest (refresh tokens, approver-exec results); rotating it orphans existing ciphertext, so migrate/discard that data first."
  default     = 1
}

variable "seal_audit_alarm_actions" {
  type        = list(string)
  description = "ARNs notified when the seal-audit alarm fires (SNS topic, Chatbot). Empty leaves the alarm state as the only signal, which nothing watches on its own."
  default     = []
}

variable "secret_recovery_window_days" {
  type        = number
  description = "Secrets Manager recovery window on destroy. 0 lets a dev stack be recreated with the same secret names immediately; keep the 30-day default for prod."
  default     = 30
}

variable "secret_rotation_version" {
  type        = number
  description = "Bump to regenerate the generated secrets (session secret, result key, gRPC token)."
  default     = 1
}

variable "target_credential_groups" {
  type = map(object({
    aws_account_id    = optional(string)
    aws_account_alias = optional(string)
    rds_kind          = optional(string)
    rds_identifier    = optional(string)

    external_identifier = optional(string)
    external_host       = optional(string)
    external_port       = optional(number)
    external_ca_pem     = optional(string)

    external_ca_strict_extensions = optional(bool, true)

    engine            = string
    database          = string
    schemas           = list(string)
    privileges        = optional(list(string), ["SELECT"])
    system_schemas    = optional(list(string), [])
    system_routines   = optional(list(string), [])
    drop_tables       = optional(list(string), [])
    global_privileges = optional(list(string), [])
    username          = optional(string, "pmproxy")
    postgres_role     = optional(string)

    postgres_role_create = optional(bool, false)
  }))
  description = <<-EOT
    Backend DB accounts the bootstrap function provisions, keyed by group name. One group names one
    target; every datasource carrying that credential_group receives the same credential.

    A group is backed one of two ways, never both.

    RDS-backed (aws_account_id, aws_account_alias, rds_kind, rds_identifier): the function assumes a
    reader role in that account, resolves the endpoint through the RDS API, and reads the credential
    RDS manages. The target must already have manage_master_user_password = true with
    master_user_secret_kms_key_id set to rds_admin_key_arns[aws_account_alias] from this module, and
    must hold a <name>-bootstrap-reader role trusting this account. Both live in the leaf that owns
    the database.

    External (external_identifier, external_host, external_port, external_ca_pem): for a backend the
    RDS API cannot describe, such as GCP Cloud SQL. There is no managed master credential to read, so
    this module creates an empty <name>/master-credentials/<external_identifier> secret that an
    operator fills by hand with the master account, and the function reads that instead. It assumes
    no role and describes nothing: the host is taken at its word, and reachability from the
    function's subnets is a precondition, not something this checks.

    external_identifier names the backend instance, the way rds_identifier does for RDS, and every
    group on it shares one master-credentials secret. One master account per instance is the fact on
    the ground: a per-group secret would be the same credential typed twice, and the two copies drift
    the first time it rotates.

    external_ca_pem is the CA that signs the backend's certificate, which the function verifies the
    chain against because the RDS bundle it otherwise pins does not sign these. Cloud SQL issues one
    CA per instance, readable from `gcloud sql instances describe <id> --format='value(serverCaCert.cert)'`;
    it is a public certificate, not a secret, and it expires, so it belongs in version control where
    a reviewer can see the date.

    external_ca_strict_extensions keeps OpenSSL's RFC 5280 extension checks on. Set it false only for
    a backend whose certificates do not comply: a Cloud SQL per-instance CA carries no Subject Key
    Identifier, so its leaf carries no Authority Key Identifier and the handshake is rejected. Per
    group rather than implied by external, so a later compliant target keeps the stricter check. The
    chain is verified against external_ca_pem either way.

    database is the connect database; schemas are what the account is granted privileges on
    (SELECT-only unless widened), and they decide what the proxy's catalog contains, because
    information_schema is privilege-filtered. A list rather than one name because a target normally
    holds several and the alternative would be one credential per schema on the same backend. GRANT
    is additive, so re-running never narrows an existing account: removing a schema here needs a
    REVOKE that this does not issue.

    privileges applies to every schema in the group; a datasource needing a different privilege set
    needs its own group. SELECT stays mandatory because the catalog is built from it. GRANT OPTION
    sits here rather than in global_privileges because MySQL scopes it per schema, and MySQL checks a
    grantor against every privilege it passes on, so it can never widen the account itself.

    postgres_role opts PostgreSQL 16+ into inheriting an existing NOLOGIN role instead of direct
    object grants. The master still needs CREATEROLE and ADMIN OPTION on that role and any existing
    proxy account. Other memberships cause an error rather than being revoked. The role owns the
    table, sequence and default-privilege policy; schemas and privileges describe expected access,
    not a limit on what the role can grant. Audit the role before provisioning.

    postgres_role_create lets the function create postgres_role itself as NOLOGIN, and each of
    schemas with that role as owner, when they do not exist. For a database this stack owns
    outright, so no one has to run the first statements by hand. An existing schema must already
    be owned by postgres_role; objects other roles created in it keep their owners.

    system_schemas receive SELECT only, independently of the group's application privileges.
    mysql enables SHOW GRANTS FOR other accounts and also exposes authentication tables,
    including password hashes. Grant it only to accounts intended to inspect other accounts.
    performance_schema enables lock and wait diagnostics. Proxy authorization is configured
    separately from these backend privileges.

    system_routines are RDS-provided stored procedures granted EXECUTE, each named schema.routine.
    The allowlist limits execution to mysql.rds_kill and mysql.rds_kill_query without granting
    schema-wide EXECUTE.

    drop_tables are tables granted DROP at table level, each named schema.table within the
    group's schemas. DROP is the one keyword worth scoping this way: schema-wide, it carries
    DROP DATABASE and TRUNCATE on every table, which is why a production group keeps it out of
    privileges. The table part may carry "*" as a glob (schema.*_dropme_20260929), expanded to
    the base tables that exist when the function runs; a table created later needs another run.
    An entry that matches no table is skipped and reported in drop_tables_skipped, since MySQL
    refuses a grant on a missing table. MySQL keeps the table-level row across DROP TABLE, so a
    table recreated under the same name inherits the grant.

    global_privileges are granted ON *.*, the only unscoped grant this issues, because MySQL defines
    them at the global level only. PROCESS is what makes information_schema.INNODB_TRX readable and
    what shows other sessions' rows in PROCESSLIST; it also exposes every session's current statement
    text server-wide, so it belongs on an account that needs transaction diagnostics and no other.
    CREATE USER provisions an application account through the proxy rather than through the RDS master
    credential. MySQL folds DROP USER, RENAME USER and ALTER USER into it at server scope, so the
    account also reaches every other account on the target, this module's own pmproxy_ro included.

    Every one of these is interpolated into SQL: identifiers are validated as bare identifiers and
    privileges against the engine's grantable keywords.
  EOT
  default     = {}

  validation {
    condition = alltrue([
      for group in var.target_credential_groups : group.postgres_role == null ? true : (
        group.engine == "postgres" &&
        can(regex("^[A-Za-z0-9_]{1,63}$", group.postgres_role)) &&
        group.postgres_role != group.username
      )
    ])
    error_message = "postgres_role must be a PostgreSQL role identifier distinct from username."
  }

  validation {
    condition     = alltrue([for group in var.target_credential_groups : !group.postgres_role_create || group.postgres_role != null])
    error_message = "postgres_role_create needs postgres_role."
  }

  # Names the function creates: PostgreSQL reserves pg_ and truncates past 63 bytes, and a repeated
  # schema would be created twice.
  validation {
    condition = alltrue([
      for group in var.target_credential_groups :
      length(distinct(group.schemas)) == length(group.schemas) && alltrue([
        for name in concat([coalesce(group.postgres_role, "x")], group.schemas) :
        !startswith(name, "pg_") && length(name) <= 63
      ])
      if group.postgres_role_create
    ])
    error_message = "With postgres_role_create, schemas must be distinct, and postgres_role and each schema must not start with pg_ and must fit in 63 bytes."
  }

  validation {
    condition = alltrue([
      for group in var.target_credential_groups :
      (
        group.aws_account_id != null && group.aws_account_alias != null &&
        group.rds_kind != null && group.rds_identifier != null &&
        group.external_host == null && group.external_port == null
        ) || (
        group.external_host != null && group.external_port != null &&
        group.aws_account_id == null && group.aws_account_alias == null &&
        group.rds_kind == null && group.rds_identifier == null
      )
    ])
    error_message = "Each target_credential_groups entry must be either RDS-backed (aws_account_id, aws_account_alias, rds_kind, rds_identifier) or external (external_host, external_port), with the other set left unset. The two resolve the endpoint and the master credential by different routes, so a half-filled group would silently take the RDS path."
  }

  validation {
    condition = alltrue([
      for group in var.target_credential_groups :
      (group.external_host == null) == (group.external_identifier == null)
    ])
    error_message = "An external target_credential_groups entry needs external_identifier, and an RDS-backed one must leave it unset: it names the backend instance whose hand-filled master-credentials secret the group reads."
  }

  validation {
    condition = alltrue([
      for a in var.target_credential_groups : alltrue([
        for b in var.target_credential_groups :
        a.external_host == b.external_host && a.external_port == b.external_port && a.external_ca_pem == b.external_ca_pem
        if a.external_identifier != null && a.external_identifier == b.external_identifier
      ])
    ])
    error_message = "target_credential_groups entries sharing an external_identifier must agree on external_host, external_port, and external_ca_pem: one identifier is one backend instance, and the groups on it share that instance's master account and CA."
  }

  validation {
    condition = alltrue([
      for group in var.target_credential_groups :
      group.external_host == null || can(regex("-----BEGIN CERTIFICATE-----", coalesce(group.external_ca_pem, "")))
    ])
    error_message = "An external target_credential_groups entry needs external_ca_pem: the function verifies the backend's chain against it, and the RDS bundle it otherwise pins does not sign external certificates."
  }

  validation {
    condition = alltrue([
      for group in var.target_credential_groups :
      group.external_host != null || group.external_ca_pem == null
    ])
    error_message = "external_ca_pem is only read for external groups; an RDS-backed group verifies against the bundled RDS CA."
  }

  validation {
    condition = alltrue([
      for group in var.target_credential_groups :
      group.external_host != null || group.external_ca_strict_extensions
    ])
    error_message = "external_ca_strict_extensions is only read for external groups; the bundled RDS CA is RFC 5280 clean, so an RDS-backed group has nothing to relax."
  }

  validation {
    condition     = alltrue([for group in var.target_credential_groups : group.rds_kind == null || contains(["cluster", "instance"], group.rds_kind)])
    error_message = "target_credential_groups[*].rds_kind must be \"cluster\" or \"instance\"."
  }

  validation {
    condition     = alltrue([for group in var.target_credential_groups : contains(["mysql", "postgres"], group.engine)])
    error_message = "target_credential_groups[*].engine must be \"mysql\" or \"postgres\"."
  }

  validation {
    condition = alltrue([
      for group in var.target_credential_groups :
      can(regex("^[A-Za-z0-9_]{1,64}$", group.database)) && can(regex("^[A-Za-z0-9_]{1,32}$", group.username)) && alltrue([for schema in group.schemas : can(regex("^[A-Za-z0-9_]{1,64}$", schema))])
    ])
    error_message = "target_credential_groups[*].{database,schemas,username} must be bare identifiers: they are interpolated into SQL."
  }

  validation {
    condition     = alltrue([for group in var.target_credential_groups : length(group.schemas) > 0])
    error_message = "target_credential_groups[*].schemas must name at least one schema: an empty grant gives the proxy an empty catalog, which reads as a broken credential."
  }

  validation {
    condition = alltrue([
      for group in var.target_credential_groups : alltrue([
        for privilege in group.privileges : contains(
          group.engine == "postgres"
          ? ["DELETE", "INSERT", "REFERENCES", "SELECT", "TRIGGER", "TRUNCATE", "UPDATE"]
          : [
            "ALTER", "ALTER ROUTINE", "CREATE", "CREATE ROUTINE", "CREATE TEMPORARY TABLES",
            "CREATE VIEW", "DELETE", "DROP", "EVENT", "EXECUTE", "GRANT OPTION", "INDEX",
            "INSERT", "LOCK TABLES", "REFERENCES", "SELECT", "SHOW VIEW", "TRIGGER", "UPDATE",
          ],
          privilege
        )
      ])
    ])
    error_message = "target_credential_groups[*].privileges must be grantable keywords for the group's engine: they are interpolated into SQL."
  }

  validation {
    condition     = alltrue([for group in var.target_credential_groups : contains(group.privileges, "SELECT")])
    error_message = "target_credential_groups[*].privileges must include SELECT: the proxy's catalog and every read depend on it."
  }

  validation {
    condition = alltrue([
      for group in var.target_credential_groups : alltrue([
        for schema in group.system_schemas : contains(
          group.engine == "postgres" ? [] : ["mysql", "performance_schema", "sys"],
          schema
        )
      ])
    ])
    error_message = "target_credential_groups[*].system_schemas must be \"mysql\", \"performance_schema\" or \"sys\" on MySQL and empty on PostgreSQL. mysql grants SELECT access to account authentication tables as well as SHOW GRANTS FOR other accounts."
  }

  validation {
    condition = alltrue([
      for group in var.target_credential_groups : alltrue([
        for routine in group.system_routines : contains(
          group.engine == "postgres" ? [] : ["mysql.rds_kill", "mysql.rds_kill_query"],
          routine
        )
      ])
    ])
    error_message = "target_credential_groups[*].system_routines must be \"mysql.rds_kill\" or \"mysql.rds_kill_query\" on MySQL and empty on PostgreSQL: they are the RDS procedures that end a session the account does not own."
  }

  validation {
    condition = alltrue([
      for group in var.target_credential_groups : alltrue([
        for table in group.drop_tables :
        group.engine == "mysql" && can(regex("^[A-Za-z0-9_]{1,64}\\.[A-Za-z0-9_*]{1,64}$", table)) && can(regex("[A-Za-z0-9_]", split(".", table)[1])) && contains(group.schemas, split(".", table)[0])
      ])
    ])
    error_message = "target_credential_groups[*].drop_tables must be schema.table names or \"*\" globs (never a bare \"*\") within the group's schemas on MySQL and empty on PostgreSQL: they are interpolated into SQL, and DROP is not a grantable privilege on PostgreSQL."
  }

  validation {
    condition = alltrue([
      for group in var.target_credential_groups : alltrue([
        for privilege in group.global_privileges : contains(
          group.engine == "postgres" ? [] : ["CREATE USER", "PROCESS", "REPLICATION CLIENT"],
          privilege
        )
      ])
    ])
    error_message = "target_credential_groups[*].global_privileges must be \"CREATE USER\", \"PROCESS\" or \"REPLICATION CLIENT\" on MySQL and empty on PostgreSQL: they are granted ON *.*, so the list stays keywords MySQL defines at the global level only."
  }

  validation {
    condition = length(distinct([
      for group in var.target_credential_groups : "${group.aws_account_alias}/${group.aws_account_id}"
      if group.aws_account_alias != null
      ])) == length(distinct([
      for group in var.target_credential_groups : group.aws_account_alias
      if group.aws_account_alias != null
    ]))
    error_message = "target_credential_groups[*].aws_account_alias must map to exactly one aws_account_id."
  }
}

variable "target_credentials_key_admin_role_arns" {
  type        = list(string)
  description = <<-EOT
    Roles exempted from the target-credentials key Deny; in practice the role that runs
    terraform apply. Exemption is not access: the secret policy still denies them GetSecretValue.
  EOT
  default     = []
}

variable "vpc_cidr" {
  type        = string
  description = "VPC CIDR block; used for the load-balancer ingress rules."
}

variable "vpc_id" {
  type        = string
  description = "VPC ID the stack deploys into."
}

variable "auditmon_task_size" {
  type = object({
    cpu    = number
    memory = number
  })
  default = {
    cpu    = 512
    memory = 1024
  }
  description = <<-EOT
    Fargate task size for the auditmon service. Default 512 / 1024.

    One poll reads every event since the last signed anchor into memory at once, so the sizing
    input is the backlog a long outage leaves behind, not the steady-state event rate: a busy
    trail outgrows the default and OOM-kills the task before it can export or advance the anchor,
    which no restart recovers from. Raise it per deployment, and keep to a documented Fargate
    cpu/memory pair.
  EOT
}

variable "auditmon_slack_alerts" {
  type = object({
    min_severity = optional(string, "warn")
  })
  default     = null
  description = <<-EOT
    Forward auditmon alerts to Slack and enable the anomaly-detection rules that feed them.
    A non-null value mounts an auditmon.yaml with the rules and the Slack webhook sink; null
    disables both (alerts still reach the WORM bucket). Default null.

    The webhook URL is filled by hand into the <name>/alert-slack-webhook secret; a sink with
    an empty URL makes auditmon fail closed at boot, so fill the secret before setting this.

    min_severity is the Slack floor: "warn" forwards every rule; "critical" forwards only
    mass-export volume breaches and chain-integrity breaks.
  EOT

  validation {
    condition     = var.auditmon_slack_alerts == null ? true : contains(["info", "warn", "critical"], var.auditmon_slack_alerts.min_severity)
    error_message = "auditmon_slack_alerts.min_severity must be info, warn, or critical."
  }
}

variable "slack" {
  type = object({
    statement = optional(string, "auto")
    locale    = optional(string, "en")
  })
  default     = null
  description = <<-EOT
    Slack approval notifications from the control plane. A non-null value wires the notifier and
    creates a <name>/slack secret; null disables the layer. Default null. Distinct from
    auditmon_slack_alerts, which is auditmon's own SecOps webhook.

    Both tokens are filled by hand into the <name>/slack secret as a JSON object
    {"bot_token":"xoxb-…","app_token":"xapp-…"}; the control plane runs the layer inert until both
    are present, so fill the secret before rolling the control plane onto this.

    statement controls how much of a query's SQL an approval message shows — "omit" (metadata only),
    "auto" (the default; shown only when a disclosure hint clears it, hidden when the query's own text
    carries a protected literal), or "full" (shown to pending approvers, then hidden once the task is
    handled if the hint flags it). A statement's literals can be the very values a policy protects, so
    "omit" is the conservative floor. locale is the notification language, "en" or "ko".
  EOT

  validation {
    condition     = var.slack == null ? true : contains(["omit", "auto", "full"], var.slack.statement)
    error_message = "slack.statement must be omit, auto, or full."
  }

  validation {
    condition     = var.slack == null ? true : contains(["en", "ko"], var.slack.locale)
    error_message = "slack.locale must be en or ko."
  }
}
