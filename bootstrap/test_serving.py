import unittest
from unittest.mock import MagicMock, mock_open, patch

with patch(
    "builtins.open",
    mock_open(read_data='{"secret_prefix": "", "ecs_cluster": "", "groups": {}}'),
):
    import handler as bootstrap


def make_group(datasources, serving):
    return bootstrap.Group(
        engine="mysql",
        database="app",
        schemas=["app"],
        privileges=["SELECT"],
        system_schemas=[],
        system_routines=[],
        global_privileges=[],
        username="pmproxy_rw",
        host_pattern="10.25.%",
        datasources=datasources,
        serving=serving,
    )


class ServingTest(unittest.TestCase):
    def test_disabled_datasource_gets_its_secret_but_no_restart(self):
        group = make_group({"a_off": "db.example.com", "z_on": "db.example.com"}, ["z_on"])
        aws = MagicMock()
        with patch.object(bootstrap.boto3, "client", return_value=aws):
            written = bootstrap._publish(group, bootstrap.Secret("pw"))
            restarted = bootstrap._restart_proxies(group)

        prefix = bootstrap.CONFIG.secret_prefix
        self.assertEqual(written, [f"{prefix}a_off", f"{prefix}z_on"])
        self.assertEqual(restarted, ["proxy-z_on"])
        aws.update_service.assert_called_once_with(
            cluster=bootstrap.CONFIG.ecs_cluster, service="proxy-z_on", forceNewDeployment=True
        )


if __name__ == "__main__":
    unittest.main()
