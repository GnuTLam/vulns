"""The updater sidecar's pure logic: rebuilding the container configuration from an
inspection and validating update requests. The Docker API itself is exercised by the
end-to-end release process, not here."""

import importlib.util
import sys
from pathlib import Path

UPDATER = Path(__file__).resolve().parents[1] / "updater" / "app.py"


def sidecar():
    if str(UPDATER.parent) not in sys.path:
        sys.path.insert(0, str(UPDATER.parent))
    spec = importlib.util.spec_from_file_location("vulns_updater", UPDATER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_container_recreate_plan_reproduces_the_compose_configuration():
    updater = sidecar()
    attrs = {
        "Config": {
            "Env": ["VULNS_DATA_DIR=/data", "VULNS_ADMIN_PASSWORD=x"],
            "Labels": {"com.docker.compose.service": "vulns"},
            "Hostname": "vulns",
            "Healthcheck": {
                "Test": ["CMD", "python", "-c", "pass"],
                "Interval": 30000000000,
                "Timeout": None,
                "StartPeriod": 10000000000,
                "Retries": 3,
            },
        },
        "HostConfig": {
            "PortBindings": {"8000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8000"}]},
            "RestartPolicy": {"Name": "unless-stopped", "MaximumRetryCount": 0},
            "SecurityOpt": ["no-new-privileges:true"],
            "NetworkMode": "vulns_default",
        },
        "Mounts": [
            {"Type": "volume", "Source": "vulns_vulns_data", "Destination": "/data", "RW": True},
            {"Type": "volume", "Source": "other", "Destination": "/ro", "RW": False},
            {"Type": "tmpfs", "Source": "", "Destination": "/tmp", "RW": True},
        ],
    }
    plan = updater.container_recreate_plan(attrs)
    assert plan["environment"] == ["VULNS_DATA_DIR=/data", "VULNS_ADMIN_PASSWORD=x"]
    assert plan["labels"] == {"com.docker.compose.service": "vulns"}
    assert plan["binds"] == ["vulns_vulns_data:/data", "other:/ro:ro"]
    assert plan["port_bindings"] == {"8000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8000"}]}
    assert plan["exposed_ports"] == ["8000/tcp"]
    assert plan["restart_policy"] == {"Name": "unless-stopped"}
    assert plan["security_opt"] == ["no-new-privileges:true"]
    assert plan["healthcheck"]["Interval"] == 30000000000
    assert "Timeout" not in plan["healthcheck"]  # null values are dropped


def test_version_and_image_rules():
    updater = sidecar()
    assert updater.VERSION_RE.match("1.2.3") and updater.VERSION_RE.match("v0.10.0")
    assert not updater.VERSION_RE.match("latest")
    assert not updater.VERSION_RE.match("1.2.3-broken")
    assert updater.IMAGE_PREFIX == "ghcr.io/gnutlam/vulns:"
