import json
import os
import time
from unittest.mock import MagicMock, patch

from crusoe import (
    CACHE_TTL,
    build_cluster_names,
    build_inventory,
    build_vm_to_nodepool,
    get_clusters,
    get_nodepools,
    get_vms,
    load_cache,
    save_cache,
)

SAMPLE_VMS = [
    {
        "id": "vm-001",
        "name": "gpu-worker-01",
        "type": "a40.80gb",
        "location": "us-northcentral1-a",
        "project_id": "proj-aaa-111",
        "state": "STATE_RUNNING",
        "network_interfaces": [{"ips": [{
            "private_ipv4": {"address": "10.0.1.10"},
            "public_ipv4": {"address": "1.2.3.4"},
        }]}],
    },
    {
        "id": "vm-002",
        "name": "cpu-worker-01",
        "type": "c1a.16x",
        "location": "us-east1-a",
        "project_id": "proj-bbb-222",
        "state": "STATE_RUNNING",
        "network_interfaces": [{"ips": [{
            "private_ipv4": {"address": "10.0.2.20"},
        }]}],
    },
    {
        "id": "vm-003",
        "name": "stopped-vm",
        "type": "a40.80gb",
        "location": "us-northcentral1-a",
        "project_id": "proj-aaa-111",
        "state": "STATE_STOPPED",
        "network_interfaces": [],
    },
]

SAMPLE_NODEPOOLS = [
    {
        "id": "np-001",
        "name": "gpu-pool",
        "cluster_id": "cluster-abc",
        "instance_ids": ["vm-001"],
        "node_labels": {"type": "a40", "crusoe.ai/nodepool.name": "gpu-pool"},
    },
    {
        "id": "np-002",
        "name": "cpu-pool",
        "cluster_id": "cluster-abc",
        "instance_ids": ["vm-002"],
        "node_labels": {"type": "c1a", "crusoe.ai/nodepool.name": "cpu-pool"},
    },
]

SAMPLE_CLUSTERS = [
    {"id": "cluster-abc", "name": "prod-cluster"},
]


def test_all_running_vms_in_all_group():
    inv = build_inventory(SAMPLE_VMS)
    assert "gpu-worker-01" in inv["all"]["hosts"]
    assert "cpu-worker-01" in inv["all"]["hosts"]


def test_non_running_vms_excluded():
    inv = build_inventory(SAMPLE_VMS)
    assert "stopped-vm" not in inv["all"]["hosts"]


def test_project_groups_created():
    inv = build_inventory(SAMPLE_VMS)
    assert "gpu-worker-01" in inv["project_proj_aaa_111"]["hosts"]
    assert "cpu-worker-01" in inv["project_proj_bbb_222"]["hosts"]


def test_type_groups_created():
    inv = build_inventory(SAMPLE_VMS)
    assert "gpu-worker-01" in inv["type_a40"]["hosts"]
    assert "cpu-worker-01" in inv["type_c1a"]["hosts"]


def test_region_groups_created():
    inv = build_inventory(SAMPLE_VMS)
    assert "gpu-worker-01" in inv["region_us_northcentral1"]["hosts"]
    assert "cpu-worker-01" in inv["region_us_east1"]["hosts"]


def test_nodepool_groups_created():
    vm_to_np = build_vm_to_nodepool(SAMPLE_NODEPOOLS)
    inv = build_inventory(SAMPLE_VMS, vm_to_nodepool=vm_to_np)
    assert "gpu-worker-01" in inv["nodepool_gpu_pool"]["hosts"]
    assert "cpu-worker-01" in inv["nodepool_cpu_pool"]["hosts"]


def test_k8s_cluster_groups_created():
    vm_to_np = build_vm_to_nodepool(SAMPLE_NODEPOOLS)
    names = build_cluster_names(SAMPLE_CLUSTERS)
    inv = build_inventory(
        SAMPLE_VMS, vm_to_nodepool=vm_to_np, cluster_names=names
    )
    assert "gpu-worker-01" in inv["k8s_prod_cluster"]["hosts"]
    assert "cpu-worker-01" in inv["k8s_prod_cluster"]["hosts"]


def test_vms_without_nodepool_have_no_nodepool_group():
    inv = build_inventory(SAMPLE_VMS)
    assert not any(k.startswith("nodepool_") for k in inv)
    assert not any(k.startswith("k8s_") for k in inv)


def test_ansible_host_prefers_public_ip():
    inv = build_inventory(SAMPLE_VMS)
    assert inv["_meta"]["hostvars"]["gpu-worker-01"]["ansible_host"] == "1.2.3.4"


def test_ansible_host_falls_back_to_private_ip():
    inv = build_inventory(SAMPLE_VMS)
    assert inv["_meta"]["hostvars"]["cpu-worker-01"]["ansible_host"] == "10.0.2.20"


def test_hostvars_exposes_both_ips():
    inv = build_inventory(SAMPLE_VMS)
    hv = inv["_meta"]["hostvars"]["gpu-worker-01"]
    assert hv["crusoe_public_ip"] == "1.2.3.4"
    assert hv["crusoe_private_ip"] == "10.0.1.10"


def test_hostvars_crusoe_metadata():
    inv = build_inventory(SAMPLE_VMS)
    hv = inv["_meta"]["hostvars"]["gpu-worker-01"]
    assert hv["crusoe_project"] == "proj_aaa_111"
    assert hv["crusoe_type"] == "a40.80gb"
    assert hv["crusoe_location"] == "us-northcentral1-a"


def test_hostvars_nodepool_and_cluster():
    vm_to_np = build_vm_to_nodepool(SAMPLE_NODEPOOLS)
    names = build_cluster_names(SAMPLE_CLUSTERS)
    inv = build_inventory(
        SAMPLE_VMS, vm_to_nodepool=vm_to_np, cluster_names=names
    )
    hv = inv["_meta"]["hostvars"]["gpu-worker-01"]
    assert hv["crusoe_nodepool"] == "gpu_pool"
    assert hv["crusoe_cluster"] == "prod_cluster"
    assert hv["crusoe_node_labels"] == {
        "type": "a40",
        "crusoe.ai/nodepool.name": "gpu-pool",
    }


def test_hostvars_node_labels_empty_without_nodepool():
    inv = build_inventory(SAMPLE_VMS)
    hv = inv["_meta"]["hostvars"]["gpu-worker-01"]
    assert hv["crusoe_node_labels"] == {}


def test_meta_key_present():
    inv = build_inventory(SAMPLE_VMS)
    assert "_meta" in inv
    assert "hostvars" in inv["_meta"]


def test_empty_vm_list():
    inv = build_inventory([])
    assert inv["all"]["hosts"] == []
    assert inv["_meta"]["hostvars"] == {}


def test_build_vm_to_nodepool():
    mapping = build_vm_to_nodepool(SAMPLE_NODEPOOLS)
    assert mapping["vm-001"]["name"] == "gpu-pool"
    assert mapping["vm-001"]["cluster_id"] == "cluster-abc"
    assert mapping["vm-001"]["node_labels"] == {
        "type": "a40",
        "crusoe.ai/nodepool.name": "gpu-pool",
    }


def test_build_cluster_names():
    names = build_cluster_names(SAMPLE_CLUSTERS)
    assert names["cluster-abc"] == "prod-cluster"


def _mock_run(data):
    m = MagicMock()
    m.returncode = 0
    m.stdout = json.dumps(data)
    return m


def test_get_vms_calls_crusoe_cli():
    with patch("crusoe.subprocess.run", return_value=_mock_run(SAMPLE_VMS)) as mock:  # noqa: E501
        result = get_vms()
        mock.assert_called_once_with(
            ["crusoe", "compute", "vms", "list", "--format", "json"],
            capture_output=True,
            text=True,
        )
        assert result == SAMPLE_VMS


def test_get_nodepools_calls_crusoe_cli():
    with patch(  # noqa: E501
        "crusoe.subprocess.run", return_value=_mock_run(SAMPLE_NODEPOOLS)
    ) as mock:
        result = get_nodepools()
        mock.assert_called_once_with(
            ["crusoe", "kubernetes", "nodepools", "list", "--format", "json"],
            capture_output=True,
            text=True,
        )
        assert result == SAMPLE_NODEPOOLS


def test_get_clusters_calls_crusoe_cli():
    with patch(
        "crusoe.subprocess.run", return_value=_mock_run(SAMPLE_CLUSTERS)
    ) as mock:
        result = get_clusters()
        mock.assert_called_once_with(
            ["crusoe", "kubernetes", "clusters", "list", "--format", "json"],
            capture_output=True,
            text=True,
        )
        assert result == SAMPLE_CLUSTERS


def test_load_cache_returns_none_when_missing(tmp_path):
    with patch("crusoe.CACHE_PATH", str(tmp_path / "inventory.json")):
        assert load_cache() is None


def test_save_and_load_cache(tmp_path):
    inventory = build_inventory(SAMPLE_VMS)
    cache_file = str(tmp_path / "inventory.json")
    with patch("crusoe.CACHE_PATH", cache_file):
        save_cache(inventory)
        result = load_cache()
    assert result == inventory


def test_load_cache_returns_none_when_expired(tmp_path):
    inventory = build_inventory(SAMPLE_VMS)
    cache_file = str(tmp_path / "inventory.json")
    with patch("crusoe.CACHE_PATH", cache_file):
        save_cache(inventory)
        expired_mtime = time.time() - CACHE_TTL - 1
        os.utime(cache_file, (expired_mtime, expired_mtime))
        assert load_cache() is None
