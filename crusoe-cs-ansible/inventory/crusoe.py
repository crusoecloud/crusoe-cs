#!/usr/bin/env python3

import argparse
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

CACHE_TTL = 120  # seconds
CACHE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), ".cache", "inventory.json"
)


def _slugify(value):
    return value.lower().replace("-", "_").replace(" ", "_")


def _run_crusoe(args):
    result = subprocess.run(
        ["crusoe"] + args + ["--format", "json"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        return []
    return json.loads(result.stdout)


def get_vms():
    return _run_crusoe(["compute", "vms", "list"])


def get_nodepools():
    return _run_crusoe(["kubernetes", "nodepools", "list"])


def get_clusters():
    return _run_crusoe(["kubernetes", "clusters", "list"])


def load_cache():
    try:
        age = time.time() - os.path.getmtime(CACHE_PATH)
        if age < CACHE_TTL:
            with open(CACHE_PATH) as f:
                return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass
    return None


def save_cache(inventory):
    os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
    with open(CACHE_PATH, "w") as f:
        json.dump(inventory, f)


def build_vm_to_nodepool(nodepools):
    mapping = {}
    for np in nodepools:
        for vm_id in np.get("instance_ids", []):
            mapping[vm_id] = {
                "name": np.get("name", ""),
                "cluster_id": np.get("cluster_id", ""),
                "node_labels": np.get("node_labels", {}),
            }
    return mapping


def build_cluster_names(clusters):
    return {
        c["id"]: c.get("name", c["id"][:8])
        for c in clusters
        if "id" in c
    }


def build_inventory(vms, vm_to_nodepool=None, cluster_names=None):
    vm_to_nodepool = vm_to_nodepool or {}
    cluster_names = cluster_names or {}

    inventory = {
        "_meta": {"hostvars": {}},
        "all": {"hosts": []},
    }
    groups = {}

    for vm in vms:
        state = vm.get("state")
        if state is not None and state != "STATE_RUNNING":
            continue

        name = vm["name"]

        private_ip = None
        public_ip = None
        for iface in vm.get("network_interfaces", []):
            for ip_entry in iface.get("ips", []):
                if not private_ip:
                    private_ip = ip_entry.get("private_ipv4", {}).get("address")
                if not public_ip:
                    public_ip = ip_entry.get("public_ipv4", {}).get("address")
            if private_ip and public_ip:
                break

        ansible_host = public_ip or private_ip
        if not ansible_host:
            continue

        raw_project = vm.get("project_id", "unknown")
        project = _slugify(raw_project)
        instance_type = vm.get("type", "unknown").split(".")[0].lower()
        # Strip AZ suffix: "eu-iceland1-a" -> "eu-iceland1"
        raw_location = vm.get("location", "unknown")
        region = _slugify(raw_location.rsplit("-", 1)[0])

        group_memberships = [
            (f"project_{project}", name),
            (f"type_{instance_type}", name),
            (f"region_{region}", name),
        ]

        np_info = vm_to_nodepool.get(vm.get("id", ""))
        nodepool_name = ""
        cluster_name = ""
        if np_info:
            nodepool_name = _slugify(np_info["name"])
            fallback = np_info["cluster_id"][:8]
            cluster_name = _slugify(
                cluster_names.get(np_info["cluster_id"], fallback)
            )
            group_memberships += [
                (f"nodepool_{nodepool_name}", name),
                (f"k8s_{cluster_name}", name),
            ]

        for group, value in group_memberships:
            groups.setdefault(group, {"hosts": []})["hosts"].append(value)

        inventory["all"]["hosts"].append(name)
        inventory["_meta"]["hostvars"][name] = {
            "ansible_host": ansible_host,
            "crusoe_private_ip": private_ip or "",
            "crusoe_public_ip": public_ip or "",
            "crusoe_project": project,
            "crusoe_type": vm.get("type"),
            "crusoe_location": raw_location,
            "crusoe_nodepool": nodepool_name,
            "crusoe_cluster": cluster_name,
            "crusoe_node_labels": (
                np_info.get("node_labels", {}) if np_info else {}
            ),
        }

    inventory.update(groups)
    return inventory


def main():
    parser = argparse.ArgumentParser(
        description="Crusoe Cloud dynamic inventory"
    )
    parser.add_argument("--list", action="store_true", dest="list_hosts")
    parser.add_argument("--host", type=str)
    parser.add_argument(
        "--refresh", action="store_true", help="Bypass cache and fetch fresh"
    )
    args = parser.parse_args()

    if args.list_hosts:
        if not args.refresh:
            cached = load_cache()
            if cached is not None:
                print(json.dumps(cached, indent=2))
                return

        with ThreadPoolExecutor(max_workers=3) as executor:
            f_vms = executor.submit(get_vms)
            f_nodepools = executor.submit(get_nodepools)
            f_clusters = executor.submit(get_clusters)
        vms = f_vms.result()
        nodepools = f_nodepools.result()
        clusters = f_clusters.result()
        vm_to_nodepool = build_vm_to_nodepool(nodepools)
        cluster_names = build_cluster_names(clusters)
        inventory = build_inventory(vms, vm_to_nodepool, cluster_names)
        save_cache(inventory)
        print(json.dumps(inventory, indent=2))
    elif args.host:
        print(json.dumps({}))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
