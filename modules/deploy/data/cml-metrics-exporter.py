#!/usr/bin/env python3
"""
CML Metrics Exporter for GCP Cloud Monitoring.

Polls the CML REST API on localhost and writes custom metrics to
Google Cloud Monitoring using Application Default Credentials
(from the GCE metadata server).

Designed to run as a systemd oneshot service triggered by a 60s timer.
"""

import json
import logging
import re
import sys
import time
import urllib.request
import urllib.error
import ssl

from pathlib import Path

import yaml

try:
    from google.cloud import monitoring_v3
    from google.cloud import secretmanager
    from google.api import metric_pb2, monitored_resource_pb2
    from google.protobuf import timestamp_pb2
except ImportError:
    print("ERROR: google-cloud-monitoring or google-cloud-secret-manager package not installed", file=sys.stderr)
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("cml-metrics-exporter")

METRIC_PREFIX = "custom.googleapis.com/cml"
CML_BASE_URL = "https://localhost/api/v0"
LAB_TITLE_RE = re.compile(r"POD(\d+)-(BLUE|RED)$", re.IGNORECASE)

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE


def get_metadata(path: str) -> str:
    url = f"http://metadata.google.internal/computeMetadata/v1/{path}"
    req = urllib.request.Request(url, headers={"Metadata-Flavor": "Google"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.read().decode().strip()


def get_project_id() -> str:
    return get_metadata("project/project-id")


def get_instance_id() -> str:
    return get_metadata("instance/id")


def get_zone() -> str:
    zone_path = get_metadata("instance/zone")
    return zone_path.split("/")[-1]


def get_secret(project_id: str, secret_id: str) -> str:
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"
    response = client.access_secret_version(request={"name": name})
    return response.payload.data.decode("utf-8")


def load_cml_credentials(project_id: str) -> tuple[str, str]:
    cfg_path = Path("/etc/virl2-base-config.yml")
    with cfg_path.open() as f:
        cfg = yaml.safe_load(f)

    admins = cfg.get("admins", {})
    controller = admins.get("controller", {})
    username = controller.get("username") or cfg.get("sys_admin_username", "admin")

    password = get_secret(project_id, "cml-admin-password")
    return username, password


def cml_authenticate(username: str, password: str) -> str:
    data = json.dumps({"username": username, "password": password}).encode()
    req = urllib.request.Request(
        f"{CML_BASE_URL}/authenticate",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, context=ssl_ctx, timeout=30) as resp:
        token = json.loads(resp.read())
    return token


def cml_get(endpoint: str, token: str) -> dict:
    url = f"{CML_BASE_URL}{endpoint}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, context=ssl_ctx, timeout=60) as resp:
        return json.loads(resp.read())


def parse_lab_title(title: str) -> tuple[str, str]:
    m = LAB_TITLE_RE.search(title)
    if m:
        return m.group(1), m.group(2).lower()
    if title.upper().endswith("ISP"):
        return "0", "isp"
    return "0", "unknown"


def build_time_series(
    project_id: str,
    metric_type: str,
    value: float,
    labels: dict,
    resource_labels: dict,
    now: timestamp_pb2.Timestamp,
) -> monitoring_v3.TimeSeries:
    series = monitoring_v3.TimeSeries()
    series.metric.type = f"{METRIC_PREFIX}/{metric_type}"
    for k, v in labels.items():
        series.metric.labels[k] = str(v)
    series.resource.type = "gce_instance"
    for k, v in resource_labels.items():
        series.resource.labels[k] = str(v)

    point = monitoring_v3.Point()
    point.interval.end_time = now
    point.value.double_value = float(value)
    series.points = [point]
    return series


def collect_compute_metrics(
    system_stats: dict, resource_labels: dict, now: timestamp_pb2.Timestamp, project_id: str
) -> list:
    series_list = []
    computes = system_stats.get("computes", {})

    for compute_id, info in computes.items():
        stats = info.get("stats", {})
        hostname = info.get("hostname", compute_id)
        labels = {"compute_id": hostname, "hostname": hostname}

        cpu = stats.get("cpu", {})
        if cpu.get("percent") is not None:
            series_list.append(build_time_series(
                project_id, "compute/cpu_percent", cpu["percent"],
                labels, resource_labels, now,
            ))

        mem = stats.get("memory", {})
        if mem.get("used") is not None:
            series_list.append(build_time_series(
                project_id, "compute/memory_used_bytes", mem["used"],
                labels, resource_labels, now,
            ))
        if mem.get("total") is not None:
            series_list.append(build_time_series(
                project_id, "compute/memory_total_bytes", mem["total"],
                labels, resource_labels, now,
            ))
        if mem.get("used") is not None and mem.get("total"):
            series_list.append(build_time_series(
                project_id, "compute/memory_percent",
                100.0 * mem["used"] / mem["total"],
                labels, resource_labels, now,
            ))

        disk = stats.get("disk", {})
        if disk.get("used") is not None:
            series_list.append(build_time_series(
                project_id, "compute/disk_used_bytes", disk["used"],
                labels, resource_labels, now,
            ))
        if disk.get("total") is not None:
            series_list.append(build_time_series(
                project_id, "compute/disk_total_bytes", disk["total"],
                labels, resource_labels, now,
            ))
        if disk.get("used") is not None and disk.get("total"):
            series_list.append(build_time_series(
                project_id, "compute/disk_percent",
                100.0 * disk["used"] / disk["total"],
                labels, resource_labels, now,
            ))

        dominfo = stats.get("dominfo", {})
        if dominfo.get("running_nodes") is not None:
            series_list.append(build_time_series(
                project_id, "compute/vm_running_count", dominfo["running_nodes"],
                labels, resource_labels, now,
            ))
        if dominfo.get("total_nodes") is not None:
            series_list.append(build_time_series(
                project_id, "compute/vm_total_count", dominfo["total_nodes"],
                labels, resource_labels, now,
            ))

    agg = system_stats.get("all", {})
    if agg:
        agg_cpu = agg.get("cpu", {})
        if agg_cpu.get("percent") is not None:
            series_list.append(build_time_series(
                project_id, "cluster/cpu_percent", agg_cpu["percent"],
                {}, resource_labels, now,
            ))
        agg_mem = agg.get("memory", {})
        if agg_mem.get("used") is not None:
            series_list.append(build_time_series(
                project_id, "cluster/memory_used_bytes", agg_mem["used"],
                {}, resource_labels, now,
            ))
        if agg_mem.get("total") is not None:
            series_list.append(build_time_series(
                project_id, "cluster/memory_total_bytes", agg_mem["total"],
                {}, resource_labels, now,
            ))

    return series_list


def collect_health_metrics(
    system_health: dict, resource_labels: dict, now: timestamp_pb2.Timestamp, project_id: str
) -> list:
    series_list = []
    computes = system_health.get("computes", {})
    ready_count = 0
    not_ready_count = 0
    for compute_id, health in computes.items():
        hostname = health.get("hostname", compute_id)
        labels = {"compute_id": hostname}
        is_ready = health.get("admission_state") == "READY" and health.get("valid", False)
        ready = 1.0 if is_ready else 0.0
        series_list.append(build_time_series(
            project_id, "health/ready", ready, labels, resource_labels, now,
        ))
        overloaded = 1.0 if any(health.get(k, False) for k in ("cpu_overload", "memory_overload", "disk_overload")) else 0.0
        series_list.append(build_time_series(
            project_id, "health/overloaded", overloaded, labels, resource_labels, now,
        ))
        if is_ready:
            ready_count += 1
        else:
            not_ready_count += 1

    series_list.append(build_time_series(
        project_id, "cluster/computes_by_status", ready_count,
        {"status": "ready"}, resource_labels, now,
    ))
    series_list.append(build_time_series(
        project_id, "cluster/computes_by_status", not_ready_count,
        {"status": "not_ready"}, resource_labels, now,
    ))
    return series_list


LAB_STATE_MAP = {
    "DEFINED_ON_CORE": 0,
    "STOPPED": 1,
    "STARTED": 2,
    "BOOTED": 3,
    "QUEUED": 4,
}


def collect_lab_metrics(
    labs: dict, resource_labels: dict, now: timestamp_pb2.Timestamp, project_id: str
) -> list:
    series_list = []
    lab_state_counts = {s: 0 for s in LAB_STATE_MAP}
    for lab_id, lab_data in labs.items():
        title = lab_data.get("lab_title", "")
        pod_number, color = parse_lab_title(title)
        state_str = lab_data.get("state", "STOPPED")
        state_val = LAB_STATE_MAP.get(state_str, 0)
        labels = {
            "lab_id": lab_id,
            "lab_title": title,
            "pod_number": pod_number,
            "color": color,
        }

        series_list.append(build_time_series(
            project_id, "lab/state", state_val, labels, resource_labels, now,
        ))

        node_count = lab_data.get("node_count", 0)
        series_list.append(build_time_series(
            project_id, "lab/nodes_total", node_count, labels, resource_labels, now,
        ))

        if state_str in lab_state_counts:
            lab_state_counts[state_str] += 1

    for state_name, count in lab_state_counts.items():
        series_list.append(build_time_series(
            project_id, "cluster/labs_by_state", count,
            {"state": state_name.lower()}, resource_labels, now,
        ))

    return series_list


NODE_STATE_MAP = {
    "DEFINED_ON_CORE": 0,
    "STOPPED": 1,
    "STARTED": 2,
    "BOOTED": 3,
    "QUEUED": 4,
}


def collect_node_metrics(
    token: str,
    labs: dict,
    resource_labels: dict,
    now: timestamp_pb2.Timestamp,
    project_id: str,
) -> list:
    series_list = []
    global_state_counts = {"BOOTED": 0, "STARTED": 0, "STOPPED": 0, "DEFINED_ON_CORE": 0, "QUEUED": 0}

    for lab_id, lab_data in labs.items():
        state_str = lab_data.get("state", "STOPPED")
        if state_str not in ("STARTED", "BOOTED"):
            global_state_counts["STOPPED"] += lab_data.get("node_count", 0)
            continue

        title = lab_data.get("lab_title", "")
        pod_number, color = parse_lab_title(title)

        try:
            nodes = cml_get(f"/labs/{lab_id}/nodes?data=true", token)
        except Exception as e:
            log.warning("Failed to get nodes for lab %s: %s", lab_id, e)
            continue

        if isinstance(nodes, list):
            node_iter = {n.get("id", str(i)): n for i, n in enumerate(nodes)}
        elif isinstance(nodes, dict):
            node_iter = nodes
        else:
            continue

        booted = 0
        stopped = 0

        for node_id, node_data in node_iter.items():
            if not isinstance(node_data, dict):
                continue
            node_state = node_data.get("state", "STOPPED")
            node_label = node_data.get("label", node_id)
            node_def = node_data.get("node_definition", "unknown")

            if node_state in ("BOOTED", "STARTED"):
                booted += 1
            elif node_state in ("STOPPED", "DEFINED_ON_CORE"):
                stopped += 1

            if node_state in global_state_counts:
                global_state_counts[node_state] += 1

            labels = {
                "lab_id": lab_id,
                "pod_number": pod_number,
                "color": color,
                "node_id": str(node_id),
                "node_label": node_label,
                "node_definition": node_def,
            }

            state_val = NODE_STATE_MAP.get(node_state, 0)
            series_list.append(build_time_series(
                project_id, "node/state", state_val, labels, resource_labels, now,
            ))

            if node_state not in ("BOOTED", "STARTED"):
                continue

            cpu_usage = node_data.get("cpu_usage")
            if cpu_usage is not None:
                series_list.append(build_time_series(
                    project_id, "node/cpu_percent", cpu_usage, labels, resource_labels, now,
                ))

            ram_usage = node_data.get("ram")
            if ram_usage is not None:
                series_list.append(build_time_series(
                    project_id, "node/memory_used_bytes", ram_usage, labels, resource_labels, now,
                ))

            disk_read = node_data.get("data_read")
            if disk_read is not None:
                series_list.append(build_time_series(
                    project_id, "node/disk_read_bytes", disk_read, labels, resource_labels, now,
                ))

            disk_write = node_data.get("data_written")
            if disk_write is not None:
                series_list.append(build_time_series(
                    project_id, "node/disk_write_bytes", disk_write, labels, resource_labels, now,
                ))

        lab_labels = {
            "lab_id": lab_id,
            "lab_title": title,
            "pod_number": pod_number,
            "color": color,
        }
        series_list.append(build_time_series(
            project_id, "lab/nodes_booted", booted, lab_labels, resource_labels, now,
        ))
        series_list.append(build_time_series(
            project_id, "lab/nodes_stopped", stopped, lab_labels, resource_labels, now,
        ))

    for state_name, count in global_state_counts.items():
        series_list.append(build_time_series(
            project_id, "cluster/nodes_by_state", count,
            {"state": state_name.lower()}, resource_labels, now,
        ))

    return series_list


def write_time_series(client: monitoring_v3.MetricServiceClient, project_id: str, series_list: list):
    if not series_list:
        return
    project_name = f"projects/{project_id}"
    batch_size = 200
    for i in range(0, len(series_list), batch_size):
        batch = series_list[i : i + batch_size]
        try:
            client.create_time_series(name=project_name, time_series=batch)
            log.info("Wrote %d time series (batch %d)", len(batch), i // batch_size + 1)
        except Exception as e:
            log.error("Failed to write batch %d: %s", i // batch_size + 1, e)


def main():
    try:
        project_id = get_project_id()
        instance_id = get_instance_id()
        zone = get_zone()
    except Exception as e:
        log.error("Failed to get GCE metadata: %s", e)
        sys.exit(1)

    resource_labels = {
        "project_id": project_id,
        "instance_id": instance_id,
        "zone": zone,
    }

    try:
        username, password = load_cml_credentials(project_id)
    except Exception as e:
        log.error("Failed to load CML credentials: %s", e)
        sys.exit(1)

    try:
        token = cml_authenticate(username, password)
    except Exception as e:
        log.error("CML authentication failed: %s", e)
        sys.exit(1)

    now = timestamp_pb2.Timestamp()
    now.FromSeconds(int(time.time()))

    all_series = []

    try:
        system_stats = cml_get("/system_stats", token)
        all_series.extend(collect_compute_metrics(system_stats, resource_labels, now, project_id))
    except Exception as e:
        log.error("Failed to collect system_stats: %s", e)

    try:
        system_health = cml_get("/system_health", token)
        all_series.extend(collect_health_metrics(system_health, resource_labels, now, project_id))
    except Exception as e:
        log.error("Failed to collect system_health: %s", e)

    labs = {}
    try:
        labs = cml_get("/labs?with_data=true", token)
        if isinstance(labs, list):
            labs = {lab.get("id", str(i)): lab for i, lab in enumerate(labs)}
        all_series.extend(collect_lab_metrics(labs, resource_labels, now, project_id))
    except Exception as e:
        log.error("Failed to collect lab metrics: %s", e)

    try:
        all_series.extend(collect_node_metrics(token, labs, resource_labels, now, project_id))
    except Exception as e:
        log.error("Failed to collect node metrics: %s", e)

    log.info("Collected %d total time series", len(all_series))

    if all_series:
        client = monitoring_v3.MetricServiceClient()
        write_time_series(client, project_id, all_series)

    log.info("Export complete")


if __name__ == "__main__":
    main()
