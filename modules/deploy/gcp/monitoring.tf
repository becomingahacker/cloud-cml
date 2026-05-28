#
# This file is part of Cisco Modeling Labs
# Copyright (c) 2019-2026, Cisco Systems, Inc.
# All rights reserved.
#

# CML custom metric descriptors for GCP Cloud Monitoring.
# These make the custom metrics discoverable in the Cloud Monitoring UI
# and document their schema. The exporter will write to these automatically
# via ADC on the controller VM.

locals {
  cml_metric_descriptors = {
    # Compute-level metrics
    "compute/cpu_percent" = {
      description  = "CPU utilization percentage for a CML compute host"
      display_name = "CML Compute CPU %"
      unit         = "%"
      labels = {
        compute_id = "CML compute host identifier"
        hostname   = "Compute host hostname"
      }
    }
    "compute/memory_used_bytes" = {
      description  = "Memory used in bytes on a CML compute host"
      display_name = "CML Compute Memory Used"
      unit         = "By"
      labels = {
        compute_id = "CML compute host identifier"
        hostname   = "Compute host hostname"
      }
    }
    "compute/memory_total_bytes" = {
      description  = "Total memory in bytes on a CML compute host"
      display_name = "CML Compute Memory Total"
      unit         = "By"
      labels = {
        compute_id = "CML compute host identifier"
        hostname   = "Compute host hostname"
      }
    }
    "compute/disk_used_bytes" = {
      description  = "Disk space used in bytes on a CML compute host"
      display_name = "CML Compute Disk Used"
      unit         = "By"
      labels = {
        compute_id = "CML compute host identifier"
        hostname   = "Compute host hostname"
      }
    }
    "compute/disk_total_bytes" = {
      description  = "Total disk space in bytes on a CML compute host"
      display_name = "CML Compute Disk Total"
      unit         = "By"
      labels = {
        compute_id = "CML compute host identifier"
        hostname   = "Compute host hostname"
      }
    }
    "compute/memory_percent" = {
      description  = "Memory utilization percentage for a CML compute host"
      display_name = "CML Compute Memory %"
      unit         = "%"
      labels = {
        compute_id = "CML compute host identifier"
        hostname   = "Compute host hostname"
      }
    }
    "compute/disk_percent" = {
      description  = "Disk utilization percentage for a CML compute host"
      display_name = "CML Compute Disk %"
      unit         = "%"
      labels = {
        compute_id = "CML compute host identifier"
        hostname   = "Compute host hostname"
      }
    }
    "cluster/computes_by_status" = {
      description  = "Number of CML compute hosts by health status"
      display_name = "CML Computes by Status"
      unit         = "1"
      labels = {
        status = "Health status (ready, not_ready)"
      }
    }
    "cluster/nodes_by_state" = {
      description  = "Total CML simulation nodes by lifecycle state"
      display_name = "CML Nodes by State"
      unit         = "1"
      labels = {
        state = "Node lifecycle state (booted, started, stopped, defined_on_core, queued)"
      }
    }
    "cluster/labs_by_state" = {
      description  = "Number of CML labs by lifecycle state"
      display_name = "CML Labs by State"
      unit         = "1"
      labels = {
        state = "Lab lifecycle state (defined_on_core, stopped, started, booted, queued)"
      }
    }
    "compute/vm_running_count" = {
      description  = "Number of running VMs on a CML compute host"
      display_name = "CML Running VMs"
      unit         = "1"
      labels = {
        compute_id = "CML compute host identifier"
        hostname   = "Compute host hostname"
      }
    }
    "compute/vm_total_count" = {
      description  = "Total number of VMs on a CML compute host"
      display_name = "CML Total VMs"
      unit         = "1"
      labels = {
        compute_id = "CML compute host identifier"
        hostname   = "Compute host hostname"
      }
    }

    # Cluster aggregate metrics
    "cluster/cpu_percent" = {
      description  = "Aggregate CPU utilization across all CML compute hosts"
      display_name = "CML Cluster CPU %"
      unit         = "%"
      labels       = {}
    }
    "cluster/memory_used_bytes" = {
      description  = "Aggregate memory used across all CML compute hosts"
      display_name = "CML Cluster Memory Used"
      unit         = "By"
      labels       = {}
    }
    "cluster/memory_total_bytes" = {
      description  = "Aggregate total memory across all CML compute hosts"
      display_name = "CML Cluster Memory Total"
      unit         = "By"
      labels       = {}
    }

    # Health metrics
    "health/ready" = {
      description  = "Whether a CML compute host is ready (1) or not (0)"
      display_name = "CML Compute Ready"
      unit         = "1"
      labels = {
        compute_id = "CML compute host identifier"
      }
    }
    "health/overloaded" = {
      description  = "Whether a CML compute host is overloaded (1) or not (0)"
      display_name = "CML Compute Overloaded"
      unit         = "1"
      labels = {
        compute_id = "CML compute host identifier"
      }
    }

    # Lab-level metrics
    "lab/state" = {
      description  = "Lab state as numeric enum (0=DEFINED, 1=STOPPED, 2=STARTED, 3=BOOTED)"
      display_name = "CML Lab State"
      unit         = "1"
      labels = {
        lab_id     = "CML lab identifier"
        lab_title  = "Lab title (e.g. POD31-BLUE)"
        pod_number = "Pod number derived from lab title"
        color      = "Lab color (blue, red, isp)"
      }
    }
    "lab/nodes_total" = {
      description  = "Total number of nodes in a CML lab"
      display_name = "CML Lab Nodes Total"
      unit         = "1"
      labels = {
        lab_id     = "CML lab identifier"
        lab_title  = "Lab title"
        pod_number = "Pod number"
        color      = "Lab color"
      }
    }
    "lab/nodes_booted" = {
      description  = "Number of nodes in BOOTED/STARTED state in a CML lab"
      display_name = "CML Lab Nodes Booted"
      unit         = "1"
      labels = {
        lab_id     = "CML lab identifier"
        lab_title  = "Lab title"
        pod_number = "Pod number"
        color      = "Lab color"
      }
    }
    "lab/nodes_stopped" = {
      description  = "Number of nodes in STOPPED/DEFINED state in a CML lab"
      display_name = "CML Lab Nodes Stopped"
      unit         = "1"
      labels = {
        lab_id     = "CML lab identifier"
        lab_title  = "Lab title"
        pod_number = "Pod number"
        color      = "Lab color"
      }
    }

    # Per-node simulation metrics
    "node/state" = {
      description  = "Node state as numeric enum (0=DEFINED, 1=STOPPED, 2=STARTED, 3=BOOTED)"
      display_name = "CML Node State"
      unit         = "1"
      labels = {
        lab_id          = "CML lab identifier"
        pod_number      = "Pod number"
        color           = "Lab color"
        node_id         = "CML node identifier"
        node_label      = "Node label (e.g. edge-rtr)"
        node_definition = "Node definition type (e.g. c8000v)"
      }
    }
    "node/cpu_percent" = {
      description  = "CPU utilization of an individual CML lab node VM"
      display_name = "CML Node CPU %"
      unit         = "%"
      labels = {
        lab_id          = "CML lab identifier"
        pod_number      = "Pod number"
        color           = "Lab color"
        node_id         = "CML node identifier"
        node_label      = "Node label"
        node_definition = "Node definition type"
      }
    }
    "node/memory_used_bytes" = {
      description  = "Memory used by an individual CML lab node VM"
      display_name = "CML Node Memory Used"
      unit         = "By"
      labels = {
        lab_id          = "CML lab identifier"
        pod_number      = "Pod number"
        color           = "Lab color"
        node_id         = "CML node identifier"
        node_label      = "Node label"
        node_definition = "Node definition type"
      }
    }
    "node/disk_read_bytes" = {
      description  = "Cumulative bytes read from disk by a CML lab node VM"
      display_name = "CML Node Disk Read"
      unit         = "By"
      labels = {
        lab_id          = "CML lab identifier"
        pod_number      = "Pod number"
        color           = "Lab color"
        node_id         = "CML node identifier"
        node_label      = "Node label"
        node_definition = "Node definition type"
      }
    }
    "node/disk_write_bytes" = {
      description  = "Cumulative bytes written to disk by a CML lab node VM"
      display_name = "CML Node Disk Write"
      unit         = "By"
      labels = {
        lab_id          = "CML lab identifier"
        pod_number      = "Pod number"
        color           = "Lab color"
        node_id         = "CML node identifier"
        node_label      = "Node label"
        node_definition = "Node definition type"
      }
    }
  }
}

resource "google_monitoring_metric_descriptor" "cml" {
  for_each = local.cml_metric_descriptors

  project      = var.options.cfg.gcp.project
  description  = each.value.description
  display_name = each.value.display_name
  type         = "custom.googleapis.com/cml/${each.key}"
  metric_kind  = "GAUGE"
  value_type   = "DOUBLE"
  unit         = each.value.unit

  dynamic "labels" {
    for_each = each.value.labels
    content {
      key         = labels.key
      description = labels.value
      value_type  = "STRING"
    }
  }
}

# --- Dashboard ---

resource "google_monitoring_dashboard" "cml" {
  project = var.options.cfg.gcp.project

  lifecycle {
    ignore_changes = [dashboard_json]
  }

  dashboard_json = jsonencode({
    displayName = "CML Cluster Overview"
    gridLayout = {
      columns = 3
      widgets = [
        # Row 1: Status overview (pie charts)
        {
          title = "Compute Health"
          pieChart = {
            dataSets = [{
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "metric.type=\"custom.googleapis.com/cml/cluster/computes_by_status\""
                  aggregation = {
                    alignmentPeriod  = "60s"
                    perSeriesAligner = "ALIGN_MAX"
                  }
                }
              }
              minAlignmentPeriod = "60s"
            }]
            chartType = "DONUT"
          }
        },
        {
          title = "Lab State"
          pieChart = {
            dataSets = [{
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "metric.type=\"custom.googleapis.com/cml/cluster/labs_by_state\""
                  aggregation = {
                    alignmentPeriod  = "60s"
                    perSeriesAligner = "ALIGN_MAX"
                  }
                }
              }
              minAlignmentPeriod = "60s"
            }]
            chartType = "DONUT"
          }
        },
        {
          title = "Node State"
          pieChart = {
            dataSets = [{
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "metric.type=\"custom.googleapis.com/cml/cluster/nodes_by_state\""
                  aggregation = {
                    alignmentPeriod  = "60s"
                    perSeriesAligner = "ALIGN_MAX"
                  }
                }
              }
              minAlignmentPeriod = "60s"
            }]
            chartType = "DONUT"
          }
        },
        # Row 2: Cluster-wide resource utilization
        {
          title = "Cluster CPU"
          xyChart = {
            dataSets = [{
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "metric.type=\"custom.googleapis.com/cml/cluster/cpu_percent\""
                }
              }
              plotType = "LINE"
            }]
            yAxis = { label = "%" }
          }
        },
        {
          title = "Cluster Memory"
          xyChart = {
            dataSets = [
              {
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "metric.type=\"custom.googleapis.com/cml/cluster/memory_used_bytes\""
                  }
                }
                plotType = "LINE"
              },
              {
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "metric.type=\"custom.googleapis.com/cml/cluster/memory_total_bytes\""
                  }
                }
                plotType = "LINE"
              },
            ]
            yAxis = { label = "bytes" }
          }
        },
        # Row 3: Per-compute breakdown
        {
          title = "Per-Compute CPU"
          xyChart = {
            dataSets = [{
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "metric.type=\"custom.googleapis.com/cml/compute/cpu_percent\""
                }
              }
              plotType = "LINE"
            }]
            yAxis = { label = "%" }
          }
        },
        {
          title = "Running VMs per Compute"
          xyChart = {
            dataSets = [{
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "metric.type=\"custom.googleapis.com/cml/compute/vm_running_count\""
                }
              }
              plotType = "STACKED_AREA"
            }]
            yAxis = { label = "VMs" }
          }
        },
        # Row 4: Lab and storage
        {
          title = "Nodes Booted by Pod"
          xyChart = {
            dataSets = [{
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "metric.type=\"custom.googleapis.com/cml/lab/nodes_booted\""
                }
              }
              plotType = "STACKED_AREA"
            }]
            yAxis = { label = "nodes" }
          }
        },
        {
          title = "Per-Compute Disk"
          xyChart = {
            dataSets = [{
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "metric.type=\"custom.googleapis.com/cml/compute/disk_used_bytes\""
                }
              }
              plotType = "LINE"
            }]
            yAxis = { label = "bytes" }
          }
        },
        {
          title = "Per-Compute Memory"
          xyChart = {
            dataSets = [{
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "metric.type=\"custom.googleapis.com/cml/compute/memory_used_bytes\""
                }
              }
              plotType = "LINE"
            }]
            yAxis = { label = "bytes" }
          }
        },
      ]
    }
  })
}

# --- Alert Policies ---

resource "google_monitoring_alert_policy" "cml_compute_memory_high" {
  project      = var.options.cfg.gcp.project
  display_name = "CML Compute Memory > 90%"
  combiner     = "OR"

  conditions {
    display_name = "Memory utilization above 90%"
    condition_threshold {
      filter          = "metric.type=\"custom.googleapis.com/cml/compute/memory_percent\" AND resource.type=\"gce_instance\""
      comparison      = "COMPARISON_GT"
      threshold_value = 90
      duration        = "300s"
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }

  notification_channels = []
  enabled               = true
}

resource "google_monitoring_alert_policy" "cml_compute_not_ready" {
  project      = var.options.cfg.gcp.project
  display_name = "CML Compute Not Ready"
  combiner     = "OR"

  conditions {
    display_name = "Compute host not ready"
    condition_threshold {
      filter          = "metric.type=\"custom.googleapis.com/cml/health/ready\" AND resource.type=\"gce_instance\""
      comparison      = "COMPARISON_LT"
      threshold_value = 1
      duration        = "300s"
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }

  notification_channels = []
  enabled               = true
}

resource "google_monitoring_alert_policy" "cml_cluster_cpu_high" {
  project      = var.options.cfg.gcp.project
  display_name = "CML Cluster CPU > 80%"
  combiner     = "OR"

  conditions {
    display_name = "Cluster CPU sustained above 80%"
    condition_threshold {
      filter          = "metric.type=\"custom.googleapis.com/cml/cluster/cpu_percent\" AND resource.type=\"gce_instance\""
      comparison      = "COMPARISON_GT"
      threshold_value = 80
      duration        = "600s"
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }

  notification_channels = []
  enabled               = true
}

resource "google_monitoring_alert_policy" "cml_compute_disk_high" {
  project      = var.options.cfg.gcp.project
  display_name = "CML Compute Disk > 85%"
  combiner     = "OR"

  conditions {
    display_name = "Disk utilization above 85%"
    condition_threshold {
      filter          = "metric.type=\"custom.googleapis.com/cml/compute/disk_percent\" AND resource.type=\"gce_instance\""
      comparison      = "COMPARISON_GT"
      threshold_value = 85
      duration        = "300s"
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }

  notification_channels = []
  enabled               = true
}
