"""Prometheus metrics instrumentation for PatchPilot API."""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

# ─── HTTP Metrics ─────────────────────────────────────────────────────────────
http_requests_total = Counter(
    "patchpilot_http_requests_total",
    "Total HTTP requests",
    ["method", "path", "status"],
)

http_request_duration_seconds = Histogram(
    "patchpilot_http_request_duration_seconds",
    "HTTP request duration",
    ["method", "path"],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
)

# ─── Scan Metrics ─────────────────────────────────────────────────────────────
scans_total = Counter(
    "patchpilot_scans_total",
    "Total scans submitted",
    ["source_type", "status"],
)

scan_duration_seconds = Histogram(
    "patchpilot_scan_duration_seconds",
    "End-to-end scan duration",
    buckets=[1, 5, 10, 30, 60, 120, 300],
)

findings_total = Counter(
    "patchpilot_findings_total",
    "Total findings created",
    ["severity", "predicted_cwe"],
)

active_scans = Gauge(
    "patchpilot_active_scans",
    "Currently running scans",
)

# ─── LLM Metrics ──────────────────────────────────────────────────────────────
llm_requests_total = Counter(
    "patchpilot_llm_requests_total",
    "Total LLM API calls",
    ["provider", "operation", "status"],
)

llm_tokens_total = Counter(
    "patchpilot_llm_tokens_total",
    "Total LLM tokens consumed",
    ["provider", "direction"],
)

llm_cost_usd_total = Counter(
    "patchpilot_llm_cost_usd_total",
    "Total LLM cost in USD",
    ["provider"],
)

llm_latency_seconds = Histogram(
    "patchpilot_llm_latency_seconds",
    "LLM API call latency",
    ["provider", "operation"],
    buckets=[0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0],
)

# ─── ML Service Metrics ───────────────────────────────────────────────────────
ml_inference_duration_ms = Histogram(
    "patchpilot_ml_inference_duration_ms",
    "ML model inference latency",
    ["model"],
    buckets=[10, 25, 50, 100, 200, 500, 1000],
)

cache_hits_total = Counter(
    "patchpilot_cache_hits_total",
    "Redis cache hits",
    ["operation"],
)

cache_misses_total = Counter(
    "patchpilot_cache_misses_total",
    "Redis cache misses",
    ["operation"],
)

# ─── Patch Metrics ────────────────────────────────────────────────────────────
patches_total = Counter(
    "patchpilot_patches_total",
    "Total patches generated",
    ["verified", "attempt"],
)
