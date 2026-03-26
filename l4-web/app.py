import os
import threading
import time
from datetime import datetime, timezone

import requests
from flask import Flask, jsonify, render_template

app = Flask(__name__)

# Read-only HMI integration:
# l4-web only performs HTTP GET requests against HMI-facing status endpoints
# and republishes a sanitized summary for enterprise users.
HMI_STATUS_URLS = [
    url.strip()
    for url in os.getenv(
        "HMI_STATUS_URLS",
        "http://192.168.90.107:8080/api/status,http://192.168.90.107:8080/status",
    ).split(",")
    if url.strip()
]
POLL_INTERVAL_SECONDS = int(os.getenv("HMI_POLL_INTERVAL_SECONDS", "10"))
HTTP_TIMEOUT_SECONDS = float(os.getenv("HMI_HTTP_TIMEOUT_SECONDS", "3"))

status_cache = {
    "plant_status": "DEGRADED",
    "tank_level": 0.0,
    "pump_state": "UNKNOWN",
    "valve_state": "UNKNOWN",
    "alarm_count": 0,
    "last_update": datetime.now(timezone.utc).isoformat(),
    "source": "demo-fallback",
}
cache_lock = threading.Lock()


def _coerce_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _coerce_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def sanitize_status(raw_status):
    # Adapter layer: map best-effort HMI payload shapes into a strict
    # enterprise-safe summary schema.
    return {
        "plant_status": str(raw_status.get("plant_status", raw_status.get("status", "UNKNOWN"))),
        "tank_level": _coerce_float(raw_status.get("tank_level", raw_status.get("tankLevel", 0.0))),
        "pump_state": str(raw_status.get("pump_state", raw_status.get("pumpState", "UNKNOWN"))),
        "valve_state": str(raw_status.get("valve_state", raw_status.get("valveState", "UNKNOWN"))),
        "alarm_count": _coerce_int(raw_status.get("alarm_count", raw_status.get("alarmCount", 0))),
        "last_update": raw_status.get("last_update") or datetime.now(timezone.utc).isoformat(),
    }


def fetch_hmi_status():
    for url in HMI_STATUS_URLS:
        try:
            response = requests.get(url, timeout=HTTP_TIMEOUT_SECONDS)
            response.raise_for_status()
            payload = response.json()
            if isinstance(payload, dict):
                return sanitize_status(payload), url
        except (requests.RequestException, ValueError):
            continue
    return None, None


def poll_loop():
    while True:
        status, source_url = fetch_hmi_status()
        with cache_lock:
            if status:
                status_cache.update(status)
                status_cache["source"] = source_url
            else:
                # Demo-safe fallback when no deterministic HMI status endpoint is
                # available yet. Swap this once the exact HMI endpoint is finalized.
                status_cache.update(
                    {
                        "plant_status": "DEGRADED",
                        "tank_level": status_cache.get("tank_level", 73.5),
                        "pump_state": status_cache.get("pump_state", "RUNNING"),
                        "valve_state": status_cache.get("valve_state", "OPEN"),
                        "alarm_count": status_cache.get("alarm_count", 1),
                        "last_update": datetime.now(timezone.utc).isoformat(),
                        "source": "demo-fallback",
                    }
                )
        time.sleep(POLL_INTERVAL_SECONDS)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    with cache_lock:
        return jsonify(status_cache)


def start_background_polling():
    thread = threading.Thread(target=poll_loop, daemon=True)
    thread.start()


start_background_polling()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
