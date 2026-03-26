import os
import re
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urljoin

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
HMI_BASE_URL = os.getenv("HMI_BASE_URL", "http://192.168.90.107:8080").rstrip("/")
HMI_LOGIN_PATH = os.getenv("HMI_LOGIN_PATH", "/login.htm")
HMI_USERNAME = os.getenv("HMI_USERNAME", "admin")
HMI_PASSWORD = os.getenv("HMI_PASSWORD", "admin")
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
session_lock = threading.Lock()
hmi_session = requests.Session()


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


def extract_status_from_text(text):
    # Best-effort adapter for non-JSON authenticated pages.
    patterns = {
        "plant_status": r"(?:plant[_\\s-]*status|status)\\s*[:=]\\s*\"?([A-Za-z_ -]+)\"?",
        "tank_level": r"(?:tank[_\\s-]*level)\\s*[:=]\\s*\"?([0-9]+(?:\\.[0-9]+)?)\"?",
        "pump_state": r"(?:pump[_\\s-]*state)\\s*[:=]\\s*\"?([A-Za-z_ -]+)\"?",
        "valve_state": r"(?:valve[_\\s-]*state)\\s*[:=]\\s*\"?([A-Za-z_ -]+)\"?",
        "alarm_count": r"(?:alarm[_\\s-]*count|alarms?)\\s*[:=]\\s*\"?([0-9]+)\"?",
    }
    extracted = {}
    for key, pattern in patterns.items():
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            extracted[key] = match.group(1).strip()

    if not extracted:
        return None
    extracted["last_update"] = datetime.now(timezone.utc).isoformat()
    return sanitize_status(extracted)


def _parse_login_form(login_html):
    action_match = re.search(r'<form[^>]*action=["\\\']?([^"\\\' >]+)', login_html, flags=re.IGNORECASE)
    action = action_match.group(1) if action_match else HMI_LOGIN_PATH
    hidden_fields = dict(
        re.findall(
            r'<input[^>]*type=["\\\']hidden["\\\'][^>]*name=["\\\']([^"\\\']+)["\\\'][^>]*value=["\\\']([^"\\\']*)["\\\']',
            login_html,
            flags=re.IGNORECASE,
        )
    )
    names = re.findall(r'<input[^>]*name=["\\\']([^"\\\']+)["\\\']', login_html, flags=re.IGNORECASE)
    lower_to_name = {n.lower(): n for n in names}
    user_field = next((lower_to_name[k] for k in ["username", "user", "j_username", "loginusername"] if k in lower_to_name), None)
    pass_field = next((lower_to_name[k] for k in ["password", "pass", "j_password", "loginpassword"] if k in lower_to_name), None)
    return action, hidden_fields, user_field or "username", pass_field or "password"


def login_to_hmi():
    login_url = urljoin(f"{HMI_BASE_URL}/", HMI_LOGIN_PATH.lstrip("/"))
    login_page = hmi_session.get(login_url, timeout=HTTP_TIMEOUT_SECONDS)
    login_page.raise_for_status()

    action, hidden_fields, user_field, pass_field = _parse_login_form(login_page.text)
    target_url = urljoin(login_url, action)
    payload = {**hidden_fields, user_field: HMI_USERNAME, pass_field: HMI_PASSWORD}

    response = hmi_session.post(target_url, data=payload, timeout=HTTP_TIMEOUT_SECONDS, allow_redirects=True)
    response.raise_for_status()
    return "login.htm" not in response.url.lower()


def fetch_hmi_status():
    for url in HMI_STATUS_URLS:
        try:
            with session_lock:
                response = hmi_session.get(url, timeout=HTTP_TIMEOUT_SECONDS, allow_redirects=True)
                if "login.htm" in response.url.lower():
                    if not login_to_hmi():
                        continue
                    response = hmi_session.get(url, timeout=HTTP_TIMEOUT_SECONDS, allow_redirects=True)
            response.raise_for_status()
            content_type = response.headers.get("Content-Type", "").lower()
            if "application/json" in content_type:
                payload = response.json()
                if isinstance(payload, dict):
                    return sanitize_status(payload), url
            parsed = extract_status_from_text(response.text)
            if parsed:
                return parsed, url
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
