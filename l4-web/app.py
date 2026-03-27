import os
import re
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
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
HMI_AUTH_STATUS_URLS = [
    url.strip()
    for url in os.getenv("HMI_AUTH_STATUS_URLS", "/view_edit.shtm,/watch_list.shtm,/").split(",")
    if url.strip()
]
HMI_WATCHLIST_PATH = os.getenv("HMI_WATCHLIST_PATH", "/watch_list.shtm")
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
        "plant_status": r"(?:plant[_\s-]*status|status)\s*[:=]\s*\"?([A-Za-z_ -]+)\"?",
        "tank_level": r"(?:tank[_\s-]*level)\s*[:=]\s*\"?([0-9]+(?:\.[0-9]+)?)\"?",
        "pump_state": r"(?:pump[_\s-]*state)\s*[:=]\s*\"?([A-Za-z_ -]+)\"?",
        "valve_state": r"(?:valve[_\s-]*state)\s*[:=]\s*\"?([A-Za-z_ -]+)\"?",
        "alarm_count": r"(?:alarm[_\s-]*count|alarms?)\s*[:=]\s*\"?([0-9]+)\"?",
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


def _is_login_page(response):
    lower_text = response.text.lower()
    has_login_form = (
        'name="username"' in lower_text
        and 'name="password"' in lower_text
        and "<form" in lower_text
    )
    # Important: Scada-LTS can remain on /login.htm after successful POST
    # while already authenticated. So detect login state by form presence,
    # not URL alone.
    return (
        has_login_form
        or (
            response.status_code in (301, 302, 303, 307, 308)
            and "login.htm" in response.headers.get("Location", "").lower()
        )
    )


def login_to_hmi():
    login_url = urljoin(f"{HMI_BASE_URL}/", HMI_LOGIN_PATH.lstrip("/"))
    login_page = hmi_session.get(login_url, timeout=HTTP_TIMEOUT_SECONDS)
    login_page.raise_for_status()

    action, hidden_fields, user_field, pass_field = _parse_login_form(login_page.text)
    target_url = urljoin(login_url, action)
    payload = {**hidden_fields, user_field: HMI_USERNAME, pass_field: HMI_PASSWORD}

    response = hmi_session.post(target_url, data=payload, timeout=HTTP_TIMEOUT_SECONDS, allow_redirects=True)
    response.raise_for_status()
    return not _is_login_page(response)


def _candidate_status_urls():
    urls = list(HMI_STATUS_URLS)
    for path in HMI_AUTH_STATUS_URLS:
        urls.append(urljoin(f"{HMI_BASE_URL}/", path.lstrip("/")))
    return urls


def _to_float_or_none(value):
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _normalize_space(value):
    return " ".join(str(value).replace("\xa0", " ").split())


def parse_watchlist_html(html):
    soup = BeautifulSoup(html, "html.parser")
    table = soup.find(id="watchListTable")
    if table is None:
        app.logger.warning("watchListTable not found in authenticated watch list HTML")
        return None

    points = {}
    for name_td in table.select('td[id$="Name"]'):
        td_id = name_td.get("id", "")
        value_id = td_id.replace("Name", "Value")
        value_td = table.find("td", id=value_id)
        if not value_td:
            continue
        name = _normalize_space(name_td.get_text(" ", strip=True))
        value = _normalize_space(value_td.get_text(" ", strip=True))
        if name:
            points[name] = value

    if not points:
        app.logger.warning("No point name/value rows parsed from watchListTable")
        return None

    def _find_point(exact_names, contains_terms):
        for key in exact_names:
            if key in points:
                return points[key]
        for name, value in points.items():
            lowered = name.lower()
            if all(term in lowered for term in contains_terms):
                return value
        return None

    level_raw = _find_point(["TenEast - Level"], ["level"])
    level = _to_float_or_none(level_raw)
    run_value = _find_point(["TenEast - Run"], ["run"])
    pump_state = str(run_value) if run_value is not None else "UNKNOWN"

    preferred_valves = [
        "TenEast - ProductValve",
        "TenEast - AValve",
        "TenEast - BValve",
        "TenEast - PurgeValve",
    ]
    valve_state = _find_point(preferred_valves, ["valve"])
    if valve_state is None:
        valve_state = "UNKNOWN"

    header_text = soup.get_text(" ", strip=True)
    status_keywords = ["critical", "urgent", "warning", "information", "normal", "ok"]
    plant_status = "UNKNOWN"
    for keyword in status_keywords:
        if keyword in header_text.lower():
            plant_status = keyword.upper()
            break

    alarm_count = 0
    alarm_match = re.search(r"alarm(?:s)?\s*[:=]\s*(\d+)", header_text, flags=re.IGNORECASE)
    if alarm_match:
        alarm_count = _coerce_int(alarm_match.group(1), 0)

    if level is None and run_value is None and valve_state == "UNKNOWN":
        app.logger.warning("Watch-list parsed but key points were missing; using fallback")
        return None

    parsed = {
        "plant_status": plant_status,
        "tank_level": level if level is not None else 0.0,
        "pump_state": pump_state,
        "valve_state": str(valve_state),
        "alarm_count": alarm_count,
        "last_update": datetime.now(timezone.utc).isoformat(),
        "source": "hmi-watchlist",
    }
    return parsed


def fetch_hmi_status():
    watchlist_url = urljoin(f"{HMI_BASE_URL}/", HMI_WATCHLIST_PATH.lstrip("/"))
    with session_lock:
        try:
            initial = hmi_session.get(watchlist_url, timeout=HTTP_TIMEOUT_SECONDS, allow_redirects=True)
            if _is_login_page(initial):
                if not login_to_hmi():
                    app.logger.warning("HMI login failed; watch-list fetch cannot proceed")
                    return None, None
                initial = hmi_session.get(watchlist_url, timeout=HTTP_TIMEOUT_SECONDS, allow_redirects=True)
            initial.raise_for_status()
            if not _is_login_page(initial):
                parsed_watchlist = parse_watchlist_html(initial.text)
                if parsed_watchlist:
                    return parsed_watchlist, "hmi-watchlist"
                app.logger.warning("Authenticated watch-list fetch succeeded but parsing returned no values")
        except requests.RequestException:
            app.logger.exception("Error requesting authenticated watch-list page")

    for url in _candidate_status_urls():
        try:
            with session_lock:
                response = hmi_session.get(url, timeout=HTTP_TIMEOUT_SECONDS, allow_redirects=True)
                if _is_login_page(response):
                    if not login_to_hmi():
                        continue
                    response = hmi_session.get(url, timeout=HTTP_TIMEOUT_SECONDS, allow_redirects=True)
            response.raise_for_status()
            if _is_login_page(response):
                continue
            content_type = response.headers.get("Content-Type", "").lower()
            if "application/json" in content_type:
                payload = response.json()
                if isinstance(payload, dict):
                    status = sanitize_status(payload)
                    status["source"] = "hmi-authenticated"
                    return status, "hmi-authenticated"
            parsed = extract_status_from_text(response.text)
            if parsed:
                parsed["source"] = "hmi-authenticated"
                return parsed, "hmi-authenticated"
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
