"""Persistent engagement-scoped HTTP repeater and intruder workbench."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
import time
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
import uuid

from .engagements import get_engagement, resolve_engagement_path


HTTP_SESSION_PATTERN = re.compile(r"http_\d{8}_[0-9a-f]{32}")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sessions_root(engagement_id: str) -> Path:
    get_engagement(engagement_id)
    path = resolve_engagement_path(engagement_id, ".drost/http-sessions", must_exist=False)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _validate_session_id(session_id: str) -> str:
    if not isinstance(session_id, str) or not HTTP_SESSION_PATTERN.fullmatch(session_id):
        raise ValueError("session_id must be a server-generated HTTP session identifier")
    return session_id


def _session_path(engagement_id: str, session_id: str) -> Path:
    return _sessions_root(engagement_id) / f"{_validate_session_id(session_id)}.json"


def _history_path(engagement_id: str, session_id: str) -> Path:
    return _sessions_root(engagement_id) / f"{_validate_session_id(session_id)}.history.jsonl"


def _write_state(engagement_id: str, state: dict[str, Any]) -> None:
    path = _session_path(engagement_id, state["session_id"])
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _load_state(engagement_id: str, session_id: str) -> dict[str, Any]:
    path = _session_path(engagement_id, session_id)
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"unknown HTTP session: {session_id}")
    state = json.loads(path.read_text(encoding="utf-8"))
    if state.get("engagement_id") != engagement_id or state.get("session_id") != session_id:
        raise ValueError(f"invalid HTTP session manifest: {session_id}")
    return state


def _public_state(state: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in state.items() if not key.startswith("_")}


def create_http_session(
    engagement_id: str,
    name: str,
    base_url: str,
    scope_hosts: list[str] | None = None,
    include_subdomains: bool = False,
    default_headers: dict[str, str] | None = None,
    verify_tls: bool = True,
    follow_redirects: bool = True,
) -> dict[str, Any]:
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("base_url must be an absolute HTTP(S) URL")
    hosts = [host.strip().lower() for host in (scope_hosts or [parsed.hostname]) if host.strip()]
    if not hosts:
        raise ValueError("scope_hosts must contain at least one host")
    date = datetime.now(timezone.utc).strftime("%Y%m%d")
    session_id = f"http_{date}_{uuid.uuid4().hex}"
    state = {
        "schema_version": 1,
        "session_id": session_id,
        "engagement_id": engagement_id,
        "name": name.strip() or session_id,
        "base_url": base_url,
        "scope_hosts": hosts,
        "include_subdomains": include_subdomains,
        "default_headers": dict(default_headers or {}),
        "cookies": {},
        "rules": [],
        "verify_tls": verify_tls,
        "follow_redirects": follow_redirects,
        "created_at": _now(),
        "updated_at": _now(),
    }
    _write_state(engagement_id, state)
    return _public_state(state)


def list_http_sessions(engagement_id: str) -> dict[str, Any]:
    sessions = []
    for path in sorted(_sessions_root(engagement_id).glob("http_*.json")):
        if path.name.endswith(".history.jsonl") or path.is_symlink():
            continue
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if state.get("engagement_id") == engagement_id:
            sessions.append(_public_state(state))
    sessions.sort(key=lambda item: item.get("created_at", ""), reverse=True)
    return {"engagement_id": engagement_id, "sessions": sessions}


def get_http_session(engagement_id: str, session_id: str) -> dict[str, Any]:
    state = _load_state(engagement_id, session_id)
    history_path = _history_path(engagement_id, session_id)
    history_count = 0
    if history_path.is_file():
        with history_path.open(encoding="utf-8") as handle:
            history_count = sum(1 for line in handle if line.strip())
    return {**_public_state(state), "history_count": history_count}


def update_http_session(
    engagement_id: str,
    session_id: str,
    scope_hosts: list[str] | None = None,
    include_subdomains: bool | None = None,
    default_headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    rules: list[dict[str, str]] | None = None,
    verify_tls: bool | None = None,
    follow_redirects: bool | None = None,
) -> dict[str, Any]:
    state = _load_state(engagement_id, session_id)
    if scope_hosts is not None:
        normalized = [host.strip().lower() for host in scope_hosts if host.strip()]
        if not normalized:
            raise ValueError("scope_hosts must not be empty")
        state["scope_hosts"] = normalized
    if include_subdomains is not None:
        state["include_subdomains"] = include_subdomains
    if default_headers is not None:
        state["default_headers"] = dict(default_headers)
    if cookies is not None:
        state["cookies"] = dict(cookies)
    if rules is not None:
        for rule in rules:
            if rule.get("location") not in {"url", "header", "body"}:
                raise ValueError("rule location must be url, header, or body")
            if not isinstance(rule.get("match"), str) or not isinstance(rule.get("replace"), str):
                raise ValueError("rules require string match and replace values")
        state["rules"] = rules
    if verify_tls is not None:
        state["verify_tls"] = verify_tls
    if follow_redirects is not None:
        state["follow_redirects"] = follow_redirects
    state["updated_at"] = _now()
    _write_state(engagement_id, state)
    return _public_state(state)


def _is_in_scope(state: dict[str, Any], url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    for allowed in state["scope_hosts"]:
        if host == allowed:
            return True
        if state["include_subdomains"] and host.endswith("." + allowed):
            return True
    return False


def _apply_rules(
    state: dict[str, Any],
    url: str,
    headers: dict[str, str],
    body: str | None,
) -> tuple[str, dict[str, str], str | None]:
    for rule in state.get("rules", []):
        location = rule["location"]
        match = rule["match"]
        replacement = rule["replace"]
        if location == "url":
            url = url.replace(match, replacement)
        elif location == "header":
            headers = {key: value.replace(match, replacement) for key, value in headers.items()}
        elif body is not None:
            body = body.replace(match, replacement)
    return url, headers, body


def _append_history(engagement_id: str, session_id: str, entry: dict[str, Any]) -> None:
    path = _history_path(engagement_id, session_id)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")


def repeat_http_request(
    engagement_id: str,
    session_id: str,
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: str | None = None,
) -> dict[str, Any]:
    import requests

    state = _load_state(engagement_id, session_id)
    absolute_url = url if url.startswith(("http://", "https://")) else urljoin(state["base_url"], url)
    merged_headers = {**state.get("default_headers", {}), **(headers or {})}
    absolute_url, merged_headers, body = _apply_rules(state, absolute_url, merged_headers, body)
    if not _is_in_scope(state, absolute_url):
        raise ValueError(f"request is outside declared HTTP session scope: {absolute_url}")
    started = time.monotonic()
    client = requests.Session()
    client.cookies.update(state.get("cookies", {}))
    current_method = method.upper()
    current_url = absolute_url
    current_body = body
    redirect_chain = []
    while True:
        response = client.request(
            current_method,
            current_url,
            headers=merged_headers,
            data=current_body,
            verify=state["verify_tls"],
            allow_redirects=False,
        )
        location = response.headers.get("location")
        if not state["follow_redirects"] or response.status_code not in {301, 302, 303, 307, 308} or not location:
            break
        next_url = urljoin(response.url, location)
        if not _is_in_scope(state, next_url):
            raise ValueError(f"redirect leaves declared HTTP session scope: {next_url}")
        redirect_chain.append({"status": response.status_code, "url": response.url, "location": next_url})
        if response.status_code == 303 or (response.status_code in {301, 302} and current_method == "POST"):
            current_method = "GET"
            current_body = None
        current_url = next_url
        if len(redirect_chain) >= 30:
            raise ValueError("HTTP redirect chain exceeded 30 in-scope redirects")
    state["cookies"].update(client.cookies.get_dict())
    state["updated_at"] = _now()
    _write_state(engagement_id, state)
    entry = {
        "timestamp": _now(),
        "request": {
            "method": response.request.method,
            "url": response.request.url,
            "headers": dict(response.request.headers),
            "body": body,
        },
        "response": {
            "status": response.status_code,
            "url": response.url,
            "headers": dict(response.headers),
            "body": response.text,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
            "redirect_chain": redirect_chain,
        },
    }
    _append_history(engagement_id, session_id, entry)
    return {"engagement_id": engagement_id, "session_id": session_id, **entry}


def intrude_http_parameter(
    engagement_id: str,
    session_id: str,
    method: str,
    url: str,
    location: str,
    parameter: str,
    payloads: list[str],
    max_requests: int,
    headers: dict[str, str] | None = None,
    body: str = "",
) -> dict[str, Any]:
    if max_requests < 1 or len(payloads) > max_requests:
        raise ValueError("payload count exceeds caller-selected max_requests")
    normalized = location.lower()
    if normalized not in {"query", "header", "body", "path"}:
        raise ValueError("location must be query, header, body, or path")
    results = []
    for payload in payloads:
        candidate_url = url
        candidate_headers = dict(headers or {})
        candidate_body = body or None
        if normalized == "query":
            parsed = urlparse(candidate_url)
            query = dict(parse_qsl(parsed.query, keep_blank_values=True))
            query[parameter] = payload
            candidate_url = urlunparse(parsed._replace(query=urlencode(query)))
        elif normalized == "header":
            candidate_headers[parameter] = payload
        elif normalized == "body":
            candidate_body = body.replace("{{FUZZ}}", payload) if "{{FUZZ}}" in body else payload
        else:
            if "{{FUZZ}}" not in candidate_url:
                raise ValueError("path intrusion requires {{FUZZ}} in url")
            candidate_url = candidate_url.replace("{{FUZZ}}", payload)
        result = repeat_http_request(
            engagement_id,
            session_id,
            method,
            candidate_url,
            candidate_headers,
            candidate_body,
        )
        results.append({"payload": payload, **result["response"]})
    return {
        "engagement_id": engagement_id,
        "session_id": session_id,
        "location": normalized,
        "parameter": parameter,
        "request_count": len(results),
        "results": results,
    }


def read_http_history(engagement_id: str, session_id: str) -> dict[str, Any]:
    _load_state(engagement_id, session_id)
    path = _history_path(engagement_id, session_id)
    entries = []
    if path.is_file():
        with path.open(encoding="utf-8") as handle:
            entries = [json.loads(line) for line in handle if line.strip()]
    engagement_root = Path(get_engagement(engagement_id)["workspace"])
    return {
        "engagement_id": engagement_id,
        "session_id": session_id,
        "history_path": str(path.relative_to(engagement_root)),
        "entries": entries,
    }
