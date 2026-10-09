"""In-container Playwright browser sessions bound to Drost engagements."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import fnmatch
import json
from pathlib import Path
import shutil
from typing import Any
import uuid

from .engagements import get_engagement, resolve_engagement_path


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class BrowserSession:
    session_id: str
    engagement_id: str
    name: str
    context: Any
    page: Any
    created_at: str
    network_log_path: Path
    network_events: list[dict[str, Any]] = field(default_factory=list)
    blocked_patterns: list[str] = field(default_factory=list)
    url_replacements: list[dict[str, str]] = field(default_factory=list)
    extra_headers: dict[str, str] = field(default_factory=dict)


class BrowserManager:
    def __init__(self) -> None:
        self._playwright: Any = None
        self._browser: Any = None
        self._sessions: dict[str, BrowserSession] = {}

    async def _ensure_browser(self) -> Any:
        if self._browser is not None and self._browser.is_connected():
            return self._browser
        executable = shutil.which("chromium") or shutil.which("chromium-browser")
        if not executable:
            raise ValueError("Chromium is not installed in the Drost container")
        from playwright.async_api import async_playwright

        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            executable_path=executable,
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage"],
        )
        return self._browser

    def _get(self, engagement_id: str, session_id: str) -> BrowserSession:
        session = self._sessions.get(session_id)
        if session is None or session.engagement_id != engagement_id:
            raise ValueError(f"unknown browser session: {session_id}")
        return session

    async def create(
        self,
        engagement_id: str,
        name: str,
        viewport_width: int = 1440,
        viewport_height: int = 900,
        user_agent: str = "",
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        get_engagement(engagement_id)
        browser = await self._ensure_browser()
        context_options: dict[str, Any] = {
            "viewport": {"width": viewport_width, "height": viewport_height},
            "ignore_https_errors": True,
        }
        if user_agent:
            context_options["user_agent"] = user_agent
        if extra_headers:
            context_options["extra_http_headers"] = extra_headers
        context = await browser.new_context(**context_options)
        page = await context.new_page()
        session_id = f"browser_{datetime.now(timezone.utc).strftime('%Y%m%d')}_{uuid.uuid4().hex}"
        artifact_root = resolve_engagement_path(
            engagement_id,
            f".drost/browser/{session_id}",
            must_exist=False,
        )
        artifact_root.mkdir(parents=True, exist_ok=True)
        session = BrowserSession(
            session_id=session_id,
            engagement_id=engagement_id,
            name=name.strip() or session_id,
            context=context,
            page=page,
            created_at=_now(),
            network_log_path=artifact_root / "network.jsonl",
            extra_headers=dict(extra_headers or {}),
        )

        def record_network_event(event: dict[str, Any]) -> None:
            session.network_events.append(event)
            with session.network_log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, sort_keys=True) + "\n")

        def on_request(request: Any) -> None:
            record_network_event(
                {
                    "type": "request",
                    "timestamp": _now(),
                    "method": request.method,
                    "url": request.url,
                    "resource_type": request.resource_type,
                    "headers": dict(request.headers),
                }
            )

        def on_response(response: Any) -> None:
            record_network_event(
                {
                    "type": "response",
                    "timestamp": _now(),
                    "status": response.status,
                    "url": response.url,
                }
            )

        async def route_handler(route: Any, request: Any) -> None:
            if any(fnmatch.fnmatch(request.url, pattern) for pattern in session.blocked_patterns):
                await route.abort()
                return
            url = request.url
            for rule in session.url_replacements:
                url = url.replace(rule["match"], rule["replace"])
            headers = {**request.headers, **session.extra_headers}
            await route.continue_(url=url, headers=headers)

        page.on("request", on_request)
        page.on("response", on_response)
        await context.route("**/*", route_handler)
        self._sessions[session_id] = session
        return await self.get(engagement_id, session_id)

    async def list(self, engagement_id: str) -> dict[str, Any]:
        get_engagement(engagement_id)
        sessions = [
            await self.get(engagement_id, session_id)
            for session_id, session in self._sessions.items()
            if session.engagement_id == engagement_id
        ]
        return {"engagement_id": engagement_id, "sessions": sessions}

    async def get(self, engagement_id: str, session_id: str) -> dict[str, Any]:
        session = self._get(engagement_id, session_id)
        return {
            "engagement_id": engagement_id,
            "session_id": session_id,
            "name": session.name,
            "created_at": session.created_at,
            "url": session.page.url,
            "title": await session.page.title(),
            "network_event_count": len(session.network_events),
            "blocked_patterns": session.blocked_patterns,
            "url_replacements": session.url_replacements,
            "extra_headers": session.extra_headers,
        }

    async def close(self, engagement_id: str, session_id: str) -> dict[str, Any]:
        session = self._get(engagement_id, session_id)
        await session.context.close()
        self._sessions.pop(session_id, None)
        return {"engagement_id": engagement_id, "session_id": session_id, "closed": True}

    async def navigate(self, engagement_id: str, session_id: str, url: str, wait_until: str = "load") -> dict[str, Any]:
        session = self._get(engagement_id, session_id)
        response = await session.page.goto(url, wait_until=wait_until, timeout=0)
        return {
            "engagement_id": engagement_id,
            "session_id": session_id,
            "url": session.page.url,
            "title": await session.page.title(),
            "status": response.status if response else None,
            "headers": await response.all_headers() if response else {},
        }

    async def snapshot(self, engagement_id: str, session_id: str, include_html: bool = False) -> dict[str, Any]:
        session = self._get(engagement_id, session_id)
        body = session.page.locator("body")
        try:
            accessibility = await body.aria_snapshot()
        except Exception:
            accessibility = ""
        result = {
            "engagement_id": engagement_id,
            "session_id": session_id,
            "url": session.page.url,
            "title": await session.page.title(),
            "text": await body.inner_text(),
            "accessibility": accessibility,
        }
        if include_html:
            result["html"] = await session.page.content()
        return result

    async def action(
        self,
        engagement_id: str,
        session_id: str,
        action: str,
        selector: str,
        value: str = "",
    ) -> dict[str, Any]:
        session = self._get(engagement_id, session_id)
        locator = session.page.locator(selector).first
        normalized = action.lower()
        if normalized == "click":
            await locator.click(timeout=0)
        elif normalized == "fill":
            await locator.fill(value, timeout=0)
        elif normalized == "type":
            await locator.type(value, timeout=0)
        elif normalized == "clear":
            await locator.clear(timeout=0)
        elif normalized == "press":
            await locator.press(value, timeout=0)
        elif normalized == "check":
            await locator.check(timeout=0)
        elif normalized == "uncheck":
            await locator.uncheck(timeout=0)
        elif normalized == "select":
            await locator.select_option(value, timeout=0)
        elif normalized == "hover":
            await locator.hover(timeout=0)
        else:
            raise ValueError("action must be click, fill, type, clear, press, check, uncheck, select, or hover")
        return {
            "engagement_id": engagement_id,
            "session_id": session_id,
            "action": normalized,
            "selector": selector,
            "url": session.page.url,
        }

    async def screenshot(self, engagement_id: str, session_id: str, path: str = "", full_page: bool = True) -> dict[str, Any]:
        session = self._get(engagement_id, session_id)
        if not path:
            path = f".drost/browser/{session_id}/screenshot-{uuid.uuid4().hex[:8]}.png"
        target = resolve_engagement_path(engagement_id, path, must_exist=False)
        target.parent.mkdir(parents=True, exist_ok=True)
        await session.page.screenshot(path=str(target), full_page=full_page)
        root = Path(get_engagement(engagement_id)["workspace"])
        return {
            "engagement_id": engagement_id,
            "session_id": session_id,
            "path": str(target.relative_to(root)),
            "size": target.stat().st_size,
        }

    async def evaluate(self, engagement_id: str, session_id: str, expression: str, argument: Any = None) -> dict[str, Any]:
        session = self._get(engagement_id, session_id)
        value = await session.page.evaluate(expression, argument)
        return {"engagement_id": engagement_id, "session_id": session_id, "value": value}

    async def state(self, engagement_id: str, session_id: str) -> dict[str, Any]:
        session = self._get(engagement_id, session_id)
        storage = await session.page.evaluate(
            """() => ({
              localStorage: Object.fromEntries(Object.entries(localStorage)),
              sessionStorage: Object.fromEntries(Object.entries(sessionStorage))
            })"""
        )
        return {
            "engagement_id": engagement_id,
            "session_id": session_id,
            "cookies": await session.context.cookies(),
            **storage,
        }

    async def set_state(
        self,
        engagement_id: str,
        session_id: str,
        cookies: list[dict[str, Any]] | None = None,
        local_storage: dict[str, str] | None = None,
        session_storage: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        session = self._get(engagement_id, session_id)
        if cookies:
            await session.context.add_cookies(cookies)
        await session.page.evaluate(
            """state => {
              for (const [key, value] of Object.entries(state.local || {})) localStorage.setItem(key, value);
              for (const [key, value] of Object.entries(state.session || {})) sessionStorage.setItem(key, value);
            }""",
            {"local": local_storage or {}, "session": session_storage or {}},
        )
        return await self.state(engagement_id, session_id)

    async def network_rules(
        self,
        engagement_id: str,
        session_id: str,
        blocked_patterns: list[str] | None = None,
        url_replacements: list[dict[str, str]] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        session = self._get(engagement_id, session_id)
        if blocked_patterns is not None:
            session.blocked_patterns = blocked_patterns
        if url_replacements is not None:
            for rule in url_replacements:
                if not isinstance(rule.get("match"), str) or not isinstance(rule.get("replace"), str):
                    raise ValueError("URL replacement rules require string match and replace values")
            session.url_replacements = url_replacements
        if extra_headers is not None:
            session.extra_headers = extra_headers
        return {
            "engagement_id": engagement_id,
            "session_id": session_id,
            "blocked_patterns": session.blocked_patterns,
            "url_replacements": session.url_replacements,
            "extra_headers": session.extra_headers,
        }

    async def network_log(self, engagement_id: str, session_id: str, clear: bool = False) -> dict[str, Any]:
        session = self._get(engagement_id, session_id)
        events = list(session.network_events)
        if clear:
            session.network_events.clear()
            session.network_log_path.write_text("", encoding="utf-8")
        root = Path(get_engagement(engagement_id)["workspace"])
        return {
            "engagement_id": engagement_id,
            "session_id": session_id,
            "events": events,
            "history_path": str(session.network_log_path.relative_to(root)),
            "cleared": clear,
        }


BROWSER_MANAGER = BrowserManager()
