# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# HunterX — AI-Assisted Vulnerability Hunter
from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .utils import logger


HAS_PLAYWRIGHT = False
try:
    from playwright.async_api import async_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    pass


@dataclass
class BrowserSnapshot:
    url: str
    dom_html: str = ""
    local_storage: Dict[str, str] = field(default_factory=dict)
    session_storage: Dict[str, str] = field(default_factory=dict)
    cookies: List[Dict[str, Any]] = field(default_factory=list)
    indexed_db_names: List[str] = field(default_factory=list)
    intercepted_requests: List[Dict[str, Any]] = field(default_factory=list)
    websocket_events: List[Dict[str, Any]] = field(default_factory=list)
    service_workers: List[Dict[str, Any]] = field(default_factory=list)
    csp_violations: List[Dict[str, Any]] = field(default_factory=list)
    console_errors: List[str] = field(default_factory=list)
    network_errors: List[Dict[str, Any]] = field(default_factory=list)
    client_routes: List[str] = field(default_factory=list)
    page_title: str = ""
    js_variables: Dict[str, str] = field(default_factory=dict)
    dom_mutations: List[Dict[str, Any]] = field(default_factory=list)
    screenshot_path: Optional[str] = None
    collected_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "page_title": self.page_title,
            "dom_length": len(self.dom_html),
            "local_storage_items": len(self.local_storage),
            "session_storage_items": len(self.session_storage),
            "cookies_count": len(self.cookies),
            "intercepted_requests_count": len(self.intercepted_requests),
            "websocket_events_count": len(self.websocket_events),
            "service_workers_count": len(self.service_workers),
            "csp_violations_count": len(self.csp_violations),
            "console_errors_count": len(self.console_errors),
            "network_errors_count": len(self.network_errors),
            "client_routes": self.client_routes,
            "collected_at": self.collected_at.isoformat(),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class PlaywrightSession:
    def __init__(self, headless: bool = True, timeout_ms: int = 30000):
        if not HAS_PLAYWRIGHT:
            raise ImportError("Playwright is required. Install: pip install playwright && playwright install chromium")
        self.headless = headless
        self.timeout_ms = timeout_ms
        self._browser = None
        self._context = None
        self._page = None
        self._intercepted: List[Dict[str, Any]] = []
        self._ws_events: List[Dict[str, Any]] = []
        self._csp_violations: List[Dict[str, Any]] = []
        self._console_errors: List[str] = []
        self._network_errors: List[Dict[str, Any]] = []
        self._dom_mutations: List[Dict[str, Any]] = []

    async def __aenter__(self):
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(headless=self.headless)
        self._context = await self._browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            viewport={"width": 1920, "height": 1080},
            java_script_enabled=True,
            ignore_https_errors=True,
        )
        self._page = await self._context.new_page()
        self._setup_listeners()
        return self

    async def __aexit__(self, *args):
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()

    def _setup_listeners(self):
        if not self._page:
            return

        async def on_response(response):
            try:
                self._intercepted.append({
                    "url": response.url,
                    "status": response.status,
                    "headers": dict(response.headers),
                    "timestamp": time.time(),
                })
            except Exception:
                pass

        async def on_request(request):
            try:
                if request.resource_type in ("xhr", "fetch"):
                    self._intercepted.append({
                        "url": request.url,
                        "method": request.method,
                        "resource_type": request.resource_type,
                        "headers": dict(request.headers),
                        "timestamp": time.time(),
                    })
            except Exception:
                pass

        async def on_console(msg):
            if msg.type == "error":
                self._console_errors.append(str(msg.text))

        async def on_page_error(err):
            self._network_errors.append({"error": str(err), "timestamp": time.time()})

        async def on_websocket(ws):
            async def on_frame_sent(frame):
                self._ws_events.append({
                    "type": "sent",
                    "data": str(frame),
                    "timestamp": time.time(),
                })

            async def on_frame_received(frame):
                self._ws_events.append({
                    "type": "received",
                    "data": str(frame),
                    "timestamp": time.time(),
                })

            ws.on("framesent", on_frame_sent)
            ws.on("framereceived", on_frame_received)

        self._page.on("response", on_response)
        self._page.on("request", on_request)
        self._page.on("console", on_console)
        self._page.on("pageerror", on_page_error)
        self._page.on("websocket", on_websocket)

    async def navigate(self, url: str, wait_until: str = "networkidle") -> bool:
        if not self._page:
            return False
        try:
            await self._page.goto(url, wait_until=wait_until, timeout=self.timeout_ms)
            await asyncio.sleep(1)
            return True
        except Exception as e:
            logger.warning(f"Playwright navigate failed: {e}")
            return False

    async def snapshot(self, url: str) -> BrowserSnapshot:
        if not self._page:
            return BrowserSnapshot(url=url)

        snapshot = BrowserSnapshot(url=url)

        try:
            snapshot.page_title = await self._page.title()
            snapshot.dom_html = await self._page.content()
        except Exception:
            pass

        try:
            snapshot.local_storage = await self._page.evaluate("JSON.parse(JSON.stringify(window.localStorage))")
        except Exception:
            pass

        try:
            snapshot.session_storage = await self._page.evaluate("JSON.parse(JSON.stringify(window.sessionStorage))")
        except Exception:
            pass

        try:
            cookies = await self._context.cookies()
            snapshot.cookies = cookies
        except Exception:
            pass

        try:
            sws = await self._context.service_workers
            snapshot.service_workers = [{"url": sw.url} for sw in sws]
        except Exception:
            pass

        try:
            js_vars = await self._page.evaluate("""() => {
                const vars = {};
                const keys = Object.keys(window).filter(k =>
                    !k.startsWith('_') && k !== 'constructor' &&
                    typeof window[k] !== 'function'
                );
                for (const k of keys.slice(0, 50)) {
                    try { vars[k] = JSON.stringify(window[k]).slice(0, 200); }
                    catch(e) { vars[k] = String(window[k]).slice(0, 200); }
                }
                return vars;
            }""")
            snapshot.js_variables = js_vars
        except Exception:
            pass

        try:
            routes = await self._page.evaluate("""() => {
                if (typeof window.__NEXT_DATA__ !== 'undefined') return [];
                if (typeof window.__NUXT__ !== 'undefined') return [];
                const links = Array.from(document.querySelectorAll('a[href]'));
                return [...new Set(links.map(l => l.getAttribute('href')))].slice(0, 100);
            }""")
            if isinstance(routes, list):
                snapshot.client_routes = routes
        except Exception:
            pass

        snapshot.intercepted_requests = self._intercepted[-200:]
        snapshot.websocket_events = self._ws_events[-100:]
        snapshot.console_errors = self._console_errors[-100:]
        snapshot.network_errors = self._network_errors[-50:]
        snapshot.dom_mutations = self._dom_mutations[-100:]

        return snapshot

    async def evaluate(self, script: str) -> Any:
        if not self._page:
            return None
        try:
            return await self._page.evaluate(script)
        except Exception as e:
            logger.warning(f"Playwright evaluate failed: {e}")
            return None

    async def screenshot(self, path: str) -> bool:
        if not self._page:
            return False
        try:
            await self._page.screenshot(path=path, full_page=True)
            return True
        except Exception as e:
            logger.warning(f"Playwright screenshot failed: {e}")
            return False


class BrowserIntelligenceEngine:
    def __init__(self, headless: bool = True, timeout_ms: int = 30000):
        self.headless = headless
        self.timeout_ms = timeout_ms
        self._enabled = HAS_PLAYWRIGHT

    @property
    def enabled(self) -> bool:
        return self._enabled

    def check_available(self) -> bool:
        if not HAS_PLAYWRIGHT:
            logger.warning("BrowserIntelligence: playwright not installed. pip install playwright && playwright install chromium")
            return False
        return True

    async def collect(self, url: str) -> BrowserSnapshot:
        if not self.check_available():
            return BrowserSnapshot(url=url)

        logger.info(f"BrowserIntelligence: collecting client-side data from {url}")
        async with PlaywrightSession(headless=self.headless, timeout_ms=self.timeout_ms) as session:
            success = await session.navigate(url)
            if not success:
                logger.warning(f"BrowserIntelligence: failed to navigate to {url}")
                return BrowserSnapshot(url=url)

            snapshot = await session.snapshot(url)
            logger.info(f"BrowserIntelligence: collected {len(snapshot.intercepted_requests)} requests, "
                         f"{len(snapshot.cookies)} cookies, {len(snapshot.client_routes)} routes")
            return snapshot

    async def collect_with_analysis(self, url: str) -> Dict[str, Any]:
        snapshot = await self.collect(url)
        analysis = {
            "snapshot": snapshot.to_dict(),
            "analysis": self._analyze_snapshot(snapshot),
        }
        return analysis

    def _analyze_snapshot(self, snapshot: BrowserSnapshot) -> Dict[str, Any]:
        findings = []

        if any(c.get("httpOnly") is False for c in snapshot.cookies):
            findings.append("Cookies without HttpOnly flag detected")

        if any(c.get("secure") is False for c in snapshot.cookies if c.get("name") not in ("",)):
            findings.append("Cookies without Secure flag detected")

        if snapshot.local_storage:
            for key in snapshot.local_storage:
                if any(secret in key.lower() for secret in ["token", "secret", "key", "password", "jwt"]):
                    findings.append(f"Sensitive data in localStorage: {key}")

        if snapshot.session_storage:
            for key in snapshot.session_storage:
                if any(secret in key.lower() for secret in ["token", "secret", "key", "password", "jwt"]):
                    findings.append(f"Sensitive data in sessionStorage: {key}")

        if snapshot.service_workers:
            findings.append(f"Service Workers registered: {len(snapshot.service_workers)}")

        if snapshot.console_errors:
            findings.append(f"Console errors detected: {len(snapshot.console_errors)}")

        if snapshot.network_errors:
            findings.append(f"Network errors detected: {len(snapshot.network_errors)}")

        return {
            "findings": findings,
            "risk_flags": len(findings),
            "client_side_routes": len(snapshot.client_routes),
        }

    def analyze_snapshot_sync(self, snapshot: BrowserSnapshot) -> Dict[str, Any]:
        return self._analyze_snapshot(snapshot)
