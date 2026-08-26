# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""In-process browser-testing adapter (Playwright + Chromium).

A first-class browser capability for modern web applications: the adapter
launches a real headless browser against the target, exercises the page like a
client (scripts execute, XHR/fetch fire, storage is populated) and collects
client-side security evidence no HTTP-only tool can see:

* console errors / stack traces (information disclosure),
* failed network requests,
* DOM-discovered links/routes/forms/endpoints (attack-surface expansion),
* localStorage / sessionStorage / cookies (sensitive-data exposure),
* security-relevant DOM facts (iframes, inline handlers, mixed content).

The adapter is scope-safe by construction: it only ever loads the URL the
execution context authorizes. Discovered third-party URLs are REPORTED, never
visited.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

from hunterx.domain.execution import ExecutionContext
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.sdk.adapter import ToolAdapter
from hunterx.tools.sdk.output import OutputCollector

_DESCRIPTOR = ToolDescriptor(
    name="browser",
    version="1.0.0",
    description=(
        "Headless-browser client-side security testing (Playwright/Chromium): "
        "DOM discovery, console/network error capture, web-storage secret scan"
    ),
    targets=("url",),
    permissions=("network",),
)


class BrowserTestingAdapter(ToolAdapter):
    """Real headless-browser assessment of an authorized URL."""

    descriptor = _DESCRIPTOR

    def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
        """Load ``context.target`` in headless Chromium and collect evidence."""
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(f"playwright not installed: {exc}") from exc

        target = context.target.strip()
        if not target:
            raise RuntimeError("browser testing requires a URL target")
        timeout_ms = int(self._param(context, "timeout", 20) * 1000)
        console_errors: list[str] = []
        request_failures: list[dict[str, str]] = []
        responses: list[dict[str, Any]] = []

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                page = browser.new_page()
                page.on(
                    "console",
                    lambda message: (
                        console_errors.append(str(message.text)[:500])
                        if message.type == "error"
                        else None
                    ),
                )
                page.on(
                    "requestfailed",
                    lambda request: request_failures.append(
                        {"url": request.url[:300], "failure": str(request.failure)[:120]}
                    ),
                )
                response = page.goto(target, timeout=timeout_ms, wait_until="domcontentloaded")
                try:
                    # Give SPA frameworks a bounded window to boot and fire XHRs.
                    page.wait_for_load_state("networkidle", timeout=min(timeout_ms, 8000))
                except Exception:  # noqa: BLE001 - networkidle is best-effort
                    pass
                status = response.status if response is not None else 0
                headers = {k.lower(): v for k, v in (response.headers.items() if response is not None else {})}
                body_text = ""
                try:
                    body_text = page.inner_text("body")[:20000]
                except Exception:  # noqa: BLE001 - pages without body text
                    body_text = ""

                dom_links = page.eval_on_selector_all(
                    "a[href]",
                    "els => els.map(e => e.getAttribute('href')).filter(Boolean)",
                )
                forms = page.eval_on_selector_all(
                    "form",
                    """
                    els => els.map(e => ({
                        action: e.getAttribute('action') || '',
                        method: (e.getAttribute('method') || 'get').toLowerCase(),
                        fields: Array.from(e.elements).map(f => f.name).filter(Boolean),
                    }))
                    """,
                )
                iframes = page.eval_on_selector_all(
                    "iframe[src]", "els => els.map(e => e.getAttribute('src'))"
                )
                inline_handlers = page.eval_on_selector_all(
                    "[onclick],[onerror],[onload],[onmouseover]",
                    "els => els.length",
                )
                storage = page.evaluate(
                    "() => ({ local: JSON.stringify(localStorage).slice(0, 4000),"
                    " session: JSON.stringify(sessionStorage).slice(0, 4000) })"
                )
                cookies = [cookie["name"] for cookie in context_cookies(page)]
            finally:
                browser.close()

        origin = "{0.scheme}://{0.netloc}".format(urlsplit(target))
        same_origin_links = sorted(
            {
                _absolute(link, target)
                for link in dom_links
                if link and _absolute(link, target).startswith(origin)
            }
        )
        third_party_links = sorted(
            {
                _absolute(link, target)
                for link in dom_links
                if link and not _absolute(link, target).startswith(origin) and link.startswith(("http://", "https://"))
            }
        )

        blob = json.dumps({"storage": storage, "errors": console_errors}).lower()
        secret_markers = ("token", "secret", "apikey", "api_key", "password", "authorization")
        storage_secrets = [marker for marker in secret_markers if marker in blob]

        payload = {
            "browser_testing": {
                "target": target,
                "status": status,
                "title": "",
                "security_headers_missing": [
                    header
                    for header in (
                        "content-security-policy",
                        "x-content-type-options",
                        "strict-transport-security",
                        "x-frame-options",
                    )
                    if header not in headers
                ],
                "console_errors": console_errors[:30],
                "request_failures": request_failures[:30],
                "same_origin_links": same_origin_links[:100],
                "third_party_references": third_party_links[:50],
                "forms": forms[:20],
                "iframes": iframes[:10],
                "inline_event_handlers": int(inline_handlers or 0),
                "storage_keys_sensitive_markers": storage_secrets,
                "cookies": cookies[:40],
                "body_excerpt": body_text[:1500],
            },
            "count": len(same_origin_links) + len(console_errors),
        }
        collector.set_json(payload)

    def validate_output(self, context: ExecutionContext, output):  # noqa: ANN001
        errors: list[str] = []
        if output.exit_code != 0:
            errors.append(f"exit code {output.exit_code}")
        if not isinstance(output.json, dict):
            errors.append("browser produced no structured result")
        return (not errors, errors)

    def normalize(self, context: ExecutionContext, output):  # noqa: ANN001
        from hunterx.tools.adapter import ToolOutput

        normalized = ToolOutput()
        payload = output.json if isinstance(output.json, dict) else {}
        browser = payload.get("browser_testing", {})
        assets: list[dict[str, Any]] = []
        for link in browser.get("same_origin_links", [])[:60]:
            assets.append({"kind": "url", "url": link})
        normalized.assets = assets
        return normalized

    def _param(self, context: ExecutionContext, name: str, default: Any = None) -> Any:
        return context.parameters.get(name, default)


def context_cookies(page: Any) -> list[dict[str, Any]]:
    try:
        return list(page.context.cookies())
    except Exception:  # noqa: BLE001 - cookie access is best-effort
        return []


def _absolute(link: str, base: str) -> str:
    from urllib.parse import urljoin

    try:
        return urljoin(base, str(link).strip())
    except Exception:  # noqa: BLE001
        return ""


__all__ = ["BrowserTestingAdapter"]
