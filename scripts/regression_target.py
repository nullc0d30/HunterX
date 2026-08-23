#!/usr/bin/env python3
"""Vulnerable target for real-mission regression: JS content + reflected SQLi on /rest/products/search?q="""
import http.server
import json
import threading
import urllib.parse

JS_CONTENT = """
// application configuration
const API_BASE = "/api/v1";
const SEARCH_ENDPOINT = "/rest/products/search";
const TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.abcdefghijklmnopqrstuvwxyz";
const API_KEY = "sk_live_abcdef1234567890";
const CONFIG = { "debug": true, "timeout": 5000 };

function fetchProducts(query) {
    return fetch(`${SEARCH_ENDPOINT}?q=${encodeURIComponent(query)}`)
        .then(r => r.json());
}

async function search(query) {
    try {
        const results = await fetchProducts(query);
        render(results);
    } catch (e) {
        console.error(e);
    }
}

// template literal building API URL
function buildUrl(path, params) {
    return `${API_BASE}${path}?${new URLSearchParams(params).toString()}`;
}

document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("search-form");
    if (form) form.addEventListener("submit", (e) => { e.preventDefault(); search(form.q.value); });
});
"""

HTML_PAGE = """<!DOCTYPE html>
<html><head><title>Demo Shop</title></head><body>
<h1>Product Search</h1>
<form id="search-form">
  <input name="q" placeholder="search products..." value="apple" />
  <button type="submit">Search</button>
</form>
<div id="results"></div>
<script src="/app.js"></script>
</body></html>
"""

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode())
        elif path == "/app.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript; charset=utf-8")
            self.end_headers()
            self.wfile.write(JS_CONTENT.encode())
        elif path == "/rest/products/search":
            q = urllib.parse.parse_qs(parsed.query).get("q", [""])[0]
            # REFLECTED SQLi: naive string concat vulnerable to quote injection
            # Response includes the raw query so error-based SQLi surfaces it
            body = json.dumps({
                "query": q,
                "results": [{"id": 1, "name": "apple"}, {"id": 2, "name": "banana"}],
                "sql_debug": f"SELECT * FROM products WHERE name LIKE '%{q}%'"
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /admin")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def log_message(self, *args):
        pass


def main():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 18080), Handler)
    print("Serving on http://127.0.0.1:18080")
    server.serve_forever()


if __name__ == "__main__":
    main()