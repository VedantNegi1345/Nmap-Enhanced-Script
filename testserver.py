#!/usr/bin/env python3
"""Tiny local test server for the http-robots DA. Run: python3 testserver.py 8080"""
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

ROBOTS = """User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /old/
Disallow: /private/
Disallow: /secret-old-page/
Disallow: /tmp/
Disallow: /*.pdf$
Allow: /public/
Crawl-delay: 10

User-agent: Googlebot
User-agent: Bingbot
Disallow: /api/

Sitemap: http://127.0.0.1:{port}/sitemap_index.xml
Sitemap: http://127.0.0.1:{port}/sitemap.xml
"""
SITEMAP = """<?xml version="1.0"?><urlset>
<url><loc>http://127.0.0.1:{port}/</loc></url>
<url><loc>http://127.0.0.1:{port}/about</loc></url>
<url><loc>http://127.0.0.1:{port}/hidden-landing-page</loc></url>
<url><loc>http://127.0.0.1:{port}/products?id=1&amp;ref=2</loc></url>
</urlset>"""
INDEX = """<?xml version="1.0"?><sitemapindex>
<sitemap><loc>http://127.0.0.1:{port}/sitemap.xml</loc></sitemap>
</sitemapindex>"""
STATUS = {"/admin/": 200, "/backup/": 403, "/private/": 401, "/api/": 200}

class H(BaseHTTPRequestHandler):
    def respond(self, code, body="", extra=None, head=False):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if not head:
            self.wfile.write(data)
    def handle_any(self, head):
        p = self.path.split("?")[0]
        port = self.server.server_port
        if p == "/robots.txt": return self.respond(200, ROBOTS.format(port=port), head=head)
        if p == "/sitemap.xml": return self.respond(200, SITEMAP.format(port=port), head=head)
        if p == "/sitemap_index.xml": return self.respond(200, INDEX.format(port=port), head=head)
        if p == "/old/": return self.respond(301, "", {"Location": "/new/"}, head)
        if p in STATUS: return self.respond(STATUS[p], "ok", head=head)
        return self.respond(404, "not found", head=head)
    def do_GET(self): self.handle_any(False)
    def do_HEAD(self): self.handle_any(True)
    def log_message(self, *a): pass

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    HTTPServer(("127.0.0.1", port), H).serve_forever()
