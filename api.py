#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
api.py — API للاستعلام عن الأرقام، فوق نفس محرك البوت (app.py)

التشغيل هنا / على استضافتك / ترمكس:
    API_KEY=مفتاحك python api.py
    # أو:  python api.py --port 8000 --key مفتاحك
    # البورت الافتراضي 8000، ويقرأ PORT من البيئة (Render وغيرها)

الحماية: كل طلب لـ /lookup يحتاج مفتاحاً، إما هيدر:
    X-Api-Key: <المفتاح>
أو بارامتر:
    ?key=<المفتاح>
بدون مفتاح صحيح يرجع 401. غيّر المفتاح من متغير البيئة API_KEY.

الاستخدام:
    GET  /health
    GET  /lookup?number=+966552032016
    GET  /lookup?number=552032016&country=966
    POST /lookup   {"number": "+966552032016"}        أو {"number": "552032016", "country": "966"}

الرد الناجح:
    {"status": "ok", "number": "966552032016", "country": "966",
     "count": 10, "names": ["...", "..."]}

الرد الفارغ:
    {"status": "empty", "number": "...", "country": "966", "count": 0, "names": []}

الخطأ:
    {"status": "error", "number": "...", "error": "..."}

ملاحظة: يستخدم نفس post() المُصلح في app.py (IncompleteRead + بديل curl)،
فلا يحتاج أي إعداد إضافي. ضع هذا الملف بجانب app.py في نفس المجلد.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lookup_engine as app  # noqa: E402  (محرك البحث فقط، بدون بوت تلجرام)

API_KEY = os.environ.get("API_KEY", "")
KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "api_key.txt")

if not API_KEY and os.path.exists(KEY_FILE):
    with open(KEY_FILE, encoding="utf-8") as fh:
        API_KEY = fh.read().strip()

if not API_KEY:
    API_KEY = secrets.token_urlsafe(32)
    with open(KEY_FILE, "w", encoding="utf-8") as fh:
        fh.write(API_KEY)

# حد بسيط: طلب واحد كل ثانيتين من نفس الـ IP
_last_by_ip: dict = {}
_last_lock = threading.Lock()
COOLDOWN = 2.0


def _check_key(handler) -> bool:
    """يقبل الهيدر X-Api-Key أو بارامتر ?key= ."""
    key = handler.headers.get("X-Api-Key") or ""
    if not key:
        qs = parse_qs(urlparse(handler.path).query)
        key = (qs.get("key") or [""])[0]
    return bool(key) and key == API_KEY


def _lookup(number_raw: str, country: str):
    """نفس بحث البوت، ويعيد (status, names, message)."""
    country = re.sub(r"\D", "", country or "") or None
    detected = app.detect_country(number_raw)
    if not country:
        country = detected or app.DEFAULT_COUNTRY
    number = app.normalize_number(number_raw, country)
    res = app.lookup(number, country, "ar", app.opts())
    state, named, message = app.summarize(res)
    names = list(dict.fromkeys(n for _, n in named)) if state == "ok" else []
    if state == "ok":
        names = sorted(names, key=app.arabic_sort_key)
    return {
        "status": state,
        "number": number,
        "country": country,
        "count": len(names),
        "names": names,
        "error": message if state in ("error", "rejected") else "",
    }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # سجل مختصر بدون ضجيج
        sys.stderr.write(f"{self.log_date_time_string()} {self.address_string()} {fmt % args}\n")

    def _send(self, code: int, payload: dict):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _rate_limited(self) -> bool:
        ip = self.client_address[0]
        now = time.time()
        with _last_lock:
            last = _last_by_ip.get(ip, 0.0)
            if now - last < COOLDOWN:
                return True
            _last_by_ip[ip] = now
        return False

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/health"):
            return self._send(200, {"ok": True, "service": "phonebook-lookup",
                                    "bot": "@gagsysggsbot",
                                    "endpoints": ["GET /lookup?number=...&country=966",
                                                  "POST /lookup {\"number\": \"...\"}"]})
        if parsed.path != "/lookup":
            return self._send(404, {"status": "error", "error": "not found"})
        if not _check_key(self):
            return self._send(401, {"status": "error", "error": "unauthorized: bad or missing X-Api-Key"})
        if self._rate_limited():
            return self._send(429, {"status": "error", "error": "rate limited: wait 2 seconds"})
        qs = parse_qs(parsed.query)
        number = (qs.get("number") or [""])[0].strip()
        country = (qs.get("country") or [""])[0].strip()
        if not number:
            return self._send(400, {"status": "error", "error": "missing ?number="})
        try:
            return self._send(200, _lookup(number, country))
        except Exception as exc:  # noqa: BLE001
            return self._send(502, {"status": "error", "number": number, "error": str(exc)[:200]})

    def do_POST(self):
        if urlparse(self.path).path != "/lookup":
            return self._send(404, {"status": "error", "error": "not found"})
        if not _check_key(self):
            return self._send(401, {"status": "error", "error": "unauthorized: bad or missing X-Api-Key"})
        if self._rate_limited():
            return self._send(429, {"status": "error", "error": "rate limited: wait 2 seconds"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
            data = json.loads(self.rfile.read(length).decode("utf-8") or "{}") if length else {}
        except Exception:
            return self._send(400, {"status": "error", "error": "invalid JSON body"})
        number = str(data.get("number") or "").strip()
        country = str(data.get("country") or "").strip()
        if not number:
            return self._send(400, {"status": "error", "error": "missing number"})
        try:
            return self._send(200, _lookup(number, country))
        except Exception as exc:  # noqa: BLE001
            return self._send(502, {"status": "error", "number": number, "error": str(exc)[:200]})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--key", default=None, help="API key (يغلب API_KEY من البيئة)")
    args = parser.parse_args()
    global API_KEY
    if args.key:
        API_KEY = args.key
        with open(KEY_FILE, "w", encoding="utf-8") as fh:
            fh.write(API_KEY)
    print(f"API listening on http://{args.host}:{args.port}  (key in api_key.txt)", flush=True)
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
