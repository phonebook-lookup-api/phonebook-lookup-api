# wsgi.py - PhoneBook Lookup API as a WSGI app (PythonAnywhere, no Telegram bot)
import json
import os
import re
import sys
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lookup_engine as app

API_KEY = os.environ.get("API_KEY", "")
if not API_KEY:
    _kf = os.path.join(os.path.dirname(os.path.abspath(__file__)), "api_key.txt")
    if os.path.exists(_kf):
        with open(_kf, encoding="utf-8") as _fh:
            API_KEY = _fh.read().strip()

def _lookup(number_raw, country):
    country = re.sub(r"\D", "", country or "") or None
    detected = app.detect_country(number_raw)
    if not country:
        country = detected or app.DEFAULT_COUNTRY
    number = app.normalize_number(number_raw, country)
    res = app.lookup(number, country, "ar", app.opts())
    state, named, message = app.summarize(res)
    names = list(dict.fromkeys(n for _, n in named)) if state == "ok" else []
    return {"status": state, "number": number, "country": country,
            "count": len(names), "names": names, "error": message if state != "ok" else ""}

def application(environ, start_response):
    method = environ.get("REQUEST_METHOD", "GET")
    path = environ.get("PATH_INFO", "/")
    qs = parse_qs(environ.get("QUERY_STRING", ""))
    def send(code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        start_response(code, [("Content-Type", "application/json"), ("Content-Length", str(len(body)))])
        return [body]
    if path == "/health":
        return send("200 OK", {"ok": True, "service": "phonebook-lookup",
                               "endpoints": ["GET /lookup?number=...&country=966", "POST /lookup"]})
    if path != "/lookup":
        return send("404 Not Found", {"ok": False, "error": "not found"})
    key = environ.get("HTTP_X_API_KEY", "") or (qs.get("key") or [""])[0]
    if not key or key != API_KEY:
        return send("401 Unauthorized", {"ok": False, "error": "unauthorized"})
    if method == "GET":
        number = (qs.get("number") or [""])[0]
        country = (qs.get("country") or [""])[0]
    elif method == "POST":
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        raw = environ["wsgi.input"].read(length) if length else b""
        try:
            data = json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:
            data = {}
        number = str(data.get("number", ""))
        country = str(data.get("country", ""))
    else:
        return send("405 Method Not Allowed", {"ok": False, "error": "method not allowed"})
    if not number:
        return send("400 Bad Request", {"ok": False, "error": "number required"})
    return send("200 OK", _lookup(number, country))
