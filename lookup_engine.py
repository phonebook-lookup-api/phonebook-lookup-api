#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""lookup_engine.py - PhoneBook lookup engine only (API deploy, no Telegram bot)."""
from __future__ import annotations

import argparse
import base64
import csv
import http.client
import subprocess
import json
import os
import random
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid

# ----------------------------------------------------------------------------
# ثوابت مستخرجة من الحزمة
# ----------------------------------------------------------------------------
BASE_URL = "https://phonebookapp.xyz"
ENDPOINT_PATH = "/api/v5/allRequest"
KEY_ENCRYPT = "CCEAB2D44C1ABAEFE7ED4DFBF69FE4EB"
KEY_DECRYPT = "098BF9FFFECC092215E49B8677DEAA27"

APP_ID = "2"                 # قيمة AppId التي يرسلها التطبيق
FIREBASE_API_KEY = "AIzaSyCEFZd2FQTt-wn1nZ4hbC0PcJ90MoMhG8g"   # من resources.arsc
FIREBASE_SIGNUP = "https://identitytoolkit.googleapis.com/v1/accounts:signUp"
CACHE_FILE = os.path.join(os.path.expanduser("~"), ".phonebook_lookup.json")
PACKAGE_NAME = "com.app.phonedir"
APP_VERSION_NAME = "25"
APP_VERSION_CODE = "87"
SDK_VERSION = "36"

# التطبيق يرسل هذا الرأس صراحة عبر @Headers، والخادم يرفض غيره بخطأ 415
DEFAULT_CONTENT_TYPE = "application/json"

DEFAULT_COUNTRY = "962"      # الأردن — بادئات التطبيق 70/71/73/77/78
DEFAULT_LANG = "ar"


# ----------------------------------------------------------------------------
# AES-256-CBC — تنفيذ بايثون صرف (لا تبعيات خارجية)
# ----------------------------------------------------------------------------
def _gmul(a: int, b: int) -> int:
    """ضرب في حقل غالوا GF(2^8) بالمقياس 0x11B."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _rotl8(x: int, n: int) -> int:
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _build_sbox():
    """بناء S-box من المعكوس الضربي + التحويل الأفيني (بدل جدول مكتوب يدويًا)."""
    inv = [0] * 256
    for a in range(1, 256):
        for b in range(1, 256):
            if _gmul(a, b) == 1:
                inv[a] = b
                break
    sbox = [0] * 256
    for i in range(256):
        b = inv[i]
        sbox[i] = b ^ _rotl8(b, 1) ^ _rotl8(b, 2) ^ _rotl8(b, 3) ^ _rotl8(b, 4) ^ 0x63
    return sbox


SBOX = _build_sbox()
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D]


class AES256:
    """AES-256 مع CBC و PKCS5/PKCS7 — يكفي تمامًا لمخطط التطبيق."""

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("المفتاح يجب أن يكون 32 بايت (AES-256)")
        self.round_keys = self._expand(key)

    # --- توسيع المفتاح: Nk=8, Nr=14 ---
    def _expand(self, key: bytes):
        nk, nr = 8, 14
        w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
        for i in range(nk, 4 * (nr + 1)):
            temp = list(w[i - 1])
            if i % nk == 0:
                temp = temp[1:] + temp[:1]                      # RotWord
                temp = [SBOX[b] for b in temp]                   # SubWord
                temp[0] ^= RCON[i // nk - 1]
            elif nk > 6 and i % nk == 4:
                temp = [SBOX[b] for b in temp]
            w.append([w[i - nk][j] ^ temp[j] for j in range(4)])
        return [sum(w[4 * r:4 * r + 4], []) for r in range(nr + 1)]

    @staticmethod
    def _add_round_key(state, rk):
        return [s ^ k for s, k in zip(state, rk)]

    def _encrypt_block(self, block: bytes) -> bytes:
        s = list(block)
        s = self._add_round_key(s, self.round_keys[0])
        for rnd in range(1, 14):                       # 13 جولة كاملة مع MixColumns
            s = [SBOX[b] for b in s]
            # ShiftRows (الحالة عمودية: index = 4*col + row)
            s = [s[(4 * ((c + r) % 4)) + r] for c in range(4) for r in range(4)]
            mixed = []
            for c in range(4):
                col = s[4 * c:4 * c + 4]
                mixed += [
                    _gmul(col[0], 2) ^ _gmul(col[1], 3) ^ col[2] ^ col[3],
                    col[0] ^ _gmul(col[1], 2) ^ _gmul(col[2], 3) ^ col[3],
                    col[0] ^ col[1] ^ _gmul(col[2], 2) ^ _gmul(col[3], 3),
                    _gmul(col[0], 3) ^ col[1] ^ col[2] ^ _gmul(col[3], 2),
                ]
            s = self._add_round_key(mixed, self.round_keys[rnd])
        # الجولة الأخيرة: بلا MixColumns
        s = [SBOX[b] for b in s]
        s = [s[(4 * ((c + r) % 4)) + r] for c in range(4) for r in range(4)]
        s = self._add_round_key(s, self.round_keys[14])
        return bytes(s)

    def _decrypt_block(self, block: bytes) -> bytes:
        s = list(block)
        s = self._add_round_key(s, self.round_keys[14])
        for rnd in range(13, -1, -1):
            # InvShiftRows
            s = [s[(4 * ((c - r) % 4)) + r] for c in range(4) for r in range(4)]
            s = [INV_SBOX[b] for b in s]
            s = self._add_round_key(s, self.round_keys[rnd])
            if rnd != 0:
                unmixed = []
                for c in range(4):
                    col = s[4 * c:4 * c + 4]
                    unmixed += [
                        _gmul(col[0], 14) ^ _gmul(col[1], 11) ^ _gmul(col[2], 13) ^ _gmul(col[3], 9),
                        _gmul(col[0], 9) ^ _gmul(col[1], 14) ^ _gmul(col[2], 11) ^ _gmul(col[3], 13),
                        _gmul(col[0], 13) ^ _gmul(col[1], 9) ^ _gmul(col[2], 14) ^ _gmul(col[3], 11),
                        _gmul(col[0], 11) ^ _gmul(col[1], 13) ^ _gmul(col[2], 9) ^ _gmul(col[3], 14),
                    ]
                s = unmixed
        return bytes(s)

    # --- CBC بـ IV أصفار، كما في FunEncryptionV2 ---
    def encrypt_cbc(self, data: bytes) -> bytes:
        pad = 16 - (len(data) % 16)
        data = data + bytes([pad]) * pad
        out, prev = b"", b"\x00" * 16
        for i in range(0, len(data), 16):
            block = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
            prev = self._encrypt_block(block)
            out += prev
        return out

    def decrypt_cbc(self, data: bytes) -> bytes:
        out, prev = b"", b"\x00" * 16
        for i in range(0, len(data), 16):
            block = data[i:i + 16]
            dec = self._decrypt_block(block)
            out += bytes(a ^ b for a, b in zip(dec, prev))
            prev = block
        if out:
            pad = out[-1]
            if 1 <= pad <= 16 and out.endswith(bytes([pad]) * pad):
                out = out[:-pad]
        return out


_AES_ENC = AES256(KEY_ENCRYPT.encode())
_AES_DEC = AES256(KEY_DECRYPT.encode())
_AES_ALT = AES256(KEY_ENCRYPT.encode())   # احتياط: لو كان اتجاه المفتاحين معكوسًا


def encrypt_request(plaintext: str) -> str:
    """JSON → Base64(AES-256-CBC(UTF-8))."""
    return base64.b64encode(_AES_ENC.encrypt_cbc(plaintext.encode("utf-8"))).decode("ascii")


def decrypt_response(b64: str, aes=None) -> str:
    """Base64 → AES-256-CBC → JSON. يجرّب المفتاح الثاني تلقائيًا عند الفشل."""
    raw = base64.b64decode(b64.strip(), validate=False)
    if aes is not None:
        return aes.decrypt_cbc(raw).decode("utf-8", errors="replace")
    try:
        text = _AES_DEC.decrypt_cbc(raw).decode("utf-8")
        json.loads(text)
        return text
    except Exception:
        return _AES_ALT.decrypt_cbc(raw).decode("utf-8", errors="replace")


# ----------------------------------------------------------------------------
# هوية Firebase المجهولة — التطبيق يسجّل دخولًا مجهولًا ويرسل الـ uid
# ----------------------------------------------------------------------------
def _load_cache() -> dict:
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return {}
    return {}


def _save_cache(data: dict) -> None:
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False)
    except Exception:
        pass


def firebase_anonymous_uid(debug: bool = False, timeout: int = 25) -> str:
    """
    التطبيق (SharedViewModel) يقرأ firebaseId من DataStore، وإن كان فارغًا
    ينفّذ FirebaseAuth.signInAnonymously ويخزّن user.uid. نحن نفعل الشيء نفسه:
    نسجّل مستخدمًا مجهولًا عبر Identity Toolkit ونحفظ الـ uid محليًا.
    """
    cached = _load_cache()
    if cached.get("firebaseId"):
        if debug:
            print(f"  → FirebaseId من الذاكرة: {cached['firebaseId']}")
        return cached["firebaseId"]

    body = json.dumps({"clientType": "CLIENT_TYPE_ANDROID", "returnSecureToken": True}).encode()
    req = urllib.request.Request(
        f"{FIREBASE_SIGNUP}?key={FIREBASE_API_KEY}",
        data=body, method="POST", headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout,
                                context=ssl.create_default_context()) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    uid = data.get("localId")
    if not uid:
        raise RuntimeError(f"لم أستطع إنشاء هوية Firebase: {data}")
    cached["firebaseId"] = uid
    cached["idToken"] = data.get("idToken")
    _save_cache(cached)
    if debug:
        print(f"  → FirebaseId جديد (تسجيل مجهول): {uid}")
    return uid


# ----------------------------------------------------------------------------
# تطبيع أرقام الهاتف
# ----------------------------------------------------------------------------
def normalize_number(raw: str, country: str) -> str:
    """
    يحوّل أي صيغة إلى أرقام فقط مع بادئة الدولة.
      0791234567  + 962  →  962791234567
      +962791234567       →  962791234567
      00962791234567      →  962791234567
    """
    s = raw.strip()
    s = re.sub(r"[^\d+]", "", s)
    if s.startswith("+"):
        return s[1:]
    if s.startswith("00"):
        return s[2:]
    if s.startswith("0"):
        return country + s[1:]
    if s.startswith(country):
        return s
    return country + s


def split_number(raw: str, country: str):
    """
    يفصل الرقم كما يفعل التطبيق عبر libphonenumber:
      CleanPhone.b = getNationalNumber()   ← يُرسَل في ContactPhoneNo (بلا كود الدولة وبلا صفر)
      CleanPhone.c = getCountryCode()      ← يُرسَل في ContactCountryCode
    مثال: +966552032016 → ("552032016", "966")
    """
    digits = re.sub(r"\D", "", raw or "")
    if digits.startswith(country) and len(digits) > len(country) + 5:
        digits = digits[len(country):]
    digits = digits.lstrip("0")
    return digits, country


# ----------------------------------------------------------------------------
# بناء الطلب
# ----------------------------------------------------------------------------
def build_request(number: str, country: str, lang: str, args) -> dict:
    """
    يبني نفس JSON الذي يبنيه التطبيق حرفيًا.
    التطبيق يستخدم Gson، وGson يحذف الحقول الفارغة (null)، ولذلك لا يرسل
    سوى الحقول التسعة التالية في بحث الرقم — وقد تحقّقنا من ذلك من البايت‑كود:
      RequestType, FirebaseId, AppId, AppVersionName, PackageName,
      ContactPhoneNo, ContactCountryCode, IsAppInstalledFromGooglePlay, LanguageCode
    """
    body = {"RequestType": args.request_type}

    firebase_id = args.firebase_id
    if firebase_id is None and not args.no_firebase:
        firebase_id = firebase_anonymous_uid(args.debug, args.timeout)
    if firebase_id:
        body["FirebaseId"] = firebase_id

    body["AppId"] = APP_ID
    body["AppVersionName"] = APP_VERSION_NAME
    body["PackageName"] = PACKAGE_NAME
    national, cc = (number, country) if args.full_number else split_number(number, country)
    body["ContactPhoneNo"] = national
    body["ContactCountryCode"] = cc
    body["IsAppInstalledFromGooglePlay"] = True
    body["LanguageCode"] = lang
    if getattr(args, "member_id", None):
        body["MemberId"] = args.member_id

    # أي حقل إضافي أو تجاوز من سطر الأوامر
    for item in args.field or []:
        if "=" not in item:
            raise SystemExit("صيغة --field غير صحيحة، استخدم Key=Value")
        k, v = item.split("=", 1)
        if v.lower() in ("true", "false"):
            body[k] = v.lower() == "true"
        elif v == "":
            body.pop(k, None)
        else:
            body[k] = v
    return body


def build_init_request(firebase_id: str, first_run: bool, lang: str) -> dict:
    """نفس طلب GetAppInitializeData الذي يرسله التطبيق عند الإقلاع."""
    return {
        "RequestType": "GetAppInitializeData",
        "FirebaseId": firebase_id,
        "AppId": APP_ID,
        "AppVersionName": APP_VERSION_NAME,
        "PackageName": PACKAGE_NAME,
        "IsFirstRun": first_run,
        "IsUpdate": False,
        "LanguageCode": lang,
    }


def app_init(args, firebase_id: str):
    """
    التطبيق عند أول تشغيل يرسل GetAppInitializeData قبل أي بحث، والخادم قد
    يرفض البحث من هوية لم تُهيَّأ بعد (وهو ما يفسّر رسالة الخطأ العامة).
    """
    cache = _load_cache()
    first_run = not cache.get("initialized", False)
    body = build_init_request(firebase_id, first_run, args.lang)
    plain = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
    if args.debug:
        print("[تهيئة] JSON:", plain)
    url = (args.base_url or BASE_URL).rstrip("/") + (args.endpoint or ENDPOINT_PATH)
    try:
        status, text = post(url, encrypt_request(plain), args.timeout, args.debug, args.content_type)
        dec = decrypt_response(text)
        if args.debug:
            print("[تهيئة] الاستجابة:", dec[:400])
        cache["initialized"] = True
        _save_cache(cache)
        return {"status": status, "data": dec}
    except Exception as exc:
        if args.debug:
            print("[تهيئة] فشلت التهيئة:", exc)
        return {"error": str(exc)}


# ----------------------------------------------------------------------------
# الاتصال بالخادم
# ----------------------------------------------------------------------------
def post(url: str, payload: str, timeout: int, debug: bool = False, content_type: str = DEFAULT_CONTENT_TYPE):
    req = urllib.request.Request(
        url,
        data=payload.encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": content_type,
            "Accept": "text/plain",
            "User-Agent": "okhttp/4.12.0",
        },
    )
    if debug:
        print(f"  → POST {url}")
        print(f"  → طول الجسم المشفّر: {len(payload)} حرفًا")
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            try:
                return resp.status, resp.read().decode("utf-8", errors="replace")
            except http.client.IncompleteRead as exc:
                # الرد chunked من Cloudflare والبروكسي يغلق الاتصال قبل
                # قطعة الإنهاء، فيرمي urllib هذا الخطأ. الجزء المقروء
                # يكون غالباً الرد الكامل (4312 بايت في الرقم التجريبي)،
                # فنعيده إن فكّ تشفيره JSON سليماً.
                partial = exc.partial or b""
                if partial:
                    try:
                        text = partial.decode("utf-8", errors="replace")
                        json.loads(decrypt_response(text))
                        return resp.status, text
                    except Exception:
                        pass
                raise
    except Exception as first_err:
        # بديل curl: يتحمّل الـ chunked الناقص ويعيد الجسم كاملاً
        # (5/5 ناجحة على الرقم التجريبي مقابل فشل urllib المتكرر).
        # يُستخدم فقط عند فشل urllib، ويُقبل فقط إن فكّ تشفيره JSON سليماً.
        try:
            proc = subprocess.run(
                ["curl", "-sS", "--max-time", str(timeout), "-X", "POST", url,
                 "-H", f"Content-Type: {content_type}",
                 "-H", "Accept: text/plain",
                 "-H", "User-Agent: okhttp/4.12.0",
                 "--data-binary", payload,
                 "-w", "\n__CURL_STATUS__:%{http_code}"],
                capture_output=True, text=True, timeout=timeout + 5)
            out = proc.stdout or ""
            if "\n__CURL_STATUS__:" in out:
                text, _, status_txt = out.rpartition("\n__CURL_STATUS__:")
                status = int(status_txt.strip())
                json.loads(decrypt_response(text))
                return status, text
        except Exception:
            pass
        raise first_err


def lookup(number: str, country: str, lang: str, args) -> dict:
    """يبحث عن رقم واحد ويعيد قاموسًا بالنتيجة."""
    body = build_request(number, country, lang, args)
    plain = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
    cipher = encrypt_request(plain)
    if args.quote_body:                                  # بعض الخوادم تتوقع JSON string
        cipher = json.dumps(cipher)

    if args.debug:
        print(f"\n[طلب] {number}")
        print("  JSON قبل التشفير:", plain)

    url = (args.base_url or BASE_URL).rstrip("/") + (args.endpoint or ENDPOINT_PATH)
    last_err = None
    for attempt in range(args.retries + 1):
        try:
            status, text = post(url, cipher, args.timeout, args.debug, args.content_type)
            if args.raw:
                try:
                    dec = decrypt_response(text)
                except Exception:
                    dec = None
                return {"number": number, "status": status, "raw": text, "decrypted": dec}
            try:
                data = json.loads(decrypt_response(text))
            except Exception as exc:                      # استجابة غير مشفّرة أو تالفة
                return {"number": number, "status": status, "raw": text,
                        "error": f"تعذّر فك الاستجابة: {exc}"}
            return {"number": number, "status": status, "data": data}
        except urllib.error.HTTPError as exc:
            body_err = exc.read().decode("utf-8", errors="replace")[:400]
            last_err = f"HTTP {exc.code}: {body_err}"
            if exc.code in (400, 401, 403, 404, 415, 422):
                break                                     # خطأ ثابت، لا فائدة من الإعادة
        except urllib.error.URLError as exc:
            last_err = f"تعذّر الوصول إلى الخادم: {exc.reason}"
        except Exception as exc:
            last_err = str(exc)
        if attempt < args.retries:
            time.sleep(args.delay * (attempt + 1))
    return {"number": number, "error": last_err}


# ----------------------------------------------------------------------------
# عرض النتائج
# ----------------------------------------------------------------------------
NAME_KEYS = ("name", "Name", "fullName", "contactName", "displayName", "memberName", "title")
_AR_DIACRITICS = re.compile(r"[\u064B-\u0652\u0670\u0640]")   # تشكيل وتطويل


def arabic_sort_key(name: str) -> str:
    """مفتاح ترتيب عربي: يتجاهل التشكيل ويوحّد الألف والهمزة والتاء المربوطة."""
    key = _AR_DIACRITICS.sub("", name or "")
    for a, b in (("أ", "ا"), ("إ", "ا"), ("آ", "ا"), ("ة", "ه"), ("ى", "ي"), ("ؤ", "و"), ("ئ", "ي")):
        key = key.replace(a, b)
    return key.strip().casefold()


def extract_names(payload):
    """
    يستخرج الأسماء من استجابة البحث. الخادم يعيد قائمة عناصر فيها
    ContactName و RowNumber، ونستخدم RowNumber لترتيب الخادم عند الطلب.
    """
    items = payload if isinstance(payload, list) else [payload]
    named = []
    for item in items:
        if isinstance(item, dict):
            for key in ("ContactName", "BusinessName", "Name", "name"):
                val = item.get(key)
                if isinstance(val, str) and val.strip():
                    named.append((item.get("RowNumber") or 0, val.strip()))
                    break
    if named:
        return named
    return [(0, n) for n in _find_names(payload)]


def _find_names(obj, depth=0):
    """يجمع أي قيم تبدو كأسماء بشرية داخل الاستجابة، مهما كان شكلها."""
    found = []
    if depth > 6:
        return found
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and any(n.lower() in k.lower() for n in NAME_KEYS) and v.strip():
                found.append(v.strip())
            else:
                found.extend(_find_names(v, depth + 1))
    elif isinstance(obj, list):
        for item in obj:
            found.extend(_find_names(item, depth + 1))
    return found


def summarize(res: dict):
    """يستخرج (الحالة، الأسماء، رسالة الخادم) من استجابة التطبيق."""
    if "error" in res:
        return "error", [], res["error"]
    if "data" not in res:
        return "raw", [], ""
    data = res["data"]
    if isinstance(data, dict):
        if data.get("IsFail") is True or data.get("IsSuccess") is False:
            return "rejected", [], (data.get("ExceptionMessage") or "رفض الخادم الطلب")
        payload = data.get("Data")
    else:
        payload = data
    if payload in (None, [], {}, ""):
        return "empty", [], ""
    return "ok", extract_names(payload), ""


def print_result(res: dict, as_json: bool, brief: bool = False,
                 details: bool = False, order: str = "alpha"):
    """يطبع الأسماء فقط بشكل مرتّب. --details يضيف الاستجابة الكاملة."""
    if as_json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return
    state, named, message = summarize(res)

    if state == "error" or state == "rejected":
        print(f"{res['number']}  ✗  {message[:120]}")
        return
    if state == "raw":
        print(f"{res['number']}  حالة HTTP: {res['status']}")
        text = res.get("decrypted") or res.get("raw") or ""
        print("  " + text[:4000])
        return
    if state == "empty":
        print(f"{res['number']}  —  لا يوجد اسم مسجّل")
        return

    if order == "server":
        names = [n for _, n in sorted(named, key=lambda x: x[0])]
    else:
        names = sorted((n for _, n in named), key=arabic_sort_key)
    names = list(dict.fromkeys(names))                    # بلا تكرار مع حفظ الترتيب

    if brief:
        print(f"{res['number']}  ✓  " + "، ".join(names))
        return
    print("─" * 62)
    print(f"{res['number']}  ({len(names)} اسمًا)")
    for i, name in enumerate(names, 1):
        print(f"  {i:>2}. {name}")
    if details:
        print("\n  التفاصيل الكاملة:")
        print(json.dumps(res["data"], ensure_ascii=False, indent=2))


# ----------------------------------------------------------------------------
# اختبار ذاتي للتشفير
# ----------------------------------------------------------------------------
def self_test() -> bool:
    """يتحقق من صحة تنفيذ AES-256 مقابل متجه NIST المعروف."""
    key = bytes(range(32))
    plain = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected = "8ea2b7ca516745bfeafc49904b496089"
    aes = AES256(key)
    enc = aes._encrypt_block(plain)
    ok = enc.hex() == expected and aes._decrypt_block(enc) == plain
    sample = '{"RequestType":"SearchByPhoneNumber","ContactPhoneNo":"962790000000"}'
    cipher = AES256(KEY_ENCRYPT.encode())
    ok = ok and cipher.decrypt_cbc(cipher.encrypt_cbc(sample.encode())) == sample.encode()
    print("اختبار AES-256:", "ناجح ✓" if ok else "فاشل ✗")
    print("  متجه NIST:", enc.hex())
    print("  الترميز/فك الترميز بمفاتيح التطبيق:", "سليم ✓" if ok else "خطأ ✗")
    return ok



# ══════════════════════════════════════════════════════════════════════════
#  ضع توكن البوت هنا بين علامتي التنصيص

# --- Countries (API only, no Telegram bot) ---
COUNTRIES = [
    ("🇸🇦 السعودية", "966"),
    ("🇯🇴 الأردن", "962"),
    ("🇪🇬 مصر", "20"),
    ("🇦🇪 الإمارات", "971"),
    ("🇰🇼 الكويت", "965"),
    ("🇶🇦 قطر", "974"),
    ("🇧🇭 البحرين", "973"),
    ("🇴🇲 عُمان", "968"),
    ("🇮🇶 العراق", "964"),
    ("🇸🇾 سوريا", "963"),
    ("🇵🇸 فلسطين", "970"),
    ("🇱🇧 لبنان", "961"),
    ("🇾🇪 اليمن", "967"),
    ("🇱🇾 ليبيا", "218"),
    ("🇹🇳 تونس", "216"),
    ("🇩🇿 الجزائر", "213"),
    ("🇲🇦 المغرب", "212"),
    ("🇸🇩 السودان", "249"),
    ("🇹🇷 تركيا", "90"),
    ("🌍 دولة أخرى", "other"),
]
CODE_TO_NAME = {code: name for name, code in COUNTRIES}

class Opts:
    """خيارات المحرّك (نفس افتراضيات أداة سطر الأوامر)."""
    request_type = "SearchByPhoneNumber"
    lang = "ar"
    field = None
    member_id = None
    firebase_id = None
    no_firebase = False
    full_number = False
    base_url = None
    endpoint = None
    content_type = DEFAULT_CONTENT_TYPE
    timeout = 15
    retries = 4
    delay = 1.0
    debug = False
    raw = False
    quote_body = False

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        return None


def opts():
    return Opts()

def detect_country(text):
    raw = (text or "").strip()
    if not raw.startswith(("+", "00")):
        return None
