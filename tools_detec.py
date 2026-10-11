#!/usr/bin/env python3
"""
TechScan — Wappalyzer uslubidagi veb-texnologiya va versiya aniqlovchi.

Imkoniyatlar:
  * 7000+ texnologiya bazasi (Wappalyzer formatidagi ochiq baza, --update bilan yuklanadi)
  * Offlayn ishlash uchun ichki zaxira baza
  * Tekshiriladigan manbalar: HTTP sarlavhalar, cookie, meta teglar, HTML, script src,
    inline va tashqi JS fayllar, CSS, URL, robots.txt, SSL sertifikat beruvchisi,
    DNS yozuvlari (TXT/MX/NS/CNAME), DOM selektorlar, JS global o'zgaruvchilar (--browser)
  * Versiyani aniqlash (regex guruhlari, ternar shablonlar)
  * implies / requires / excludes mantiqi, ishonch darajasi
  * --aggressive: CMS versiya fayllarini tekshirish, 404 sahifa tahlili
  * Ko'p URL, parallel skanerlash, JSON chiqish
"""
import argparse
import json
import os
import random
import re
import socket
import ssl
import string
import sys
import time
import warnings
import concurrent.futures as cf
from collections import defaultdict
from urllib.parse import urljoin, urlparse

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    warnings.simplefilter("ignore", InsecureRequestWarning)
except ImportError:
    sys.exit("[!] 'requests' kerak:  pip install requests")

try:
    from bs4 import BeautifulSoup
    warnings.filterwarnings("ignore", category=UserWarning, module="bs4")
    HAVE_BS4 = True
except ImportError:
    HAVE_BS4 = False

try:
    import dns.resolver
    HAVE_DNS = True
except ImportError:
    HAVE_DNS = False

VERSION = "1.0"
CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "techscan")
DB_URL = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36")
MAX_HTML = 2_000_000
MAX_JS_FILES = 25
MAX_CSS_FILES = 10
MAX_ASSET = 1_500_000

# ---------------------------------------------------------------- ranglar
C = {"r": "\033[31m", "g": "\033[32m", "y": "\033[33m", "b": "\033[34m",
     "m": "\033[35m", "c": "\033[36m", "w": "\033[1m", "d": "\033[2m", "x": "\033[0m"}
if not sys.stdout.isatty() or os.name == "nt" and "WT_SESSION" not in os.environ:
    C = {k: "" for k in C}


def log(msg, quiet=False):
    if not quiet:
        print(msg, file=sys.stderr)


# ================================================================ BAZA
def update_db(quiet=False):
    """Ochiq Wappalyzer bazasini (enthec/webappanalyzer) yuklab keshga saqlaydi."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    techs = {}
    names = ["_"] + list(string.ascii_lowercase)
    s = requests.Session()

    def get(n):
        r = s.get(f"{DB_URL}/technologies/{n}.json", timeout=30)
        r.raise_for_status()
        return r.json()

    with cf.ThreadPoolExecutor(8) as ex:
        for part in ex.map(get, names):
            techs.update(part)
    cats = s.get(f"{DB_URL}/categories.json", timeout=30).json()
    with open(os.path.join(CACHE_DIR, "technologies.json"), "w") as f:
        json.dump(techs, f)
    with open(os.path.join(CACHE_DIR, "categories.json"), "w") as f:
        json.dump(cats, f)
    log(f"{C['g']}[+] Baza yangilandi: {len(techs)} ta texnologiya, {len(cats)} ta kategoriya{C['x']}", quiet)


def load_db(extra=None, quiet=False):
    tpath = os.path.join(CACHE_DIR, "technologies.json")
    cpath = os.path.join(CACHE_DIR, "categories.json")
    if not os.path.exists(tpath):
        log(f"{C['y']}[*] To'liq baza topilmadi, yuklanmoqda...{C['x']}", quiet)
        try:
            update_db(quiet)
        except Exception as e:
            log(f"{C['y']}[!] Yuklab bo'lmadi ({e}). Ichki zaxira baza ishlatiladi.{C['x']}", quiet)
    techs, cats = {}, {}
    if os.path.exists(tpath):
        techs = json.load(open(tpath))
        cats = json.load(open(cpath))
    # ichki baza: to'liq bazada yo'q bo'lganlarini qo'shadi, mavjudlariga patternlarni birlashtiradi
    for name, t in BUILTIN_TECHS.items():
        if name not in techs:
            techs[name] = t
        else:
            merge_tech(techs[name], t)
    for k, v in BUILTIN_CATS.items():
        cats.setdefault(k, v)
    if extra:
        for path in extra:
            for name, t in json.load(open(path)).items():
                if name in techs:
                    merge_tech(techs[name], t)
                else:
                    techs[name] = t
    return techs, cats


def merge_tech(dst, src):
    for k, v in src.items():
        if k not in dst:
            dst[k] = v
        elif isinstance(v, dict) and isinstance(dst[k], dict):
            for kk, vv in v.items():
                if kk not in dst[k]:
                    dst[k][kk] = vv
                else:
                    a = dst[k][kk] if isinstance(dst[k][kk], list) else [dst[k][kk]]
                    b = vv if isinstance(vv, list) else [vv]
                    dst[k][kk] = a + [x for x in b if x not in a]
        elif isinstance(v, (list, str)) and k not in ("description", "website", "icon", "cpe"):
            a = dst[k] if isinstance(dst[k], list) else [dst[k]]
            b = v if isinstance(v, list) else [v]
            dst[k] = a + [x for x in b if x not in a]


# ================================================================ PATTERNLAR
_re_cache = {}


def parse_pattern(raw):
    """'regex\\;version:\\1\\;confidence:50' ko'rinishidagi patternni ajratadi."""
    if isinstance(raw, (int, float, bool)):
        raw = str(raw)
    if raw in _re_cache:
        return _re_cache[raw]
    parts = raw.split("\\;")
    attrs = {}
    for p in parts[1:]:
        if ":" in p:
            k, v = p.split(":", 1)
            attrs[k.strip()] = v
    regex = parts[0]
    try:
        comp = re.compile(regex, re.I)
    except re.error:
        try:
            comp = re.compile(re.escape(regex), re.I)
        except re.error:
            comp = None
    try:
        conf = int(attrs.get("confidence", 100))
    except ValueError:
        conf = 100
    res = {"re": comp, "version": attrs.get("version", ""), "confidence": conf, "raw": regex}
    _re_cache[raw] = res
    return res


def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def resolve_version(tpl, m):
    if not tpl or m is None:
        return ""
    groups = [m.group(0)] + list(m.groups())

    def g(i):
        i = int(i)
        return (groups[i] or "") if i < len(groups) else ""

    def ternary(mm):
        return mm.group(2) if g(mm.group(1)) else mm.group(3)

    v = re.sub(r"\\(\d+)\?([^:]*):(.*)", ternary, tpl)
    v = re.sub(r"\\(\d+)", lambda mm: g(mm.group(1)), v)
    v = v.strip()
    if len(v) > 40 or not re.search(r"\d", v):
        return "" if len(v) > 40 else v
    return v


def match_one(pat, value):
    """Bitta qiymatga pattern qo'llaydi -> (moslik, versiya, ishonch) yoki None."""
    p = parse_pattern(pat)
    if p["re"] is None:
        return None
    if value is None:
        return None
    if p["raw"] == "":
        return (True, "", p["confidence"])
    m = p["re"].search(value)
    if not m:
        return None
    return (True, resolve_version(p["version"], m), p["confidence"])


# ================================================================ YIG'ISH
class Page:
    def __init__(self):
        self.url = ""
        self.urls = []
        self.status = None
        self.headers = defaultdict(list)   # lower-name -> [values]
        self.cookies = {}                   # lower-name -> value
        self.html = ""
        self.extra_html = []                # 404 sahifa va boshqalar
        self.meta = defaultdict(list)
        self.script_src = []
        self.scripts = []                   # inline + tashqi JS kontent
        self.css = []
        self.css_links = []
        self.robots = ""
        self.text = ""
        self.cert_issuer = ""
        self.dns = defaultdict(list)
        self.js = {}                        # brauzer rejimida
        self.soup = None
        self.probe_hits = []                # aggressive natijalari
        self.title = ""
        self.ip = ""


META_RE = re.compile(r"<meta\b[^>]*>", re.I | re.S)
ATTR_RE = re.compile(r"""([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""", re.S)
SCRIPT_RE = re.compile(r"<script\b([^>]*)>(.*?)</script>", re.I | re.S)
LINK_RE = re.compile(r"<link\b[^>]*>", re.I | re.S)
STYLE_RE = re.compile(r"<style\b[^>]*>(.*?)</style>", re.I | re.S)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def attrs_of(tag):
    return {m.group(1).lower(): (m.group(2) or m.group(3) or m.group(4) or "") for m in ATTR_RE.finditer(tag)}


def parse_html(page):
    html = page.html
    for tag in META_RE.findall(html):
        a = attrs_of(tag)
        key = a.get("name") or a.get("property") or a.get("http-equiv") or a.get("itemprop")
        if key and "content" in a:
            page.meta[key.lower()].append(a["content"])
    for attrs, body in SCRIPT_RE.findall(html):
        a = attrs_of(attrs)
        if a.get("src"):
            page.script_src.append(urljoin(page.url, a["src"].strip()))
        elif body.strip():
            page.scripts.append(body)
    for tag in LINK_RE.findall(html):
        a = attrs_of(tag)
        rel = a.get("rel", "").lower()
        href = a.get("href")
        if href and "stylesheet" in rel:
            page.css_links.append(urljoin(page.url, href.strip()))
        if href and ("preload" in rel or "modulepreload" in rel) and a.get("as", "") == "script":
            page.script_src.append(urljoin(page.url, href.strip()))
    page.css.extend(STYLE_RE.findall(html))
    t = TITLE_RE.search(html)
    page.title = re.sub(r"\s+", " ", t.group(1)).strip()[:120] if t else ""
    if HAVE_BS4:
        try:
            page.soup = BeautifulSoup(html, "html.parser")
            for s in page.soup(["script", "style", "noscript"]):
                s.extract()
            page.text = page.soup.get_text(" ", strip=True)[:200_000]
            page.soup = BeautifulSoup(html, "html.parser")
        except Exception:
            page.soup = None
    if not page.text:
        page.text = re.sub(r"<[^>]+>", " ", re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", html, flags=re.S | re.I))
        page.text = re.sub(r"\s+", " ", page.text)[:200_000]


def get_cert_issuer(host, port=443, timeout=6):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                der = ss.getpeercert(binary_form=True)
        # DER ichidan Organization (O=) ni oddiy yo'l bilan ajratish
        try:
            from cryptography import x509
            cert = x509.load_der_x509_certificate(der)
            parts = [a.value for a in cert.issuer]
            return ", ".join(parts)
        except Exception:
            txt = der.decode("latin-1", "ignore")
            found = re.findall(r"[A-Za-z][A-Za-z0-9 '.,-]{3,60}", txt)
            return " ".join(found[:12])
    except Exception:
        return ""


def get_dns(host, timeout=5):
    out = defaultdict(list)
    if not HAVE_DNS:
        return out
    res = dns.resolver.Resolver()
    res.lifetime = timeout
    parts = host.split(".")
    root = ".".join(parts[-2:]) if len(parts) >= 2 else host
    for rtype, name in (("TXT", root), ("MX", root), ("NS", root), ("SOA", root), ("CNAME", host)):
        try:
            for r in res.resolve(name, rtype):
                out[rtype.lower()].append(r.to_text().strip('"'))
        except Exception:
            pass
    return out


def fetch(session, url, timeout, limit=MAX_HTML):
    r = session.get(url, timeout=timeout, allow_redirects=True, stream=True)
    content = b""
    for chunk in r.iter_content(65536):
        content += chunk
        if len(content) >= limit:
            break
    r._content = content
    return r


def collect(url, args, quiet=False):
    page = Page()
    s = requests.Session()
    s.headers.update({"User-Agent": args.ua, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                      "Accept-Language": "en-US,en;q=0.9"})
    s.verify = not args.insecure
    if args.proxy:
        s.proxies = {"http": args.proxy, "https": args.proxy}
    for h in args.header or []:
        if ":" in h:
            k, v = h.split(":", 1)
            s.headers[k.strip()] = v.strip()

    r = fetch(s, url, args.timeout)
    page.url = r.url
    page.status = r.status_code
    page.urls = [h.url for h in r.history] + [r.url]
    for resp in list(r.history) + [r]:
        for k, v in resp.raw.headers.items():
            page.headers[k.lower()].append(v)
        for c in resp.cookies:
            page.cookies[c.name.lower()] = c.value or ""
    for c in s.cookies:
        page.cookies.setdefault(c.name.lower(), c.value or "")
    enc = r.encoding if r.encoding and r.encoding.lower() != "iso-8859-1" else (r.apparent_encoding or "utf-8")
    page.html = r.content.decode(enc or "utf-8", "replace")
    parse_html(page)

    host = urlparse(page.url).hostname or ""
    origin = f"{urlparse(page.url).scheme}://{urlparse(page.url).netloc}"
    try:
        page.ip = socket.gethostbyname(host)
    except Exception:
        pass

    tasks = {}
    with cf.ThreadPoolExecutor(12) as ex:
        # tashqi JS fayllar
        for src in dict.fromkeys(page.script_src).keys():
            if len([t for t in tasks.values() if t[0] == "js"]) >= MAX_JS_FILES:
                break
            if src.startswith("http"):
                tasks[ex.submit(fetch, s, src, args.timeout, MAX_ASSET)] = ("js", src)
        for href in list(dict.fromkeys(page.css_links))[:MAX_CSS_FILES]:
            if href.startswith("http"):
                tasks[ex.submit(fetch, s, href, args.timeout, MAX_ASSET)] = ("css", href)
        tasks[ex.submit(fetch, s, origin + "/robots.txt", args.timeout, 200_000)] = ("robots", "")
        if page.url.startswith("https"):
            tasks[ex.submit(get_cert_issuer, host)] = ("cert", "")
        if not args.no_dns:
            tasks[ex.submit(get_dns, host)] = ("dns", "")
        if args.aggressive:
            rnd = "".join(random.choices(string.ascii_lowercase, k=12))
            tasks[ex.submit(fetch, s, f"{origin}/{rnd}.html", args.timeout, 300_000)] = ("404", "")
            for path, tech, rx, ver in PROBES:
                tasks[ex.submit(fetch, s, origin + path, args.timeout, 300_000)] = ("probe", (path, tech, rx, ver))

        for fut in cf.as_completed(tasks):
            kind, info = tasks[fut]
            try:
                res = fut.result()
            except Exception:
                continue
            if kind == "js":
                if res.ok:
                    page.scripts.append(res.content.decode("utf-8", "replace"))
                    for k, v in res.raw.headers.items():
                        if k.lower() in ("server", "x-powered-by", "via", "x-cache", "cf-ray", "x-amz-cf-id"):
                            if v not in page.headers[k.lower()]:
                                page.headers[k.lower()].append(v)
            elif kind == "css":
                if res.ok:
                    page.css.append(res.content.decode("utf-8", "replace"))
            elif kind == "robots":
                if res.ok and "html" not in res.headers.get("content-type", ""):
                    page.robots = res.content.decode("utf-8", "replace")
            elif kind == "cert":
                page.cert_issuer = res
            elif kind == "dns":
                page.dns = res
            elif kind == "404":
                body = res.content.decode("utf-8", "replace")
                page.extra_html.append(body)
                for k, v in res.raw.headers.items():
                    if v not in page.headers[k.lower()]:
                        page.headers[k.lower()].append(v)
            elif kind == "probe":
                path, tech, rx, ver = info
                if res.status_code == 200 and res.url.rstrip("/").endswith(path.rstrip("/").split("?")[0]):
                    body = res.content.decode("utf-8", "replace")
                    m = re.search(rx, body, re.I | re.S)
                    if m:
                        page.probe_hits.append((tech, resolve_version(ver, m), path))

    if args.browser:
        browser_collect(page, url, args, quiet)
    return page


JS_PROBE = """
const props = arguments.length ? arguments[0] : __PROPS__;
const out = {};
for (const p of props) {
    try {
        let v = window;
        for (const k of p.split('.')) {
            if (v === undefined || v === null) { v = undefined; break; }
            v = v[k];
        }
        if (v === undefined || v === null) continue;
        const t = typeof v;
        out[p] = (t === 'string' || t === 'number' || t === 'boolean') ? String(v) : '';
    } catch (e) {}
}
return out;
"""
BROWSER_LOCK = __import__("threading").Lock()


def browser_collect(page, url, args, quiet):
    """Headless brauzer orqali JS o'zgaruvchilar, dinamik DOM va cookie larni yig'adi.
    Avval Playwright, ishlamasa Selenium + chromedriver sinab ko'riladi."""
    props = sorted({p for t in TECHS.values() for p in (t.get("js") or {}).keys()})
    with BROWSER_LOCK:
        data = None
        errors = []
        for backend in (_browser_playwright, _browser_selenium):
            try:
                data = backend(url, args, props)
                break
            except Exception as e:
                errors.append(f"{backend.__name__[9:]}: {str(e).splitlines()[0][:120]}")
    if not data:
        log(f"{C['y']}[!] Brauzer rejimi ishlamadi ({'; '.join(errors)}).\n"
            f"    O'rnating: pip install selenium (chromium + chromedriver bilan) yoki "
            f"pip install playwright && playwright install chromium{C['x']}", quiet)
        return
    page.js = data["js"] or {}
    page.extra_html.append(data["html"])
    for name, value in data["cookies"]:
        page.cookies.setdefault(name.lower(), value or "")
    for u in data["requests"]:
        if (u.endswith(".js") or ".js?" in u) and u not in page.script_src:
            page.script_src.append(u)
    if HAVE_BS4:
        page.soup = BeautifulSoup(data["html"], "html.parser")


def _browser_playwright(url, args, props):
    import asyncio
    from playwright.sync_api import sync_playwright
    loop = asyncio.new_event_loop()
    loop.set_exception_handler(lambda *a: None)   # drayver xatolarining shovqinini bosish
    asyncio.set_event_loop(loop)
    with sync_playwright() as pw:
        b = pw.chromium.launch(headless=True)
        try:
            ctx = b.new_context(user_agent=args.ua, ignore_https_errors=True)
            pg = ctx.new_page()
            reqs = []
            pg.on("request", lambda rq: reqs.append(rq.url))
            pg.goto(url, timeout=args.timeout * 3000, wait_until="networkidle")
            pg.wait_for_timeout(1500)
            js = pg.evaluate("(props) => {" + JS_PROBE.replace("arguments.length ? arguments[0] : __PROPS__", "props") + "}", props)
            return {"js": js, "html": pg.content(),
                    "cookies": [(c["name"], c.get("value", "")) for c in ctx.cookies()], "requests": reqs}
        finally:
            b.close()


def _browser_selenium(url, args, props):
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    opts = Options()
    for a in ("--headless=new", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
              "--ignore-certificate-errors", f"--user-agent={args.ua}"):
        opts.add_argument(a)
    opts.set_capability("goog:loggingPrefs", {"performance": "ALL"})
    for path in ("/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/google-chrome"):
        if os.path.exists(path):
            opts.binary_location = path
            break
    from selenium.webdriver.chrome.service import Service
    drvpath = next((p for p in ("/usr/bin/chromedriver", "/usr/local/bin/chromedriver") if os.path.exists(p)), None)
    drv = webdriver.Chrome(options=opts, service=Service(drvpath) if drvpath else None)
    try:
        drv.set_page_load_timeout(args.timeout * 3)
        drv.get(url)
        time.sleep(2.5)
        js = drv.execute_script(JS_PROBE.replace("__PROPS__", "[]"), props)
        reqs = []
        try:
            for entry in drv.get_log("performance"):
                msg = json.loads(entry["message"])["message"]
                if msg.get("method") == "Network.requestWillBeSent":
                    reqs.append(msg["params"]["request"]["url"])
        except Exception:
            pass
        return {"js": js, "html": drv.page_source,
                "cookies": [(c["name"], c.get("value", "")) for c in drv.get_cookies()], "requests": reqs}
    finally:
        drv.quit()


# ================================================================ ANIQLASH
class Detection:
    __slots__ = ("name", "confidence", "versions", "evidence")

    def __init__(self, name):
        self.name = name
        self.confidence = 0
        self.versions = defaultdict(int)
        self.evidence = []

    def add(self, version, conf, ev):
        self.confidence = min(100, self.confidence + conf)
        if version:
            # ishonchli manbalar (JS o'zgaruvchi, versiya fayli) va nuqtali versiyalar ustun
            w = 3 if ev.startswith(("js:", "fayl:", "meta:", "header:")) else 1
            w *= 2 if re.match(r"^\d+(\.\d+)+", version) else 0.5
            self.versions[version] += conf * w
        if len(self.evidence) < 6 and ev not in self.evidence:
            self.evidence.append(ev)

    @property
    def version(self):
        if not self.versions:
            return ""
        # eng ko'p tasdiqlangan, keyin eng aniq (uzun) versiya
        return sorted(self.versions.items(), key=lambda kv: (kv[1], len(kv[0])), reverse=True)[0][0]


def dict_match(det, name, field, rules, data, label):
    """headers/cookies/meta/dns kabi kalit->pattern maydonlari."""
    if not isinstance(rules, dict):
        return
    for key, pats in rules.items():
        k = key.lower()
        if "*" in k:
            rx = re.compile("^" + re.escape(k).replace(r"\*", ".*") + "$")
            values = [v for dk, vs in data.items() if rx.match(dk) for v in as_list(vs)]
            present = bool(values) or any(rx.match(dk) for dk in data)
        else:
            present = k in data
            values = as_list(data.get(k)) if present else []
        if not present:
            continue
        if not values:
            values = [""]
        for pat in as_list(pats) or [""]:
            for v in values:
                r = match_one(pat, v)
                if r:
                    det_get(det, name).add(r[1], r[2], f"{label}: {key}" + (f" = {v[:60]}" if v else ""))
                    break


def list_match(det, name, pats, values, label, short=True):
    for pat in as_list(pats):
        for v in values:
            r = match_one(pat, v)
            if r:
                ev = f"{label}" + (f": {v[:90]}" if short and len(v) < 300 else "")
                det_get(det, name).add(r[1], r[2], ev)
                break


def det_get(det, name):
    if name not in det:
        det[name] = Detection(name)
    return det[name]


def dom_match(det, name, rules, soup):
    if soup is None or not rules:
        return
    if isinstance(rules, (str, list)):
        rules = {sel: {"exists": ""} for sel in as_list(rules)}
    if not isinstance(rules, dict):
        return
    for sel, cond in rules.items():
        try:
            els = soup.select(sel, limit=20)
        except Exception:
            continue
        if not els:
            continue
        if not isinstance(cond, dict):
            cond = {"exists": ""}
        if "exists" in cond:
            r = match_one(cond["exists"] or "", "")
            if r:
                det_get(det, name).add("", r[2], f"dom: {sel}")
        if "text" in cond:
            for el in els:
                r = match_one(cond["text"], el.get_text(" ", strip=True))
                if r:
                    det_get(det, name).add(r[1], r[2], f"dom text: {sel}")
                    break
        for akey in ("attributes", "properties"):
            for attr, pat in (cond.get(akey) or {}).items():
                for el in els:
                    v = el.get(attr)
                    if v is None:
                        continue
                    v = " ".join(v) if isinstance(v, list) else str(v)
                    r = match_one(pat, v)
                    if r:
                        det_get(det, name).add(r[1], r[2], f"dom: {sel}[{attr}]")
                        break


def analyze(page, techs):
    det = {}
    all_html = [page.html[:MAX_HTML]] + page.extra_html
    scripts = page.scripts
    srcs = page.script_src
    hdrs = {k: v for k, v in page.headers.items()}
    js_avail = bool(page.js)

    for name, t in techs.items():
        if "url" in t:
            list_match(det, name, t["url"], page.urls, "url")
        if "headers" in t:
            dict_match(det, name, "headers", t["headers"], hdrs, "header")
        if "cookies" in t:
            dict_match(det, name, "cookies", t["cookies"], page.cookies, "cookie")
        if "meta" in t:
            dict_match(det, name, "meta", t["meta"], page.meta, "meta")
        if "scriptSrc" in t:
            list_match(det, name, t["scriptSrc"], srcs, "script")
        if "scripts" in t and scripts:
            list_match(det, name, t["scripts"], scripts, "js kontent", short=False)
        if "html" in t:
            list_match(det, name, t["html"], all_html, "html", short=False)
        if "css" in t and page.css:
            list_match(det, name, t["css"], page.css, "css", short=False)
        if "robots" in t and page.robots:
            list_match(det, name, t["robots"], [page.robots], "robots.txt", short=False)
        if "text" in t and page.text:
            list_match(det, name, t["text"], [page.text], "matn", short=False)
        if "certIssuer" in t and page.cert_issuer:
            list_match(det, name, t["certIssuer"], [page.cert_issuer], "SSL beruvchi")
        if "dns" in t and page.dns:
            dict_match(det, name, "dns", t["dns"], page.dns, "dns")
        if "dom" in t and page.soup is not None:
            dom_match(det, name, t["dom"], page.soup)
        if "js" in t and js_avail:
            dict_match(det, name, "js", t["js"], page.js, "js")

    for tech, ver, path in page.probe_hits:
        det_get(det, tech).add(ver, 100, f"fayl: {path}")

    # implies (zanjirli)
    changed = True
    rounds = 0
    while changed and rounds < 10:
        changed = False
        rounds += 1
        for name in list(det.keys()):
            for imp in as_list(techs.get(name, {}).get("implies")):
                p = parse_pattern(imp)
                iname = p["raw"]
                if iname in techs and iname not in det:
                    d = det_get(det, iname)
                    d.add(p["version"] if not p["version"].startswith("\\") else "",
                          min(p["confidence"], det[name].confidence), f"{name} orqali")
                    changed = True

    # requires / requiresCategory
    cats_present = defaultdict(set)
    for n in det:
        for c in techs.get(n, {}).get("cats", []):
            cats_present[c].add(n)
    for name in list(det.keys()):
        t = techs.get(name, {})
        req = as_list(t.get("requires"))
        if req and not any(r in det for r in req):
            del det[name]
            continue
        rc = as_list(t.get("requiresCategory"))
        if rc and not any(cats_present.get(c) for c in rc):
            del det[name]
    # excludes
    for name in list(det.keys()):
        for ex in as_list(techs.get(name, {}).get("excludes")):
            det.pop(ex, None)
    return det


# ================================================================ CHIQISH
def build_result(url, page, det, techs, cats, min_conf):
    out = []
    for name, d in det.items():
        if d.confidence < min_conf:
            continue
        t = techs.get(name, {})
        catnames = [cats.get(str(c), {}).get("name", str(c)) for c in t.get("cats", [])]
        out.append({
            "name": name,
            "version": d.version,
            "all_versions": sorted(d.versions.keys()) if len(d.versions) > 1 else [],
            "confidence": d.confidence,
            "categories": catnames,
            "website": t.get("website", ""),
            "cpe": t.get("cpe", ""),
            "evidence": d.evidence,
        })
    out.sort(key=lambda x: ((x["categories"] or ["~"])[0], x["name"].lower()))
    return {
        "url": url,
        "final_url": page.url,
        "status": page.status,
        "ip": page.ip,
        "title": page.title,
        "technologies": out,
    }


def print_result(res, verbose):
    print(f"\n{C['w']}{'=' * 78}{C['x']}")
    print(f"{C['w']}{C['c']}[>] {res['url']}{C['x']}")
    if res["final_url"] != res["url"]:
        print(f"    {C['d']}-> {res['final_url']}{C['x']}")
    print(f"    Holat: {res['status']}   IP: {res['ip'] or '-'}   Sarlavha: {res['title'] or '-'}")
    print(f"{C['w']}{'=' * 78}{C['x']}")
    if res["status"] in (403, 429, 503):
        print(f"  {C['y']}[!] Sayt so'rovni bloklagan bo'lishi mumkin (HTTP {res['status']}, WAF/rate-limit). "
              f"Natija to'liq bo'lmasligi mumkin — biroz kutib qayta urinib ko'ring yoki -b ishlating.{C['x']}")
    if not res["technologies"]:
        print(f"  {C['y']}Texnologiya aniqlanmadi.{C['x']}")
        return
    groups = defaultdict(list)
    for t in res["technologies"]:
        groups[(t["categories"] or ["Boshqa"])[0]].append(t)
    for cat in sorted(groups):
        print(f"\n  {C['m']}{C['w']}{cat}{C['x']}")
        for t in groups[cat]:
            ver = f" {C['g']}{t['version']}{C['x']}" if t["version"] else f" {C['d']}(versiya noma'lum){C['x']}"
            conf = "" if t["confidence"] >= 100 else f" {C['y']}[{t['confidence']}%]{C['x']}"
            other = f" {C['d']}(boshqa: {', '.join(t['all_versions'])}){C['x']}" if t["all_versions"] and verbose else ""
            print(f"    {C['w']}•{C['x']} {t['name']}{ver}{conf}{other}")
            if verbose:
                for e in t["evidence"]:
                    print(f"        {C['d']}↳ {e}{C['x']}")
    n = len(res["technologies"])
    nv = sum(1 for t in res["technologies"] if t["version"])
    print(f"\n  {C['b']}Jami: {n} ta texnologiya, {nv} tasining versiyasi aniqlandi.{C['x']}")


# ================================================================ ICHKI BAZA
# Faqat zaxira/qo'shimcha: to'liq baza yuklanmasa ham asosiy texnologiyalar aniqlanadi.
BUILTIN_CATS = {
    "1": {"name": "CMS"}, "6": {"name": "Ecommerce"}, "12": {"name": "JavaScript frameworks"},
    "18": {"name": "Web frameworks"}, "22": {"name": "Web servers"}, "27": {"name": "Programming languages"},
    "28": {"name": "Operating systems"}, "31": {"name": "CDN"}, "10": {"name": "Analytics"},
    "59": {"name": "JavaScript libraries"}, "66": {"name": "UI frameworks"}, "64": {"name": "Reverse proxies"},
    "16": {"name": "Security"}, "11": {"name": "Blogs"}, "62": {"name": "PaaS"}, "34": {"name": "Databases"},
    "19": {"name": "Miscellaneous"}, "17": {"name": "Font scripts"}, "87": {"name": "WordPress plugins"},
    "80": {"name": "WordPress themes"}, "70": {"name": "SSL/TLS certificate authorities"},
}

B = "\\;version:\\1"
BUILTIN_TECHS = {
    # --- Veb serverlar / proksi
    "Nginx": {"cats": [22, 64], "headers": {"Server": "nginx(?:/([\\d.]+))?" + B},
              "html": ["<center>nginx(?:/([\\d.]+))?</center>" + B], "cpe": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"},
    "Apache HTTP Server": {"cats": [22], "headers": {"Server": "(?:Apache(?:$|/([\\d.]+)|[^/-])|(?:^|\\b)HTTPD)" + B},
                           "html": ["<address>Apache(?:/([\\d.]+))?" + B]},
    "Microsoft-IIS": {"cats": [22], "headers": {"Server": "^(?:Microsoft-)?IIS(?:/([\\d.]+))?" + B}, "implies": "Windows Server"},
    "LiteSpeed": {"cats": [22], "headers": {"Server": "^LiteSpeed(?:/([\\d.]+))?" + B}},
    "OpenResty": {"cats": [22], "headers": {"Server": "openresty(?:/([\\d.]+))?" + B}, "implies": "Nginx"},
    "Caddy": {"cats": [22], "headers": {"Server": "^Caddy$"}},
    "Apache Tomcat": {"cats": [22], "headers": {"Server": "Apache-Coyote(?:/([\\d.]+))?" + B},
                      "html": ["<h3>Apache Tomcat/([\\d.]+)" + B, "Apache Tomcat/([\\d.]+)" + B], "implies": "Java"},
    "Jetty": {"cats": [22], "headers": {"Server": "Jetty(?:\\(([\\d.]+v?\\d*)\\))?" + B}, "implies": "Java"},
    "Gunicorn": {"cats": [22], "headers": {"Server": "gunicorn(?:/([\\d.]+))?" + B}, "implies": "Python"},
    "Envoy": {"cats": [64], "headers": {"Server": "^envoy$", "x-envoy-upstream-service-time": ""}},
    "Varnish": {"cats": [23], "headers": {"Via": "varnish(?:\\s\\(Varnish/([\\d.]+)\\))?" + B, "X-Varnish": ""}},
    "Windows Server": {"cats": [28]},
    "Ubuntu": {"cats": [28], "headers": {"Server": "Ubuntu"}},
    "Debian": {"cats": [28], "headers": {"Server": "Debian"}},
    "CentOS": {"cats": [28], "headers": {"Server": "CentOS"}},
    # --- Tillar
    "PHP": {"cats": [27], "headers": {"X-Powered-By": "^php/?([\\d.]+)?" + B, "Server": "php/?([\\d.]+)?" + B},
            "cookies": {"PHPSESSID": ""}, "url": ["\\.php(?:$|\\?)"]},
    "ASP.NET": {"cats": [18], "headers": {"X-AspNet-Version": "(.+)" + B, "X-Powered-By": "^ASP\\.NET",
                                          "X-AspNetMvc-Version": ""},
                "cookies": {"ASP.NET_SessionId": "", "ASPSESSION*": ""}, "html": ["<input[^>]+name=\"__VIEWSTATE"]},
    "Java": {"cats": [27], "cookies": {"JSESSIONID": ""}},
    "Python": {"cats": [27], "headers": {"Server": "(?:^|\\s)Python(?:/([\\d.]+))?" + B}},
    "Node.js": {"cats": [27]},
    "Ruby": {"cats": [27], "headers": {"Server": "(?:Mongrel|WEBrick|Ruby)"}},
    "Perl": {"cats": [27], "headers": {"Server": "\\bPerl\\b(?: ?/?v?([\\d.]+))?" + B}},
    "OpenSSL": {"cats": [33], "headers": {"Server": "OpenSSL(?:/([\\d.]+[a-z]?))?" + B}},
    # --- Freymvorklar
    "Express": {"cats": [18, 22], "headers": {"X-Powered-By": "^Express$"}, "implies": "Node.js"},
    "Laravel": {"cats": [18], "cookies": {"laravel_session": ""}, "implies": "PHP"},
    "Django": {"cats": [18], "cookies": {"csrftoken": "", "django_language": ""},
               "html": ["<input[^>]*name=[\"']csrfmiddlewaretoken"], "implies": "Python"},
    "Flask": {"cats": [18], "headers": {"Server": "Werkzeug/?([\\d.]+)?" + B}, "implies": "Python"},
    "Ruby on Rails": {"cats": [18], "headers": {"X-Powered-By": "(?:mod_rails|mod_rack|Phusion[._ ]Passenger)"},
                      "meta": {"csrf-param": "^authenticity_token$"}, "cookies": {"_rails_session": ""}, "implies": "Ruby"},
    "Symfony": {"cats": [18], "cookies": {"sf_redirect": ""}, "implies": "PHP"},
    "CodeIgniter": {"cats": [18], "cookies": {"ci_session": "", "ci_csrf_token": ""}, "implies": "PHP"},
    "Yii": {"cats": [18], "cookies": {"YII_CSRF_TOKEN": ""}, "html": ["<input[^>]+name=\"_csrf\"[^>]*>"], "implies": "PHP"},
    "Spring": {"cats": [18], "headers": {"X-Application-Context": ""}, "implies": "Java"},
    "Next.js": {"cats": [12, 18], "headers": {"X-Powered-By": "^Next\\.js ?([0-9.]+)?" + B},
                "html": ["<script[^>]+id=\"__NEXT_DATA__\""], "scriptSrc": ["/_next/static/"],
                "js": {"next.version": "^(.+)$" + B}, "implies": ["React", "Node.js"]},
    "Nuxt.js": {"cats": [12, 18], "html": ["<div [^>]*id=\"__nuxt\"", "window\\.__NUXT__"],
                "scriptSrc": ["/_nuxt/"], "implies": "Vue.js"},
    "Gatsby": {"cats": [57], "meta": {"generator": "^Gatsby(?: ([0-9.]+))?$" + B}, "html": ["<div id=\"___gatsby\""], "implies": "React"},
    "Astro": {"cats": [57], "meta": {"generator": "^Astro v?([\\d.]+)" + B}},
    # --- JS kutubxonalar
    "jQuery": {"cats": [59], "scriptSrc": ["jquery(?:-|\\.)([\\d.]*\\d)[^/]*\\.js" + B, "/([\\d.]+)/jquery(?:\\.min)?\\.js" + B,
                                            "jquery.*\\.js(?:\\?ver(?:sion)?=([\\d.]+))?" + B],
               "scripts": ["jQuery JavaScript Library v([\\d.]+)" + B, "jQuery v([\\d.]+)" + B],
               "js": {"jQuery.fn.jquery": "([\\d.]+)" + B}},
    "jQuery UI": {"cats": [59], "scriptSrc": ["jquery-ui(?:-|\\.)([\\d.]*\\d)[^/]*\\.js" + B, "([\\d.]+)/jquery-ui(?:\\.min)?\\.js" + B],
                  "scripts": ["jQuery UI - v([\\d.]+)" + B], "js": {"jQuery.ui.version": "(.+)" + B}, "implies": "jQuery"},
    "jQuery Migrate": {"cats": [59], "scriptSrc": ["jquery-migrate(?:-|\\.)([\\d.]*\\d)[^/]*\\.js" + B],
                       "scripts": ["jQuery Migrate v([\\d.]+)" + B], "implies": "jQuery"},
    "React": {"cats": [12], "html": ["<[^>]+data-react"], "scriptSrc": ["react(?:-with-addons)?(?:-|\\.)([\\d.]*\\d)[^/]*\\.js" + B,
                                                                       "/react(?:-dom)?@([\\d.]+)/" + B],
              "scripts": ["React v([\\d.]+)" + B, "react-dom\\.production\\.min\\.js"],
              "js": {"React.version": "^(.+)$" + B}},
    "Vue.js": {"cats": [12], "scriptSrc": ["vue[.-]([\\d.]*\\d)[^/]*\\.js" + B, "/vue@([\\d.]+)" + B],
               "scripts": ["Vue\\.js v([\\d.]+)" + B, "version:\"(3\\.[\\d.]+)\"" + B],
               "html": ["<[^>]+\\sdata-v(?:ue)?-"], "js": {"Vue.version": "^(.+)$" + B, "__VUE__": ""}},
    "AngularJS": {"cats": [12], "scriptSrc": ["angular[.-]([\\d.]*\\d)[^/]*\\.js" + B, "/([\\d.]+(?:-?rc[.\\d]*)*)/angular(?:\\.min)?\\.js" + B],
                  "html": ["<[^>]+ ng-app", "<[^>]+ ng-controller"], "scripts": ["AngularJS v([\\d.]+)" + B],
                  "js": {"angular.version.full": "^(.+)$" + B}},
    "Angular": {"cats": [12], "html": ["<[^>]+ ng-version=\"([\\d.]+)\"" + B], "implies": "TypeScript"},
    "Svelte": {"cats": [12], "html": ["<[^>]+class=\"[^\"]*svelte-[a-z0-9]+"]},
    "TypeScript": {"cats": [27]},
    "Bootstrap": {"cats": [66], "scriptSrc": ["bootstrap(?:[^/]*?)?(?:\\.min)?\\.js(?:\\?ver=([\\d.]+))?" + B, "/bootstrap@([\\d.]+)/" + B,
                                              "/bootstrap/([\\d.]+)/" + B],
                  "css": ["Bootstrap v([\\d.]+)" + B], "scripts": ["Bootstrap v([\\d.]+)" + B],
                  "html": ["<link[^>]+?href=\"[^\"]+bootstrap(?:[^\"]*?([\\d.]+)(?:/css)?)?(?:\\.min)?\\.css" + B],
                  "js": {"bootstrap.Alert.VERSION": "^(.+)$" + B, "jQuery.fn.tooltip.Constructor.VERSION": "^(.+)$" + B}},
    "Tailwind CSS": {"cats": [66], "css": ["tailwindcss v([\\d.]+)" + B, "--tw-(?:rotate|translate|space-x|ring)"]},
    "Font Awesome": {"cats": [17], "html": ["<link[^>]* href=[^>]+(?:font-awesome(?:\\.min)?\\.css|/font-awesome/([\\d.]+)/)" + B,
                                            "<link[^>]* href=[^>]+fontawesome[^>]*?([\\d.]+)?" + B],
                     "css": ["Font Awesome (?:Free )?([\\d.]+)" + B], "scriptSrc": ["kit\\.fontawesome\\.com"]},
    "Lodash": {"cats": [59], "scripts": ["lodash\\.com/license.{0,80}?var VERSION\\s*=\\s*['\"]([\\d.]+)" + B,
                                         "@license Lodash ([\\d.]+)" + B, "lodash ([\\d.]+) <https://lodash" + B],
               "js": {"_.VERSION": "^(.+)$\\;confidence:50\\;version:\\1"}},
    "Moment.js": {"cats": [59], "scriptSrc": ["moment(?:\\.min)?\\.js"], "scripts": ["//! version : ([\\d.]+)" + B],
                  "js": {"moment.version": "^(.+)$" + B}},
    "core-js": {"cats": [59], "scripts": ["core-js[^\"]{0,40}version:\"([\\d.]+)\"" + B, "version:\"([\\d.]+)\",mode:\"global\"" + B],
                "js": {"core.version": "^(.+)$" + B, "__core-js_shared__": ""}},
    "Swiper": {"cats": [59], "scripts": ["Swiper ([\\d.]+)" + B], "scriptSrc": ["swiper(?:-bundle)?(?:\\.min)?\\.js"]},
    "Modernizr": {"cats": [59], "scripts": ["Modernizr ([\\d.]+)" + B], "scriptSrc": ["modernizr(?:[\\d.-]+)?(?:\\.min)?\\.js"]},
    "Popper": {"cats": [59], "scripts": ["@popperjs/core v([\\d.]+)" + B, "Popper\\.js v([\\d.]+)" + B]},
    "Alpine.js": {"cats": [12], "html": ["<[^>]+\\sx-data[\\s=]"], "scriptSrc": ["/alpinejs@([\\d.]+)" + B]},
    "htmx": {"cats": [59], "html": ["<[^>]+\\shx-(?:get|post|target|swap)"], "scriptSrc": ["htmx\\.org@([\\d.]+)" + B]},
    "Webpack": {"cats": [19], "scripts": ["webpackJsonp", "__webpack_require__"]},
    "Vite": {"cats": [19], "html": ["<script[^>]+type=\"module\"[^>]+src=\"/assets/index-[\\w-]+\\.js"]},
    # --- CMS
    "WordPress": {"cats": [1, 11], "meta": {"generator": "^WordPress ?([\\d.]+)?" + B},
                  "html": ["<link rel=[\"']stylesheet[\"'] [^>]+/wp-(?:content|includes)/", "<link[^>]+s\\d+\\.wp\\.com"],
                  "scriptSrc": ["/wp-(?:content|includes)/", "wp-embed\\.min\\.js(?:\\?ver=([\\d.]+))?" + B],
                  "headers": {"link": "rel=\"https://api\\.w\\.org/\"", "X-Pingback": "/xmlrpc\\.php$"},
                  "implies": ["PHP", "MySQL"]},
    "Joomla": {"cats": [1], "meta": {"generator": "Joomla!(?: ([\\d.]+))?" + B},
               "html": ["(?:<div[^>]+id=\"wrapper_r\"|<(?:link|script)[^>]+(?:feed|components)/com_|<table[^>]+class=\"pill)"],
               "headers": {"X-Content-Encoded-By": "Joomla! ([\\d.]+)" + B}, "implies": "PHP"},
    "Drupal": {"cats": [1], "meta": {"generator": "^Drupal(?:\\s([\\d.]+))?" + B},
               "headers": {"X-Drupal-Cache": "", "X-Generator": "^Drupal(?:\\s([\\d.]+))?" + B, "X-Drupal-Dynamic-Cache": ""},
               "scriptSrc": ["drupal\\.js"], "html": ["<(?:link|style)[^>]+\"/sites/(?:default|all)/(?:themes|modules)/"],
               "implies": "PHP"},
    "Magento": {"cats": [6], "cookies": {"frontend": "\\;confidence:50", "mage-cache-storage": ""},
                "scriptSrc": ["js/mage", "skin/frontend/", "static/_requirejs"], "html": ["Mage\\.Cookies"], "implies": "PHP"},
    "Shopify": {"cats": [6], "headers": {"x-shopid": "", "x-shopify-stage": ""}, "cookies": {"_shopify_y": ""},
                "scriptSrc": ["cdn\\.shopify\\.com"], "html": ["Shopify\\.theme"]},
    "WooCommerce": {"cats": [6, 87], "meta": {"generator": "WooCommerce ([\\d.]+)" + B},
                    "scriptSrc": ["/woocommerce(?:\\.min)?\\.js(?:\\?ver=([\\d.]+))?" + B], "html": ["<link[^>]+woocommerce"],
                    "implies": "WordPress"},
    "PrestaShop": {"cats": [6], "meta": {"generator": "PrestaShop"}, "cookies": {"PrestaShop-*": ""}, "implies": "PHP"},
    "OpenCart": {"cats": [6], "cookies": {"OCSESSID": ""}, "html": ["catalog/view/theme"], "implies": "PHP"},
    "Bitrix": {"cats": [1], "headers": {"X-Powered-CMS": "Bitrix Site Manager"}, "cookies": {"BITRIX_SM_GUEST_ID": ""},
               "html": ["(?:<link[^>]+components/bitrix|(?:src|href)=\"/bitrix/(?:js|templates))"], "implies": "PHP"},
    "MODX": {"cats": [1], "headers": {"X-Powered-By": "^MODX"}, "html": ["<a[^>]+>Powered by MODX</a>"], "implies": "PHP"},
    "Ghost": {"cats": [11], "meta": {"generator": "Ghost(?:\\s([\\d.]+))?" + B}, "headers": {"X-Ghost-Cache-Status": ""}, "implies": "Node.js"},
    "Wix": {"cats": [1], "meta": {"generator": "Wix\\.com"}, "headers": {"X-Wix-Request-Id": ""}},
    "Squarespace": {"cats": [1], "headers": {"Server": "Squarespace"}},
    "Tilda": {"cats": [1], "html": ["<link[^>]* href=[^>]+tilda(?:cdn|\\.ws|-blocks)"], "scriptSrc": ["tilda(?:cdn|\\.ws)"]},
    "Typo3": {"cats": [1], "meta": {"generator": "TYPO3\\s+(?:CMS\\s+)?([\\d.]+)?" + B}, "html": ["<link[^>]+typo3conf"], "implies": "PHP"},
    "DataLife Engine": {"cats": [1], "meta": {"generator": "DataLife Engine"}, "scriptSrc": ["engine/classes/js/dle_js\\.js"], "implies": "PHP"},
    "Hugo": {"cats": [57], "meta": {"generator": "Hugo ([\\d.]+)?" + B}},
    "Jekyll": {"cats": [57], "meta": {"generator": "Jekyll v([\\d.]+)" + B}},
    "Elementor": {"cats": [51, 87], "meta": {"generator": "Elementor ([\\d.]+)" + B},
                  "scriptSrc": ["elementor/assets/js/[^/]+\\.js\\?ver=([\\d.]+)" + B], "implies": "WordPress"},
    "Yoast SEO": {"cats": [54, 87], "html": ["<!-- This site is optimized with the Yoast (?:WordPress )?SEO plugin v([^\\s]+) -" + B,
                                            "<!-- This site is optimized with the Yoast SEO Premium plugin v(?:[^\\s]+) \\(Yoast SEO v([^\\s]+)\\) -" + B],
                  "implies": "WordPress"},
    "Contact Form 7": {"cats": [87], "scriptSrc": ["/contact-form-7/[^\"']+\\.js(?:\\?ver=([\\d.]+))?" + B], "implies": "WordPress"},
    # --- Ma'lumotlar bazasi
    "MySQL": {"cats": [34]},
    "PostgreSQL": {"cats": [34]},
    # --- CDN / xavfsizlik / hosting
    "Cloudflare": {"cats": [31], "headers": {"Server": "^cloudflare$", "cf-ray": "", "cf-cache-status": ""},
                   "cookies": {"__cfduid": "", "__cf_bm": "", "cf_clearance": ""}, "dns": {"ns": "\\.ns\\.cloudflare\\.com"}},
    "Amazon CloudFront": {"cats": [31], "headers": {"X-Amz-Cf-Id": "", "Via": "\\(CloudFront\\)$"}},
    "Akamai": {"cats": [31], "headers": {"X-Akamai-Transformed": "", "X-Akamai-Request-ID": "", "Server": "AkamaiGHost"}},
    "Fastly": {"cats": [31], "headers": {"X-Fastly-Request-ID": "", "Fastly-Debug-Digest": "", "X-Served-By": "cache-.+-[A-Z]{3}$\\;confidence:50"}},
    "jsDelivr": {"cats": [31], "scriptSrc": ["cdn\\.jsdelivr\\.net"]},
    "cdnjs": {"cats": [31], "scriptSrc": ["cdnjs\\.cloudflare\\.com"]},
    "unpkg": {"cats": [31], "scriptSrc": ["unpkg\\.com"]},
    "Amazon Web Services": {"cats": [62], "headers": {"x-amz-request-id": "", "x-amz-id-2": "", "Server": "^AmazonS3$|^awselb"}},
    "Vercel": {"cats": [62], "headers": {"server": "^Vercel$", "x-vercel-id": "", "x-vercel-cache": ""}},
    "Netlify": {"cats": [62], "headers": {"Server": "^Netlify", "X-NF-Request-ID": ""}},
    "GitHub Pages": {"cats": [62], "headers": {"Server": "^GitHub\\.com$", "X-GitHub-Request-Id": ""}},
    "Heroku": {"cats": [62], "headers": {"Via": "[\\d.-]+ vegur$"}},
    "Sucuri": {"cats": [16], "headers": {"X-Sucuri-ID": "", "Server": "^Sucuri"}},
    "Imperva": {"cats": [16], "headers": {"X-Iinfo": ""}, "cookies": {"incap_ses_*": "", "visid_incap_*": ""}},
    "HSTS": {"cats": [16], "headers": {"Strict-Transport-Security": ""}},
    "reCAPTCHA": {"cats": [16], "scriptSrc": ["google\\.com/recaptcha", "recaptcha/(?:api|enterprise)\\.js"]},
    "hCaptcha": {"cats": [16], "scriptSrc": ["hcaptcha\\.com/1/api\\.js"]},
    "Let's Encrypt": {"cats": [70], "certIssuer": ["Let's Encrypt"]},
    "Google Trust Services": {"cats": [70], "certIssuer": ["Google Trust Services"]},
    "DigiCert": {"cats": [70], "certIssuer": ["DigiCert"]},
    "Sectigo": {"cats": [70], "certIssuer": ["Sectigo"]},
    # --- Analitika / marketing
    "Google Analytics": {"cats": [10], "scriptSrc": ["google-analytics\\.com/(?:ga|urchin|analytics)\\.js",
                                                     "googletagmanager\\.com/gtag/js\\?id=G-"],
                         "cookies": {"_ga": "", "__utma": ""}},
    "Google Tag Manager": {"cats": [42], "scriptSrc": ["googletagmanager\\.com/gtm\\.js"],
                           "html": ["googletagmanager\\.com/ns\\.html[^>]+></iframe>", "<!-- (?:End )?Google Tag Manager -->"]},
    "Yandex.Metrika": {"cats": [10], "scriptSrc": ["mc\\.yandex\\.ru/metrika/(?:tag|watch)\\.js"], "scripts": ["mc\\.yandex\\.ru/metrika"]},
    "Facebook Pixel": {"cats": [10], "scriptSrc": ["connect\\.facebook\\.net/[^/]+/fbevents\\.js"], "scripts": ["fbq\\('init'"]},
    "Hotjar": {"cats": [10], "scriptSrc": ["static\\.hotjar\\.com"], "scripts": ["static\\.hotjar\\.com"]},
    "Microsoft Clarity": {"cats": [10], "scripts": ["clarity\\.ms/tag"]},
    "Google Fonts": {"cats": [17], "html": ["<link[^>]* href=[^>]+fonts\\.(?:googleapis|google)\\.com"]},
    "Google Maps": {"cats": [35], "scriptSrc": ["maps\\.googleapis\\.com/maps/api/js"]},
    "Jivochat": {"cats": [52], "scriptSrc": ["code\\.jivo(?:site)?\\.(?:ru|com)"]},
    "Tawk.to": {"cats": [52], "scriptSrc": ["embed\\.tawk\\.to"], "scripts": ["embed\\.tawk\\.to"]},
    # --- Boshqalar
    "phpMyAdmin": {"cats": [3], "html": ["<title>phpMyAdmin", "PMA_VERSION:\"([\\d.]+)" + B], "implies": ["PHP", "MySQL"]},
    "Grafana": {"cats": [10], "html": ["\"buildInfo\":\\{[^}]*\"version\":\"([\\d.]+)\"" + B, "<title>Grafana</title>"]},
    "Jenkins": {"cats": [44], "headers": {"X-Jenkins": "([\\d.]+)" + B, "X-Hudson": ""}, "implies": "Java"},
    "GitLab": {"cats": [47], "cookies": {"_gitlab_session": ""}, "meta": {"og:site_name": "^GitLab$"}},
    "Kibana": {"cats": [29], "headers": {"kbn-name": "", "kbn-version": "([\\d.]+)" + B}},
    "Roundcube": {"cats": [30], "html": ["<title>Roundcube Webmail", "\"rcversion\":(\\d)(\\d\\d)(\\d\\d)\\;version:\\1.\\2.\\3"]},
    "Microsoft Exchange Online": {"cats": [30], "dns": {"mx": "mail\\.protection\\.outlook\\.com"}},
    "Google Workspace": {"cats": [30], "dns": {"mx": "aspmx\\.l\\.google\\.com|googlemail\\.com"}},
    "SPF": {"cats": [19], "dns": {"txt": "v=spf1"}},
    "DMARC": {"cats": [19], "dns": {"txt": "v=DMARC1"}},
    "HTTP/3": {"cats": [19], "headers": {"Alt-Svc": "h3"}},
}

# Aggressiv rejim: (yo'l, texnologiya, regex, versiya shabloni)
PROBES = [
    ("/readme.html", "WordPress", r"<br\s*/?>\s*(?:Version|Версия)\s+([\d.]+)", "\\1"),
    ("/wp-links-opml.php", "WordPress", r'generator="WordPress/([\d.]+)"', "\\1"),
    ("/feed/", "WordPress", r"<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>", "\\1"),
    ("/wp-admin/install.php", "WordPress", r"ver=([\d.]+)", "\\1"),
    ("/administrator/manifests/files/joomla.xml", "Joomla", r"<version>([\d.]+)</version>", "\\1"),
    ("/language/en-GB/en-GB.xml", "Joomla", r"<version>([\d.]+)</version>", "\\1"),
    ("/administrator/language/en-GB/en-GB.xml", "Joomla", r"<version>([\d.]+)</version>", "\\1"),
    ("/CHANGELOG.txt", "Drupal", r"Drupal ([\d.]+)", "\\1"),
    ("/core/CHANGELOG.txt", "Drupal", r"Drupal ([\d.]+)", "\\1"),
    ("/core/install.php", "Drupal", r"core/misc/drupal\.js\?v=([\d.]+)", "\\1"),
    ("/magento_version", "Magento", r"Magento/([\d.]+)", "\\1"),
    ("/docs/RELEASE-NOTES.txt", "Apache Tomcat", r"Apache Tomcat Version ([\d.]+)", "\\1"),
    ("/manager/html", "Apache Tomcat", r"Apache Tomcat/([\d.]+)", "\\1"),
    ("/typo3/sysext/install/composer.json", "Typo3", r'"typo3/cms-core":\s*"([\d.]+)"', "\\1"),
    ("/bitrix/admin/", "Bitrix", r"1C-Bitrix", ""),
    ("/phpmyadmin/", "phpMyAdmin", r"phpMyAdmin(?:.{0,200}?PMA_VERSION:\"([\d.]+)\")?", "\\1"),
    ("/api/health", "Grafana", r'"version":\s*"([\d.]+)"', "\\1"),
    ("/login", "Grafana", r'"buildInfo":\{[^}]*"version":"([\d.]+)"', "\\1"),
    ("/help", "GitLab", r"GitLab (?:Community|Enterprise) Edition\s*<span>([\d.]+)", "\\1"),
    ("/ghost/api/admin/site/", "Ghost", r'"version":"([\d.]+)"', "\\1"),
    ("/umbraco/ping.aspx", "Umbraco", r"I'm alive", ""),
    ("/server-status", "Apache HTTP Server", r"Server Version:\s*Apache/([\d.]+)", "\\1"),
    ("/nginx_status", "Nginx", r"Active connections", ""),
    ("/actuator/info", "Spring", r'"(?:version|build)"', ""),
    ("/elmah.axd", "ASP.NET", r"Error Log for", ""),
    ("/README.md", "Grav", r"# Grav", ""),
    ("/CHANGELOG.md", "PrestaShop", r"PrestaShop ([\d.]+)", "\\1"),
    ("/app/etc/local.xml", "Magento", r"<config>", ""),
]

TECHS = {}


# ================================================================ MAIN
def scan(url, args, techs, cats):
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    t0 = time.time()
    try:
        page = collect(url, args, args.quiet)
    except requests.exceptions.SSLError:
        if url.startswith("https://") and not args.insecure:
            args_insecure = argparse.Namespace(**vars(args))
            args_insecure.insecure = True
            page = collect(url, args_insecure, args.quiet)
        else:
            raise
    except requests.exceptions.ConnectionError:
        if url.startswith("https://"):
            page = collect("http://" + url[8:], args, args.quiet)
        else:
            raise
    det = analyze(page, techs)
    res = build_result(url, page, det, techs, cats, args.min_confidence)
    res["scan_time"] = round(time.time() - t0, 2)
    return res


def main():
    global TECHS
    ap = argparse.ArgumentParser(
        prog="techscan",
        description="Veb saytda ishlatilgan texnologiyalar va ularning versiyalarini aniqlaydi (Wappalyzer kabi).")
    ap.add_argument("urls", nargs="*", help="Tekshiriladigan URL(lar)")
    ap.add_argument("-l", "--list", help="URL ro'yxati fayli (har qatorda bitta)")
    ap.add_argument("-o", "--output", help="Natijani JSON faylga saqlash")
    ap.add_argument("-j", "--json", action="store_true", help="Natijani JSON ko'rinishda chiqarish")
    ap.add_argument("-v", "--verbose", action="store_true", help="Dalillarni (qayerdan aniqlangani) ko'rsatish")
    ap.add_argument("-a", "--aggressive", action="store_true", help="Versiya fayllari va 404 sahifani tekshirish (ko'proq so'rov)")
    ap.add_argument("-b", "--browser", action="store_true", help="Headless Chromium orqali JS o'zgaruvchilarni tekshirish (Selenium yoki Playwright)")
    ap.add_argument("-t", "--threads", type=int, default=5, help="Bir vaqtda skanerlanadigan saytlar soni (default 5)")
    ap.add_argument("--timeout", type=int, default=12, help="So'rov vaqt chegarasi, soniya")
    ap.add_argument("--min-confidence", type=int, default=0, help="Minimal ishonch darajasi (0-100)")
    ap.add_argument("-k", "--insecure", action="store_true", help="SSL sertifikatni tekshirmaslik")
    ap.add_argument("--proxy", help="Proksi, masalan http://127.0.0.1:8080")
    ap.add_argument("-H", "--header", action="append", help="Qo'shimcha sarlavha 'Nom: qiymat' (bir necha marta)")
    ap.add_argument("--ua", default=UA, help="User-Agent")
    ap.add_argument("--no-dns", action="store_true", help="DNS tekshiruvini o'chirish")
    ap.add_argument("--fingerprints", action="append", help="Qo'shimcha fingerprint JSON fayli (Wappalyzer formati)")
    ap.add_argument("--update", action="store_true", help="Texnologiyalar bazasini yangilash")
    ap.add_argument("-q", "--quiet", action="store_true", help="Faqat natija")
    ap.add_argument("--version", action="version", version=f"techscan {VERSION}")
    args = ap.parse_args()

    if args.update:
        update_db(args.quiet)
        if not args.urls and not args.list:
            return

    urls = list(args.urls)
    if args.list:
        urls += [l.strip() for l in open(args.list) if l.strip() and not l.startswith("#")]
    if not urls:
        ap.print_help()
        return

    TECHS, cats = load_db(args.fingerprints, args.quiet)
    log(f"{C['d']}[*] Baza: {len(TECHS)} ta texnologiya | Saytlar: {len(urls)}"
        f"{' | aggressive' if args.aggressive else ''}{' | browser' if args.browser else ''}{C['x']}", args.quiet)

    results = []
    with cf.ThreadPoolExecutor(max(1, args.threads)) as ex:
        futs = {ex.submit(scan, u, args, TECHS, cats): u for u in urls}
        for f in cf.as_completed(futs):
            u = futs[f]
            try:
                res = f.result()
            except Exception as e:
                res = {"url": u, "error": str(e), "technologies": []}
                if not args.json:
                    print(f"\n{C['r']}[!] {u}: {e}{C['x']}")
            results.append(res)
            if not args.json and "error" not in res:
                print_result(res, args.verbose)

    if args.json:
        print(json.dumps(results if len(results) > 1 else results[0], ensure_ascii=False, indent=2))
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        log(f"\n{C['g']}[+] Saqlandi: {args.output}{C['x']}", args.quiet)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\n[!] To'xtatildi")
