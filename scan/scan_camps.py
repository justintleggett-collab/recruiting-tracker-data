#!/usr/bin/env python3
"""One-time camp page scan. Fetches each URL in the targets CSV and flags pages for manual review.
Reports only: this script never edits camps_database.json. Standard library only."""
import csv, hashlib, json, re, sys, time, urllib.parse, urllib.request, urllib.robotparser
from html.parser import HTMLParser

UA = "BaseballRecruitingTrackerScan/1.0 (+https://baseballrecruitingtracker.com; support@baseballrecruitingtracker.com)"
TIMEOUT, DELAY, MIN_TEXT = 20, 1.0, 400
MONTHS = "Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec|January|February|March|April|June|July|August|September|October|November|December"
DATE_RE = re.compile(rf"\b(?:{MONTHS})\.?\s+\d{{1,2}}(?:st|nd|rd|th)?(?:,?\s+20\d\d)?", re.I)
MONEY_RE = re.compile(r"\$\s?(\d{1,3}(?:,\d{3})*|\d+)(?:\.\d{2})?")
KEYWORDS = ["sold out", "registration closed", "cancelled", "canceled", "no longer", "coming soon", "waitlist", "full"]
BLOCK_WORDS = ["captcha", "access denied", "are you a robot", "verify you are human", "cloudflare"]
SKIP = {"script", "style", "noscript", "nav", "footer", "header", "svg"}

class Text(HTMLParser):
    def __init__(self): super().__init__(); self.out=[]; self.depth=0
    def handle_starttag(self, t, a):
        if t in SKIP: self.depth += 1
    def handle_endtag(self, t):
        if t in SKIP and self.depth: self.depth -= 1
    def handle_data(self, d):
        if not self.depth and d.strip(): self.out.append(d.strip())

_robots = {}
def allowed(url):
    p = urllib.parse.urlparse(url); base = f"{p.scheme}://{p.netloc}"
    if base not in _robots:
        rp = urllib.robotparser.RobotFileParser(); rp.set_url(base + "/robots.txt")
        try:
            req = urllib.request.Request(base + "/robots.txt", headers={"User-Agent": UA})
            rp.parse(urllib.request.urlopen(req, timeout=TIMEOUT).read().decode("utf-8", "ignore").splitlines())
        except Exception: rp = None   # unreadable robots.txt: treat as allowed
        _robots[base] = rp
    rp = _robots[base]
    return True if rp is None else rp.can_fetch(UA, url)

def fetch(url):
    last = None
    for attempt in range(2):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,*/*"})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                return r.status, r.geturl(), r.read(2_000_000).decode(r.headers.get_content_charset() or "utf-8", "ignore"), ""
        except urllib.error.HTTPError as e:
            last = (e.code, url, "", f"HTTP {e.code}")
            if e.code in (403, 404, 410, 429): break
        except Exception as e:
            last = (0, url, "", type(e).__name__)
        time.sleep(2)
    return last

def analyze(row):
    url = row["url"]; out = {k: row[k] for k in ("campID", "school", "division", "url", "dbStartDate", "dbCost")}
    out.update(status="", final_url="", text_chars=0, sha256="", years="", dates_found="", prices_found="", keywords="", flags="", review="no")
    if not url: out["status"] = "no_url"; out["flags"] = "no URL on record"; out["review"] = "yes"; return out
    if not allowed(url): out["status"] = "robots_disallowed"; out["flags"] = "robots.txt disallows scan; check by hand"; out["review"] = "yes"; return out
    code, final, html, err = fetch(url)
    out["final_url"] = final
    if code == 0 or code >= 400:
        out["status"] = "blocked" if code in (403, 429) else "unreachable"; out["flags"] = err or f"HTTP {code}"; out["review"] = "yes"; return out
    p = Text(); p.feed(html); text = re.sub(r"\s+", " ", " ".join(p.out))
    low = text.lower()
    out["text_chars"] = len(text); out["sha256"] = hashlib.sha256(text.encode()).hexdigest()[:16]
    flags = []
    if any(w in low for w in BLOCK_WORDS) and len(text) < 2000: out["status"] = "blocked"; flags.append("looks like a bot check page")
    elif len(text) < MIN_TEXT: out["status"] = "needs_browser"; flags.append(f"only {len(text)} characters of text; likely JavaScript-rendered")
    else: out["status"] = "ok"
    if urllib.parse.urlparse(final).netloc.replace("www.", "") != urllib.parse.urlparse(url).netloc.replace("www.", ""):
        flags.append(f"redirected to {urllib.parse.urlparse(final).netloc}")
    yrs = sorted(set(re.findall(r"\b(2026|2027|2028)\b", text))); out["years"] = " ".join(yrs)
    dates = sorted(set(m.group(0).strip() for m in DATE_RE.finditer(text)))[:12]; out["dates_found"] = "; ".join(dates)
    prices = sorted(set(int(m.group(1).replace(",", "")) for m in MONEY_RE.finditer(text)))[:12]; out["prices_found"] = " ".join(f"${x}" for x in prices)
    kws = [k for k in KEYWORDS if k in low]; out["keywords"] = "; ".join(kws)
    if out["status"] == "ok":
        if "2027" in yrs: flags.append("page mentions 2027")
        if row["dbStartDate"] and "2027" not in yrs and "2026" not in yrs: flags.append("page has no 2026 or 2027 reference")
        if not row["dbStartDate"] and dates: flags.append("page shows dates; database has none")
        if row["dbStartDate"]:
            y, m, d = row["dbStartDate"].split("-"); mon = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"][int(m)-1]
            if not re.search(rf"\b{mon}[a-z]*\.?\s+0?{int(d)}\b", text, re.I): flags.append(f"database date {row['dbStartDate']} not found on page")
        try: dbc = int(float(row["dbCost"] or 0))
        except ValueError: dbc = 0
        if dbc > 0 and dbc not in prices: flags.append(f"database cost ${dbc} not found on page")
        if kws: flags.append("keywords: " + ", ".join(kws))
    out["flags"] = " | ".join(flags); out["review"] = "yes" if flags else "no"
    return out

def main(targets, outdir):
    rows = list(csv.DictReader(open(targets, encoding="utf-8"))); results = []; last = {}
    for i, row in enumerate(rows, 1):
        host = urllib.parse.urlparse(row["url"]).netloc
        wait = DELAY - (time.time() - last.get(host, 0))
        if wait > 0: time.sleep(wait)
        res = analyze(row); last[host] = time.time(); results.append(res)
        print(f"[{i}/{len(rows)}] {res['status']:<17} {res['school']}", flush=True)
    import os; os.makedirs(outdir, exist_ok=True)
    cols = list(results[0].keys())
    with open(f"{outdir}/camp_scan_report.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, cols); w.writeheader(); w.writerows(sorted(results, key=lambda r: r["review"] != "yes"))
    counts = {}
    for r in results: counts[r["status"]] = counts.get(r["status"], 0) + 1
    md = [f"# Camp scan report ({len(results)} URLs)", "", "Status counts: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())), "",
          f"Flagged for manual review: {sum(r['review']=='yes' for r in results)} of {len(results)}", "",
          "| School | Status | Flags | Link |", "| --- | --- | --- | --- |"]
    for r in sorted(results, key=lambda r: r["review"] != "yes"):
        if r["review"] == "yes": md.append(f"| {r['school']} | {r['status']} | {r['flags'].replace('|', '/')} | {r['url']} |")
    md += ["", "Pages not flagged: no check failed, but this scan compares against the database, not against a previous scan."]
    open(f"{outdir}/camp_scan_report.md", "w").write("\n".join(md) + "\n")
    print("\n".join(md))

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "scan/camp_scan_pilot.csv", sys.argv[2] if len(sys.argv) > 2 else "scan_output")
