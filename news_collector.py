import json
import os
import re
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from urllib.request import Request, urlopen

import feedparser


# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------

OUTPUT_DIR = "data"
OUTPUT_FILE = os.path.join(
    OUTPUT_DIR,
    "news.json"
)

# Endast artiklar från de senaste 7 dagarna sparas.
ARTICLE_MAX_AGE_DAYS = 7


# ---------------------------------------------------------
# RSS FEEDS
# ---------------------------------------------------------

FEEDS = [

    {
        "name": "Microsoft MSRC",
        "url": "https://msrc-blog.microsoft.com/feed/",
        "category": "Vendor",
        "vendor": "Microsoft"
    },

    {
        "name": "Red Hat Security",
        "url": "https://access.redhat.com/security/data/metrics/rhsa.rss",
        "category": "Vendor",
        "vendor": "Red Hat"
    },

    {
        "name": "CISA",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "category": "Government",
        "vendor": "CISA"
    },

    {
        "name": "KrebsOnSecurity",
        "url": "https://krebsonsecurity.com/feed/",
        "category": "News",
        "vendor": ""
    },

    {
        "name": "Dark Reading",
        "url": "https://www.darkreading.com/rss.xml",
        "category": "News",
        "vendor": ""
    },

    {
        "name": "SecurityWeek",
        "url": "https://feeds.feedburner.com/securityweek",
        "category": "News",
        "vendor": ""
    },

    {
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "category": "News",
        "vendor": ""
    },

    {
        "name": "Google Project Zero",
        "url": "https://googleprojectzero.blogspot.com/feeds/posts/default",
        "category": "Research",
        "vendor": "Google"
    },

    {
        "name": "Cisco Talos",
        "url": "https://blog.talosintelligence.com/rss/",
        "category": "Research",
        "vendor": "Cisco"
    }
]


# ---------------------------------------------------------
# CATEGORY RULES
# ---------------------------------------------------------

CATEGORY_RULES = {

    "Ransomware": [
        "ransomware",
        "extortion",
        "double extortion",
        "encrypt files"
    ],

    "Zero-day": [
        "zero-day",
        "zero day",
        "0-day"
    ],

    "Exploit": [
        "actively exploited",
        "exploited in the wild",
        "exploitation",
        "exploit",
        "weaponized"
    ],

    "Malware": [
        "malware",
        "trojan",
        "backdoor",
        "botnet",
        "infostealer",
        "stealer",
        "rootkit"
    ],

    "Phishing": [
        "phishing",
        "credential theft",
        "credential harvesting"
    ],

    "APT": [
        "apt",
        "advanced persistent threat",
        "state-sponsored",
        "state sponsored",
        "nation-state",
        "nation state"
    ],

    "Data Breach": [
        "data breach",
        "breach",
        "stolen data",
        "data leak",
        "leaked data"
    ],

    "Vulnerability": [
        "cve-",
        "vulnerability",
        "security flaw",
        "security vulnerability"
    ],

    "Patch": [
        "security update",
        "security patch",
        "patch",
        "update released",
        "security release"
    ],

    "Supply Chain": [
        "supply chain",
        "dependency",
        "package compromise",
        "npm",
        "pypi"
    ]
}


# ---------------------------------------------------------
# VENDOR RULES
# ---------------------------------------------------------

VENDOR_RULES = {

    "Microsoft": [
        "microsoft",
        "windows",
        "exchange",
        "sharepoint",
        "azure",
        "office",
        "defender"
    ],

    "Apple": [
        "apple",
        "ios",
        "ipados",
        "macos",
        "iphone",
        "ipad",
        "webkit",
        "safari"
    ],

    "Red Hat": [
        "red hat",
        "redhat",
        "rhel",
        "openshift"
    ],

    "Cisco": [
        "cisco",
        "talos"
    ],

    "Google": [
        "google",
        "chrome",
        "android"
    ],

    "Fortinet": [
        "fortinet",
        "fortigate"
    ],

    "VMware": [
        "vmware",
        "esxi",
        "vsphere"
    ],

    "Citrix": [
        "citrix"
    ],

    "Palo Alto": [
        "palo alto",
        "pan-os"
    ],

    "Ivanti": [
        "ivanti"
    ]
}


# ---------------------------------------------------------
# HTTP
# ---------------------------------------------------------

def fetch_feed(url):

    headers = {
        "User-Agent": "SecurityMonitor/1.0"
    }

    request = Request(
        url,
        headers=headers
    )

    with urlopen(
        request,
        timeout=30
    ) as response:

        return response.read()


# ---------------------------------------------------------
# HTML CLEANUP
# ---------------------------------------------------------

def strip_html(value):

    if not value:
        return ""

    value = re.sub(
        r"<[^>]+>",
        " ",
        value
    )

    value = re.sub(
        r"\s+",
        " ",
        value
    )

    return value.strip()


# ---------------------------------------------------------
# DATE PARSING
# ---------------------------------------------------------

def parse_date(entry):

    # Försök först läsa standardfält
    # från RSS/Atom.

    for field in [
        "published",
        "updated"
    ]:

        value = entry.get(
            field
        )

        if value:

            try:

                dt = parsedate_to_datetime(
                    value
                )

                if dt.tzinfo is None:

                    dt = dt.replace(
                        tzinfo=timezone.utc
                    )

                # Normalisera till UTC.
                return dt.astimezone(
                    timezone.utc
                )

            except Exception:
                pass

    # Fallback för feedparser
    # när datumet redan är uppdelat.

    for field in [
        "published_parsed",
        "updated_parsed"
    ]:

        value = entry.get(
            field
        )

        if value:

            try:

                dt = datetime(
                    *value[:6],
                    tzinfo=timezone.utc
                )

                return dt

            except Exception:
                pass

    return None


# ---------------------------------------------------------
# CATEGORY DETECTION
# ---------------------------------------------------------

def detect_categories(text):

    text = text.lower()

    categories = []

    for category, keywords in CATEGORY_RULES.items():

        for keyword in keywords:

            if keyword in text:

                categories.append(
                    category
                )

                break

    return categories


# ---------------------------------------------------------
# VENDOR DETECTION
# ---------------------------------------------------------

def detect_vendors(text):

    text = text.lower()

    vendors = []

    for vendor, keywords in VENDOR_RULES.items():

        for keyword in keywords:

            if keyword in text:

                vendors.append(
                    vendor
                )

                break

    return sorted(
        set(vendors)
    )


# ---------------------------------------------------------
# SEVERITY
# ---------------------------------------------------------

def detect_severity(
    text,
    categories
):

    text = text.lower()

    if (
        "Zero-day" in categories
        or "Ransomware" in categories
        or "actively exploited" in text
        or "exploited in the wild" in text
    ):

        return "CRITICAL"

    if (
        "Exploit" in categories
        or "APT" in categories
        or "Data Breach" in categories
    ):

        return "HIGH"

    if (
        "Vulnerability" in categories
        or "Malware" in categories
    ):

        return "MEDIUM"

    return "INFO"


# ---------------------------------------------------------
# PRIORITY
# ---------------------------------------------------------

def detect_priority(severity):

    if severity == "CRITICAL":
        return "P1"

    if severity == "HIGH":
        return "P2"

    if severity == "MEDIUM":
        return "P3"

    return "P4"


# ---------------------------------------------------------
# NORMALIZE RSS ENTRY
# ---------------------------------------------------------

def normalize_entry(
    entry,
    source
):

    title = strip_html(
        entry.get(
            "title",
            ""
        )
    )

    summary = strip_html(
        entry.get(
            "summary",
            ""
        )
        or entry.get(
            "description",
            ""
        )
    )

    url = entry.get(
        "link",
        ""
    )

    published_dt = parse_date(
        entry
    )

    # Artiklar utan datum ska inte
    # behandlas som aktuella.
    if published_dt is None:
        return None

    combined_text = (
        title
        + " "
        + summary
    )

    categories = detect_categories(
        combined_text
    )

    vendors = detect_vendors(
        combined_text
    )

    # Lägg till leverantören som
    # feeden representerar.
    if source.get("vendor"):

        vendors.append(
            source["vendor"]
        )

    vendors = sorted(
        set(vendors)
    )

    severity = detect_severity(
        combined_text,
        categories
    )

    priority = detect_priority(
        severity
    )

    article_id = (
        url
        or title
    )

    return {

        "id": article_id,

        "title": title,

        "summary": summary,

        "url": url,

        "source": source["name"],

        "source_category":
            source["category"],

        # Alltid UTC.
        "published":
            published_dt.isoformat(),

        "vendors":
            vendors,

        "categories":
            categories,

        "severity":
            severity,

        "priority":
            priority
    }


# ---------------------------------------------------------
# LOAD EXISTING DATA
# ---------------------------------------------------------

def load_existing():

    if not os.path.exists(
        OUTPUT_FILE
    ):

        return []

    try:

        with open(
            OUTPUT_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(
                file
            )

        return data.get(
            "articles",
            []
        )

    except Exception:

        return []


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------

def main():

    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True
    )

    # -----------------------------------------------------
    # CURRENT TIME
    # -----------------------------------------------------

    now = datetime.now(
        timezone.utc
    )

    # -----------------------------------------------------
    # CUTOFF
    # -----------------------------------------------------

    cutoff = (
        now
        - timedelta(
            days=ARTICLE_MAX_AGE_DAYS
        )
    )

    print(
        "Current UTC time:",
        now.isoformat()
    )

    print(
        "Article cutoff:",
        cutoff.isoformat()
    )

    # -----------------------------------------------------
    # LOAD EXISTING
    # -----------------------------------------------------

    existing = load_existing()

    articles = {}

    # -----------------------------------------------------
    # REMOVE OLD EXISTING ARTICLES
    # -----------------------------------------------------

    for item in existing:

        if not item.get("id"):
            continue

        published = item.get(
            "published"
        )

        if not published:
            continue

        try:

            published_dt = datetime.fromisoformat(
                published
            )

            if published_dt.tzinfo is None:

                published_dt = published_dt.replace(
                    tzinfo=timezone.utc
                )

            published_dt = published_dt.astimezone(
                timezone.utc
            )

        except Exception:

            continue

        # Behåll bara artiklar
        # som fortfarande ligger
        # inom 7-dagarsfönstret.

        if published_dt >= cutoff:

            item["published"] = (
                published_dt.isoformat()
            )

            articles[
                item["id"]
            ] = item

    # -----------------------------------------------------
    # FETCH RSS FEEDS
    # -----------------------------------------------------

    source_status = []

    for source in FEEDS:

        print(
            "Fetching:",
            source["name"]
        )

        try:

            raw = fetch_feed(
                source["url"]
            )

            parsed = feedparser.parse(
                raw
            )

            count = 0
            accepted = 0

            for entry in parsed.entries:

                count += 1

                article = normalize_entry(
                    entry,
                    source
                )

                if article is None:
                    continue

                if not article["title"]:
                    continue

                published_dt = datetime.fromisoformat(
                    article["published"]
                )

                # -------------------------------------------------
                # IGNORERA ARTIKLAR ÄLDRE ÄN 7 DAGAR
                # -------------------------------------------------

                if published_dt < cutoff:

                    continue

                articles[
                    article["id"]
                ] = article

                accepted += 1

            source_status.append({

                "source":
                    source["name"],

                "status":
                    "ok",

                "items":
                    count,

                "accepted":
                    accepted
            })

            print(
                f"  RSS entries: {count}"
            )

            print(
                f"  Accepted: {accepted}"
            )

        except Exception as error:

            source_status.append({

                "source":
                    source["name"],

                "status":
                    "error",

                "items":
                    0,

                "accepted":
                    0,

                "error":
                    str(error)
            })

            print(
                "  ERROR:",
                error
            )

    # -----------------------------------------------------
    # SORT ARTICLES
    # -----------------------------------------------------

    article_list = list(
        articles.values()
    )

    article_list.sort(
        key=lambda x:
            x.get("published")
            or "",
        reverse=True
    )

    # Säkerhetsgräns.
    article_list = article_list[:1000]

    # -----------------------------------------------------
    # STATISTICS
    # -----------------------------------------------------

    statistics = {

        "total":
            len(article_list),

        "critical":
            len([
                x
                for x in article_list
                if x.get(
                    "severity"
                ) == "CRITICAL"
            ]),

        "high":
            len([
                x
                for x in article_list
                if x.get(
                    "severity"
                ) == "HIGH"
            ]),

        "ransomware":
            len([
                x
                for x in article_list
                if "Ransomware"
                in x.get(
                    "categories",
                    []
                )
            ]),

        "zero_day":
            len([
                x
                for x in article_list
                if "Zero-day"
                in x.get(
                    "categories",
                    []
                )
            ])
    }

    # -----------------------------------------------------
    # OUTPUT
    # -----------------------------------------------------

    output = {

        "updated":
            now.isoformat(),

        "articles":
            article_list,

        "statistics":
            statistics,

        "sources":
            source_status
    }

    # -----------------------------------------------------
    # SAVE
    # -----------------------------------------------------

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            output,
            file,
            indent=2,
            ensure_ascii=False
        )

    print(
        "Saved:",
        OUTPUT_FILE
    )

    print(
        json.dumps(
            statistics,
            indent=2
        )
    )


# ---------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------

if __name__ == "__main__":

    main()
