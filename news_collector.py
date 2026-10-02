import json
import os
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.request import Request, urlopen

import feedparser


OUTPUT_DIR = "data"
OUTPUT_FILE = os.path.join(
    OUTPUT_DIR,
    "news.json"
)


# =========================================================
# NEWS SOURCES
# =========================================================

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


# =========================================================
# HTTP
# =========================================================

def fetch_feed(url):

    headers = {
        "User-Agent":
            "SecurityMonitor/1.0"
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


# =========================================================
# DATE
# =========================================================

def parse_date(entry):

    values = [
        entry.get("published"),
        entry.get("updated")
    ]

    for value in values:

        if not value:
            continue

        try:

            dt = parsedate_to_datetime(
                value
            )

            if dt.tzinfo is None:

                dt = dt.replace(
                    tzinfo=timezone.utc
                )

            return dt.isoformat()

        except Exception:
            pass


    # Some feeds expose struct_time
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

                return dt.isoformat()

            except Exception:
                pass


    return None


# =========================================================
# TEXT
# =========================================================

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


def get_text(entry):

    title = entry.get(
        "title",
        ""
    )

    summary = (
        entry.get("summary")
        or entry.get("description")
        or ""
    )

    return (
        title
        + " "
        + strip_html(summary)
    )


# =========================================================
# CATEGORY DETECTION
# =========================================================

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


def detect_categories(text):

    text = text.lower()

    categories = []

    for category, keywords in (
        CATEGORY_RULES.items()
    ):

        for keyword in keywords:

            if keyword in text:

                categories.append(
                    category
                )

                break

    return categories


# =========================================================
# VENDOR DETECTION
# =========================================================

def detect_vendors(text):

    text = text.lower()

    vendors = []

    keywords = {

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


    for vendor, words in (
        keywords.items()
    ):

        for word in words:

            if word in text:

                vendors.append(
                    vendor
                )

                break

    return sorted(
        set(vendors)
    )


# =========================================================
# SEVERITY / ALERT
# =========================================================

def detect_severity(
    text,
    categories
):

    text = text.lower()

    if (
        "zero-day" in categories
        or "ransomware" in categories
        or "actively exploited" in text
        or "exploited in the wild" in text
    ):

        return "CRITICAL"


    if (
        "exploit" in categories
        or "apt" in categories
        or "data breach" in categories
    ):

        return "HIGH"


    if (
        "vulnerability" in categories
        or "malware" in categories
    ):

        return "MEDIUM"


    return "INFO"


def detect_priority(
    severity,
    categories
):

    if severity == "CRITICAL":

        return "P1"


    if severity == "HIGH":

        return "P2"


    if severity == "MEDIUM":

        return "P3"


    return "P4"


# =========================================================
# ENTRY NORMALIZATION
# =========================================================

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


    url = (
        entry.get("link")
        or ""
    )


    published = parse_date(
        entry
    )


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


    # Preserve explicit feed vendor
    if source.get(
        "vendor"
    ):

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
        severity,
        categories
    )


    return {

        "id":
            url
            or title,

        "title":
            title,

        "summary":
            summary,

        "url":
            url,

        "source":
            source["name"],

        "source_category":
            source["category"],

        "published":
            published,

        "vendors":
            vendors,

        "categories":
            categories,

        "severity":
            severity,

        "priority":
            priority
    }


# =========================================================
# LOAD EXISTING
# =========================================================

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


# =========================================================
# MAIN
# =========================================================

def main():

    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True
    )


    existing =
        load_existing()


    articles = {}


    for item in existing:

        if item.get("id"):

            articles[
                item["id"]
            ] = item


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


            parsed =
                feedparser.parse(
                    raw
                )


            count = 0


            for entry in (
                parsed.entries
            ):

                article =
                    normalize_entry(
                        entry,
                        source
                    )


                if not article[
                    "title"
                ]:

                    continue


                articles[
                    article["id"]
                ] = article


                count += 1


            source_status.append({

                "source":
                    source["name"],

                "status":
                    "ok",

                "items":
                    count

            })


            print(
                f"  OK: {count}"
            )


        except Exception as error:

            source_status.append({

                "source":
                    source["name"],

                "status":
                    "error",

                "items":
                    0,

                "error":
                    str(error)

            })


            print(
                "  ERROR:",
                error
            )


    article_list =
        list(
            articles.values()
        )


    # Newest first
    article_list.sort(
        key=lambda x:
            x.get(
                "published"
            )
            or "",
        reverse=True
    )


    # Keep latest 1000
    article_list =
        article_list[:1000]


    statistics = {

        "total":
            len(article_list),

        "critical":
            len([
                x for x
                in article_list
                if x.get(
                    "severity"
                ) == "CRITICAL"
            ]),

        "high":
            len([
                x for x
                in article_list
                if x.get(
                    "severity"
                ) == "HIGH"
            ]),

        "ransomware":
            len([
                x for x
                in article_list
                if "Ransomware"
                in x.get(
                    "categories",
                    []
                )
            ]),

        "zero_day":
            len([
                x for x
                in article_list
                if "Zero-day"
                in x.get(
                    "categories",
                    []
                )
            ])
    }


    output = {

        "updated":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "articles":
            article_list,

        "statistics":
            statistics,

        "sources":
            source_status
    }


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


if __name__ == "__main__":

    main()
