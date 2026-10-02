import json
import os
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode
from urllib.request import Request, urlopen

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

KEV_URL = (
    "https://raw.githubusercontent.com/"
    "cisagov/kev-data/develop/"
    "known_exploited_vulnerabilities.json"
)

OUTPUT_DIR = "data"
OUTPUT_FILE = os.path.join(
    OUTPUT_DIR,
    "security.json"
)


# ---------------------------------------------------------
# BEVAKADE LEVERANTÖRER
# ---------------------------------------------------------

VENDORS = {

    "Microsoft": {
        "cpe_vendors": [
            "microsoft"
        ],

        "keywords": [
            "microsoft",
            "windows",
            "office",
            "exchange",
            "sharepoint",
            "azure",
            "defender",
            "active directory",
            "edge",
            "visual studio",
            ".net",
            "sql server"
        ]
    },

    "Red Hat": {
        "cpe_vendors": [
            "redhat"
        ],

        "keywords": [
            "red hat",
            "redhat",
            "rhel",
            "enterprise linux",
            "openshift"
        ]
    },

    "Apple": {
        "cpe_vendors": [
            "apple"
        ],

        "keywords": [
            "apple",
            "ios",
            "ipados",
            "macos",
            "webkit",
            "iphone",
            "ipad",
            "safari"
        ]
    }
}


# ---------------------------------------------------------
# HTTP
# ---------------------------------------------------------

def fetch_json(url, headers=None):

    default_headers = {
        "User-Agent": "SecurityMonitor/1.0"
    }

    if headers:
        default_headers.update(headers)

    request = Request(
        url,
        headers=default_headers
    )

    with urlopen(
        request,
        timeout=60
    ) as response:

        return json.loads(
            response.read()
            .decode("utf-8")
        )


# ---------------------------------------------------------
# TIME
# ---------------------------------------------------------

def iso_time(dt):

    return dt.strftime(
        "%Y-%m-%dT%H:%M:%S.000Z"
    )


# ---------------------------------------------------------
# NVD
# ---------------------------------------------------------

def get_nvd():

    now = datetime.now(
        timezone.utc
    )

    # Tre timmar ger marginal om en
    # GitHub Actions-körning blir försenad.

    start = now - timedelta(
        hours=3
    )

    params = urlencode({
        "lastModStartDate": iso_time(start),
        "lastModEndDate": iso_time(now),
        "resultsPerPage": 2000
    })

    url = (
        NVD_API
        + "?"
        + params
    )

    data = fetch_json(url)

    return data.get(
        "vulnerabilities",
        []
    )


# ---------------------------------------------------------
# KEV
# ---------------------------------------------------------

def get_kev():

    data = fetch_json(
        KEV_URL
    )

    vulnerabilities = data.get(
        "vulnerabilities",
        []
    )

    return {
        item.get("cveID")
        for item in vulnerabilities
        if item.get("cveID")
    }


# ---------------------------------------------------------
# TEXT
# ---------------------------------------------------------

def get_description(cve):

    for item in cve.get(
        "descriptions",
        []
    ):

        if item.get("lang") == "en":

            return item.get(
                "value",
                ""
            )

    return ""


def get_all_text(cve):

    text = get_description(cve)

    return text.lower()


# ---------------------------------------------------------
# CPE EXTRACTION
# ---------------------------------------------------------

def extract_cpes(obj):

    found = []

    if isinstance(
        obj,
        dict
    ):

        # Modern NVD data uses cpeMatch
        if "cpeMatch" in obj:

            for match in obj.get(
                "cpeMatch",
                []
            ):

                cpe = (
                    match.get("criteria")
                    or match.get("cpe23Uri")
                )

                if cpe:
                    found.append(cpe)

        # Recursively search configuration tree
        for value in obj.values():

            found.extend(
                extract_cpes(value)
            )

    elif isinstance(
        obj,
        list
    ):

        for item in obj:

            found.extend(
                extract_cpes(item)
            )

    return list(
        dict.fromkeys(found)
    )


# ---------------------------------------------------------
# CPE PARSING
# ---------------------------------------------------------

def parse_cpe(cpe):

    """
    Basic CPE 2.3 parser.

    Example:

    cpe:2.3:o:microsoft:windows_server_2022:...
    """

    if not cpe.startswith(
        "cpe:2.3:"
    ):

        return None

    parts = cpe.split(":")

    if len(parts) < 6:
        return None

    return {
        "part": parts[2],
        "vendor": parts[3].lower(),
        "product": parts[4].lower(),
        "version": (
            parts[5]
            if len(parts) > 5
            else "*"
        ),
        "raw": cpe
    }


# ---------------------------------------------------------
# PRODUCT NAME
# ---------------------------------------------------------

def clean_product_name(product):

    product = product.replace(
        "_",
        " "
    )

    product = product.replace(
        "-",
        " "
    )

    return product.strip()


def detect_products(cpes):

    products = []

    for cpe in cpes:

        parsed = parse_cpe(
            cpe
        )

        if not parsed:
            continue

        vendor = parsed[
            "vendor"
        ]

        product = clean_product_name(
            parsed["product"]
        )

        for name, config in VENDORS.items():

            if vendor in [
                x.lower()
                for x in config[
                    "cpe_vendors"
                ]
            ]:

                products.append({
                    "vendor": name,
                    "product": product,
                    "version": parsed[
                        "version"
                    ],
                    "cpe": cpe
                })

    # Deduplicate
    unique = {}

    for item in products:

        key = (
            item["vendor"],
            item["product"],
            item["version"]
        )

        unique[key] = item

    return list(
        unique.values()
    )


# ---------------------------------------------------------
# FALLBACK TEXT MATCHING
# ---------------------------------------------------------

def detect_vendor_from_text(
    description
):

    text = description.lower()

    matches = []

    for name, config in VENDORS.items():

        for keyword in config[
            "keywords"
        ]:

            if keyword in text:

                matches.append(
                    name
                )

                break

    return sorted(
        set(matches)
    )


# ---------------------------------------------------------
# CVSS
# ---------------------------------------------------------

def get_cvss(cve):

    metrics = cve.get(
        "metrics",
        {}
    )

    for key in [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30"
    ]:

        values = metrics.get(
            key,
            []
        )

        if values:

            metric = values[0]

            cvss = metric.get(
                "cvssData",
                {}
            )

            return {
                "score": cvss.get(
                    "baseScore"
                ),

                "severity": (
                    cvss.get(
                        "baseSeverity"
                    )
                    or metric.get(
                        "baseSeverity"
                    )
                    or "UNKNOWN"
                ),

                "vector": cvss.get(
                    "vectorString"
                )
            }

    return {
        "score": None,
        "severity": "UNKNOWN",
        "vector": None
    }


# ---------------------------------------------------------
# SECURITY SIGNALS
# ---------------------------------------------------------

def detect_signals(
    description
):

    text = description.lower()

    signals = []

    patterns = {

        "RCE": [
            "remote code execution",
            "arbitrary code execution"
        ],

        "PRIVILEGE_ESCALATION": [
            "privilege escalation",
            "elevation of privilege"
        ],

        "REMOTE": [
            "remote attacker",
            "remotely",
            "network"
        ],

        "AUTH_BYPASS": [
            "authentication bypass",
            "bypass authentication"
        ],

        "DOS": [
            "denial of service",
            "denial-of-service"
        ],

        "INFORMATION_DISCLOSURE": [
            "information disclosure",
            "sensitive information"
        ]
    }

    for signal, words in patterns.items():

        for word in words:

            if word in text:

                signals.append(
                    signal
                )

                break

    return signals


# ---------------------------------------------------------
# PRIORITY
# ---------------------------------------------------------

def calculate_priority(
    cvss,
    kev,
    signals
):

    severity = (
        cvss.get("severity")
        or "UNKNOWN"
    )

    if kev:

        return "P1"

    if (
        severity == "CRITICAL"
        and (
            "RCE" in signals
            or "REMOTE" in signals
        )
    ):

        return "P1"

    if severity == "CRITICAL":

        return "P2"

    if severity == "HIGH":

        return "P2"

    if severity == "MEDIUM":

        return "P3"

    return "P4"


# ---------------------------------------------------------
# NORMALIZATION
# ---------------------------------------------------------

def normalize_cve(
    item,
    kev_ids
):

    cve = item.get(
        "cve",
        {}
    )

    cve_id = cve.get(
        "id"
    )

    description = get_description(
        cve
    )

    cpes = extract_cpes(
        cve.get(
            "configurations",
            []
        )
    )

    products = detect_products(
        cpes
    )

    vendors = sorted(
        set(
            item["vendor"]
            for item in products
        )
    )

    # Text fallback only if CPE
    # information did not identify
    # a monitored vendor.

    if not vendors:

        vendors = detect_vendor_from_text(
            description
        )

    cvss = get_cvss(
        cve
    )

    kev = (
        cve_id in kev_ids
    )

    signals = detect_signals(
        description
    )

    priority = calculate_priority(
        cvss,
        kev,
        signals
    )

    return {

        "id": cve_id,

        "published": cve.get(
            "published"
        ),

        "modified": cve.get(
            "lastModified"
        ),

        "description": description,

        "vendors": vendors,

        "products": products,

        "cpes": cpes[:100],

        "cvss": cvss,

        "kev": kev,

        "signals": signals,

        "priority": priority,

        "url":
            f"https://nvd.nist.gov/"
            f"vuln/detail/{cve_id}"
    }


# ---------------------------------------------------------
# DATABASE FILE
# ---------------------------------------------------------

def load_existing():

    if not os.path.exists(
        OUTPUT_FILE
    ):

        return {
            "updated": None,
            "cves": [],
            "kev": []
        }

    try:

        with open(
            OUTPUT_FILE,
            "r",
            encoding="utf-8"
        ) as f:

            return json.load(f)

    except Exception:

        return {
            "updated": None,
            "cves": [],
            "kev": []
        }


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------

def main():

    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True
    )

    existing = load_existing()

    print(
        "Downloading NVD..."
    )

    nvd_items = get_nvd()

    print(
        f"NVD entries: "
        f"{len(nvd_items)}"
    )

    print(
        "Downloading CISA KEV..."
    )

    kev_ids = get_kev()

    print(
        f"KEV entries: "
        f"{len(kev_ids)}"
    )

    new_cves = []

    for item in nvd_items:

        normalized = normalize_cve(
            item,
            kev_ids
        )

        if normalized[
            "vendors"
        ]:

            new_cves.append(
                normalized
            )

    print(
        "Relevant CVEs: "
        f"{len(new_cves)}"
    )

    combined = {}

    # Existing
    for cve in existing.get(
        "cves",
        []
    ):

        combined[
            cve["id"]
        ] = cve

    # New
    for cve in new_cves:

        combined[
            cve["id"]
        ] = cve

    cves = sorted(
        combined.values(),
        key=lambda x:
            x.get("modified")
            or "",
        reverse=True
    )

    # Keep last 1000
    cves = cves[:1000]

    # Statistics
    statistics = {

        "total_relevant_cves":
            len(cves),

        "critical":
            len([
                x for x in cves
                if x.get(
                    "cvss",
                    {}
                ).get(
                    "severity"
                ) == "CRITICAL"
            ]),

        "high":
            len([
                x for x in cves
                if x.get(
                    "cvss",
                    {}
                ).get(
                    "severity"
                ) == "HIGH"
            ]),

        "medium":
            len([
                x for x in cves
                if x.get(
                    "cvss",
                    {}
                ).get(
                    "severity"
                ) == "MEDIUM"
            ]),

        "kev":
            len([
                x for x in cves
                if x.get(
                    "kev"
                )
            ]),

        "p1":
            len([
                x for x in cves
                if x.get(
                    "priority"
                ) == "P1"
            ]),

        "p2":
            len([
                x for x in cves
                if x.get(
                    "priority"
                ) == "P2"
            ])
    }

    output = {

        "updated":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "cves":
            cves,

        "kev":
            sorted(
                kev_ids
            ),

        "statistics":
            statistics
    }

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            output,
            f,
            indent=2,
            ensure_ascii=False
        )

    print(
        "Saved security data."
    )

    print(
        json.dumps(
            statistics,
            indent=2
        )
    )


if __name__ == "__main__":

    main()
