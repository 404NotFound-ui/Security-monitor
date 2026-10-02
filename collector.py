import json
import os
import re
from datetime import datetime, timedelta, timezone
from urllib.request import Request, urlopen

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"

OUTPUT_DIR = "data"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "security.json")

# Vår initiala bevakning
VENDORS = {
    "Microsoft": [
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
    ],
    "Red Hat": [
        "redhat",
        "red hat",
        "rhel",
        "enterprise linux",
        "openshift",
    ],
    "Apple": [
        "apple",
        "ios",
        "ipados",
        "macos",
        "webkit",
        "iphone",
        "ipad",
        "safari",
    ],
}


def fetch_json(url, headers=None):
    request = Request(
        url,
        headers=headers or {
            "User-Agent": "SecurityMonitor/1.0"
        }
    )

    with urlopen(request, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def iso_time(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def get_nvd():
    now = datetime.now(timezone.utc)

    # Vi hämtar de senaste 3 timmarna.
    # Det ger marginal om GitHub Actions startar försenat.
    start = now - timedelta(hours=3)

    params = (
        f"?lastModStartDate={iso_time(start)}"
        f"&lastModEndDate={iso_time(now)}"
        f"&resultsPerPage=2000"
    )

    data = fetch_json(NVD_API + params)

    return data.get("vulnerabilities", [])


def get_text(cve):
    descriptions = cve.get("descriptions", [])

    texts = []

    for description in descriptions:
        value = description.get("value", "")
        texts.append(value)

    return " ".join(texts).lower()


def detect_vendor(cve):
    text = get_text(cve)

    configurations = cve.get("configurations", [])

    # CPE-information
    cpe_text = json.dumps(configurations).lower()

    combined = text + " " + cpe_text

    matches = []

    for vendor, keywords in VENDORS.items():
        for keyword in keywords:
            if keyword.lower() in combined:
                matches.append(vendor)
                break

    return sorted(set(matches))


def get_cvss(cve):
    metrics = cve.get("metrics", {})

    # Försök CVSS v3.1
    for key in ["cvssMetricV31", "cvssMetricV30"]:
        values = metrics.get(key, [])

        if values:
            metric = values[0]
            cvss = metric.get("cvssData", {})

            return {
                "score": cvss.get("baseScore"),
                "severity": cvss.get("baseSeverity"),
                "vector": cvss.get("vectorString"),
            }

    # Fallback CVSS v2
    values = metrics.get("cvssMetricV2", [])

    if values:
        cvss = values[0].get("cvssData", {})

        return {
            "score": cvss.get("baseScore"),
            "severity": values[0].get(
                "baseSeverity",
                "UNKNOWN"
            ),
            "vector": cvss.get("vectorString"),
        }

    return {
        "score": None,
        "severity": "UNKNOWN",
        "vector": None,
    }


def normalize_cve(item):
    cve = item.get("cve", {})

    cve_id = cve.get("id")

    description = ""

    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "")
            break

    vendors = detect_vendor(cve)
    cvss = get_cvss(cve)

    published = cve.get("published")
    modified = cve.get("lastModified")

    return {
        "id": cve_id,
        "published": published,
        "modified": modified,
        "description": description,
        "vendors": vendors,
        "cvss": cvss,
        "kev": False,
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


def get_kev():
    data = fetch_json(KEV_URL)

    vulnerabilities = data.get(
        "vulnerabilities",
        []
    )

    return {
        item.get("cveID")
        for item in vulnerabilities
        if item.get("cveID")
    }


def load_existing():
    if not os.path.exists(OUTPUT_FILE):
        return {
            "updated": None,
            "cves": [],
            "kev": [],
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
            "kev": [],
        }


def main():

    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True
    )

    existing = load_existing()

    print("Downloading NVD data...")
    nvd_items = get_nvd()

    print(f"NVD returned {len(nvd_items)} entries")

    new_cves = []

    for item in nvd_items:

        normalized = normalize_cve(item)

        # Vi bryr oss initialt bara om vår stack
        if not normalized["vendors"]:
            continue

        new_cves.append(normalized)

    print(
        f"Relevant CVEs found: {len(new_cves)}"
    )

    # Hämta KEV
    print("Downloading CISA KEV...")
    kev_ids = get_kev()

    print(
        f"KEV contains {len(kev_ids)} CVEs"
    )

    # Markera KEV
    for cve in new_cves:
        if cve["id"] in kev_ids:
            cve["kev"] = True

    # Slå ihop med tidigare data
    combined = {}

    for cve in existing.get("cves", []):
        combined[cve["id"]] = cve

    for cve in new_cves:
        combined[cve["id"]] = cve

    # Sortera nyast först
    cves = sorted(
        combined.values(),
        key=lambda x: x.get("modified") or "",
        reverse=True,
    )

    # Behåll de senaste 1000
    cves = cves[:1000]

    output = {
        "updated": datetime.now(
            timezone.utc
        ).isoformat(),

        "cves": cves,

        "kev": sorted(
            kev_ids
        ),

        "statistics": {
            "total_relevant_cves": len(cves),
            "kev_count": len(
                [
                    x
                    for x in cves
                    if x.get("kev")
                ]
            ),
        },
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
            ensure_ascii=False,
        )

    print(
        f"Saved {len(cves)} CVEs"
    )


if __name__ == "__main__":
    main()
