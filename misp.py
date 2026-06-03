import requests
import json
from datetime import datetime, timedelta

MISP_URL = "https://misp.local"
API_KEY = "YOUR_API_KEY_HERE"

headers = {
    "Authorization": API_KEY,
    "Accept": "application/json",
    "Content-Type": "application/json"
}

# Pull IOCs from the last 24 hours
# Adjust 'last' and filters to your needs
payload = {
    "returnFormat": "json",
    "last": "1d",           # last 24 hours; can use 7d, 12h, 30m etc.
    "to_ids": True,         # only attributes flagged as IDS/SIEM-relevant
    "published": True,      # only published events
    "enforceWarninglist": True,  # exclude known false positives
    "deleted": False,
    "limit": 1000,
    "page": 1,
    # Filter to the most common IOC types
    "type": [
        "ip-src",
        "ip-dst",
        "domain",
        "hostname",
        "url",
        "md5",
        "sha1",
        "sha256",
        "email-src",
        "ip-dst|port"
    ]
}

def fetch_iocs():
    all_iocs = []
    page = 1

    while True:
        payload["page"] = page
        response = requests.post(
            f"{MISP_URL}/attributes/restSearch",
            headers=headers,
            json=payload,
            verify=True  # set False if using self-signed cert
        )

        if response.status_code == 403:
            print("Auth failed — check your API key")
            break
        elif response.status_code != 200:
            print(f"Error {response.status_code}: {response.text}")
            break

        data = response.json()
        attributes = data.get("response", {}).get("Attribute", [])

        if not attributes:
            break  # no more results

        all_iocs.extend(attributes)
        print(f"Page {page}: fetched {len(attributes)} IOCs")

        # Check result count header to decide if more pages exist
        result_count = int(response.headers.get("X-Result-Count", 0))
        if len(all_iocs) >= result_count:
            break

        page += 1

    return all_iocs


def normalize_for_siem(attributes):
    """Flatten the MISP attribute into a simple dict for your SIEM."""
    iocs = []
    for attr in attributes:
        iocs.append({
            "misp_id":        attr.get("id"),
            "uuid":           attr.get("uuid"),
            "event_id":       attr.get("event_id"),
            "type":           attr.get("type"),
            "category":       attr.get("category"),
            "value":          attr.get("value"),
            "to_ids":         attr.get("to_ids"),
            "timestamp":      attr.get("timestamp"),
            "comment":        attr.get("comment"),
            "tags":           [t.get("name") for t in attr.get("Tag", [])],
            "event_uuid":     attr.get("event_uuid"),
        })
    return iocs


if __name__ == "__main__":
    print("Fetching IOCs from MISP...")
    raw = fetch_iocs()
    iocs = normalize_for_siem(raw)

    print(f"\nTotal IOCs fetched: {len(iocs)}")

    # Write to JSON file for SIEM ingestion, or pipe directly to your SIEM API
    output_file = "misp_iocs.json"
    with open(output_file, "w") as f:
        json.dump(iocs, f, indent=2)

    print(f"Written to {output_file}")
