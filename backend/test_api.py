import urllib.request
import json

base_url = "http://localhost:8000"

endpoints = [
    "/api/health",
    "/api/sessions",
    "/api/pcap/demo",
    "/api/report/json",
]

for ep in endpoints:
    url = base_url + ep
    try:
        if "demo" in ep:
            req = urllib.request.Request(url, method="POST")
        else:
            req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            print(f"[{ep}] -> {response.status}")
            print(json.dumps(data, indent=2)[:200] + "...\n")
    except Exception as e:
        print(f"[{ep}] -> ERROR: {e}\n")
