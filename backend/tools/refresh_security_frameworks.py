"""Refresh the offline reference registry from official, versioned sources.

Run explicitly during KB maintenance, never on the analysis request path.
Only identifiers, titles, CWE membership and source hashes are imported, not
attack instructions or executable rules. Review the diff before publishing.
"""

import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re

import requests
import yaml


DESTINATION = Path(__file__).resolve().parents[1] / "app/data/security_frameworks.json"
SOURCES = []


class CweTitles(HTMLParser):
    def __init__(self):
        super().__init__()
        self.titles = {}

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        match = re.search(r"/data/definitions/(\d+)\.html$", attributes.get("href", ""))
        if tag == "a" and match and attributes.get("title"):
            self.titles[f"CWE-{match.group(1)}"] = attributes["title"]


def fetch(url):
    response = requests.get(url, timeout=90)
    response.raise_for_status()
    SOURCES.append({"url": url, "sha256": hashlib.sha256(response.content).hexdigest()})
    return response.text


def commit(repo, ref):
    return json.loads(fetch(f"https://api.github.com/repos/{repo}/commits/{ref}"))["sha"]


def main():
    frameworks = {}
    revision = commit("OWASP/Top10", "master")
    files = json.loads(fetch(f"https://api.github.com/repos/OWASP/Top10/contents/2025/docs/en?ref={revision}"))
    entries = {}
    for item in files:
        if not re.match(r"A\d\d_2025-", item["name"]):
            continue
        body = fetch(item["download_url"])
        identifier = item["name"][:3]
        name = item["name"].split("-", 1)[1].removesuffix(".md").replace("_", " ")
        # Only the official mapped-CWE list, not incidental mentions in examples.
        section = re.split(r"(?im)^#+\s+List of Mapped CWEs\s*$", body)
        if len(section) != 2:
            raise ValueError(f"Missing CWE membership section: {item['name']}")
        entries[identifier] = {"name": name, "cwes": sorted(set(re.findall(r"CWE-\d+", section[1]))),
                               "url": f"https://owasp.org/Top10/2025/{item['name'].removesuffix('.md')}/"}
    assert len(entries) == 10
    frameworks["owasp_web"] = {"name": "OWASP Web Top 10", "version": "2025", "entries": entries}

    revision = commit("GenAI-Security-Project/GenAI-LLM-Top10", "main")
    files = json.loads(fetch(f"https://api.github.com/repos/GenAI-Security-Project/GenAI-LLM-Top10/contents/2026/final?ref={revision}"))
    entries = {}
    for item in files:
        if not re.match(r"LLM(?:0[1-9]|10)_", item["name"]):
            continue
        body = fetch(item["download_url"])
        heading = next((line.lstrip("# ").strip() for line in body.splitlines() if line.startswith("# ")),
                       re.sub(r"(?<=[a-z])(?=[A-Z])", " ", item["name"].split("_", 1)[1].removesuffix(".md")))
        entries[item["name"][:5]] = {"name": re.sub(r"^LLM\d+(?::2026)?\s*[-:]?\s*", "", heading), "url": item["html_url"]}
    assert len(entries) == 10
    frameworks["owasp_llm"] = {"name": "OWASP LLM Top 10", "version": "2026", "entries": entries}

    attack = json.loads(fetch("https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v19.2/enterprise-attack/enterprise-attack.json"))
    entries = {}
    for item in attack["objects"]:
        if item.get("type") != "attack-pattern" or item.get("revoked") or item.get("x_mitre_deprecated"):
            continue
        ref = next((ref for ref in item.get("external_references", []) if ref.get("source_name") == "mitre-attack"), None)
        if ref:
            entries[ref["external_id"]] = {"name": item["name"], "url": ref["url"]}
    frameworks["mitre_attack"] = {"name": "MITRE ATT&CK Enterprise", "version": "19.2", "entries": entries}

    revision = commit("mitre-atlas/atlas-data", "main")
    atlas = yaml.safe_load(fetch(f"https://raw.githubusercontent.com/mitre-atlas/atlas-data/{revision}/dist/v6/ATLAS-2026.08.yaml"))
    frameworks["mitre_atlas"] = {"name": "MITRE ATLAS", "version": str(atlas["collection"]["version"]),
        "entries": {key: {"name": item["name"], "url": f"https://atlas.mitre.org/techniques/{key}"}
                    for key, item in atlas["techniques"].items()}}

    api_url = "https://owasp.org/API-Security/editions/2023/en/0x11-t10/"
    api = fetch(api_url)
    entries = {}
    for identifier, name in re.findall(r"(API\d+):2023\s*(?:-\s*)?([^<\n]+)", api):
        entries[identifier] = {"name": name.strip(), "url": api_url}
    assert len(entries) == 10
    frameworks["owasp_api"] = {"name": "OWASP API Top 10", "version": "2023", "entries": entries}

    agent_url = "https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/"
    fetch(agent_url)
    names = ["Agent Goal Hijack", "Tool Misuse", "Identity and Privilege Abuse", "Agentic Supply Chain Vulnerabilities",
             "Unexpected Code Execution", "Memory and Context Poisoning", "Insecure Inter-Agent Communication",
             "Cascading Failures", "Human-Agent Trust Exploitation", "Rogue Agents"]
    frameworks["owasp_agentic"] = {"name": "OWASP Agentic Top 10", "version": "2026",
        "entries": {f"ASI{i:02}": {"name": name, "url": agent_url} for i, name in enumerate(names, 1)}}

    top25_url = "https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html"
    body = fetch(top25_url)
    titles = CweTitles()
    titles.feed(body)
    ranks = [79, 89, 352, 862, 787, 22, 416, 125, 78, 94, 120, 434, 476, 121, 502, 122, 863, 20, 284, 200, 306, 918, 77, 639, 770]
    assert all(f"{number}.html" in body for number in ranks)
    frameworks["cwe_top25"] = {"name": "CWE Top 25", "version": "2025",
        "entries": {f"CWE-{number}": {"name": titles.titles[f"CWE-{number}"], "rank": rank, "url": top25_url} for rank, number in enumerate(ranks, 1)}}
    fetch("https://www.sans.org/top25-software-errors")

    result = {"schema_version": "1.0", "verified_on": "2026-09-05", "frameworks": frameworks,
              "sources": SOURCES, "notice": "Reference mappings are not compliance certification or proof of exploitability. SANS references CWE; current ranks use MITRE's explicitly versioned 2025 list."}
    DESTINATION.write_text(json.dumps(result, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(json.dumps({key: {"version": value["version"], "entries": len(value["entries"])} for key, value in frameworks.items()}, indent=2))


if __name__ == "__main__":
    main()
