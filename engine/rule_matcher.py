"""
Rule Matcher Engine for Layer-7 HTTP Threat Detection.
Scans URIs, headers, and payloads against compiled regex signatures.
"""
import re
import json
from typing import List, Dict, Any, Optional
from pathlib import Path
from config.settings import CONFIG_DIR
from parsers.http_parser import HTTPRequestData


class RuleMatcher:
    def __init__(self, signatures_file: Optional[Path] = None):
        self.rules: List[Dict[str, Any]] = []
        file_path = signatures_file or (CONFIG_DIR / "signatures.json")
        self._load_rules(file_path)

    def _load_rules(self, file_path: Path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                raw_rules = data.get("http_rules", [])

            for r in raw_rules:
                compiled = re.compile(r["regex"])
                self.rules.append({
                    "id": r["id"],
                    "name": r["name"],
                    "category": r["category"],
                    "severity": r["severity"],
                    "description": r.get("description", ""),
                    "pattern": compiled
                })
        except Exception as e:
            print(f"[RuleMatcher] Failed to load signatures: {e}")

    def inspect_http(self, http_data: HTTPRequestData) -> List[Dict[str, Any]]:
        """
        Scan HTTP request across multiple zones (URI, Query, Body, Headers).
        Returns list of triggered rule matches with evidence.
        """
        matches = []
        targets = [
            ("URI", http_data.uri),
            ("BODY", http_data.body),
            ("USER_AGENT", http_data.headers.get("user-agent", "")),
        ]

        for rule in self.rules:
            pattern = rule["pattern"]
            for zone_name, content in targets:
                if not content:
                    continue
                match = pattern.search(content)
                if match:
                    start, end = match.span()
                    matched_str = match.group(0)

                    # Evidence Slicing: Bóc tách lát cắt ngữ cảnh +- 40 ký tự quanh chuỗi độc hại
                    slice_start = max(0, start - 40)
                    slice_end = min(len(content), end + 40)
                    prefix = "..." if slice_start > 0 else ""
                    suffix = "..." if slice_end < len(content) else ""
                    
                    before = content[slice_start:start].replace("\r", " ").replace("\n", " ")
                    after = content[end:slice_end].replace("\r", " ").replace("\n", " ")
                    evidence_slice = f"{prefix}{before} >>> {matched_str} <<< {after}{suffix}"

                    matches.append({
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "category": rule["category"],
                        "severity": rule["severity"],
                        "description": rule["description"],
                        "evidence": matched_str,
                        "evidence_slice": evidence_slice,
                        "location": zone_name,
                        "details": f"Phát hiện trong {zone_name}: '{evidence_slice}'"
                    })
                    break  # One match per rule is sufficient

        return matches
