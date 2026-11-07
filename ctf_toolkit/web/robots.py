from __future__ import annotations

import re


def parse_robots_txt(robots_content: str) -> dict[str, list[str]]:
    """Parse robots.txt content and extract user-agents, disallow, and allow rules."""
    rules: dict[str, list[str]] = {"disallow": [], "allow": [], "sitemaps": []}

    for line in robots_content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        match_disallow = re.match(r"^Disallow:\s*(.*)$", line, re.IGNORECASE)
        if match_disallow:
            path = match_disallow.group(1).strip()
            if path and path not in rules["disallow"]:
                rules["disallow"].append(path)
            continue

        match_allow = re.match(r"^Allow:\s*(.*)$", line, re.IGNORECASE)
        if match_allow:
            path = match_allow.group(1).strip()
            if path and path not in rules["allow"]:
                rules["allow"].append(path)
            continue

        match_sitemap = re.match(r"^Sitemap:\s*(.*)$", line, re.IGNORECASE)
        if match_sitemap:
            sm = match_sitemap.group(1).strip()
            if sm and sm not in rules["sitemaps"]:
                rules["sitemaps"].append(sm)

    return rules
