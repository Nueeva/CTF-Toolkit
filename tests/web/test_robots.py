from ctf_toolkit.web.robots import parse_robots_txt


def test_parse_robots_txt():
    sample = """User-agent: *
Disallow: /admin
Disallow: /s3cr3t-area
Allow: /public
Sitemap: https://example.com/sitemap.xml
"""
    parsed = parse_robots_txt(sample)
    assert "/admin" in parsed["disallow"]
    assert "/s3cr3t-area" in parsed["disallow"]
    assert "/public" in parsed["allow"]
    assert "https://example.com/sitemap.xml" in parsed["sitemaps"]
