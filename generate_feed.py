import json
from datetime import datetime, timedelta
from urllib.request import urlopen
from xml.sax.saxutils import escape

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Giorno precedente
yesterday = (datetime.utcnow() - timedelta(days=1)).strftime("%Y-%m-%d")

with urlopen(KEV_URL) as response:
    data = json.load(response)

items = []

for vuln in data["vulnerabilities"]:

    if vuln.get("dateAdded") != yesterday:
        continue

    cve = vuln.get("cveID", "")
    vendor = vuln.get("vendorProject", "")
    product = vuln.get("product", "")
    vuln_name = vuln.get("vulnerabilityName", "")
    description = vuln.get("shortDescription", "")

    title = f"{cve} - {vendor} - {product}"

    link = (
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        f"?search_api_fulltext={cve}"
    )

    pub_date = datetime.strptime(
        vuln["dateAdded"],
        "%Y-%m-%d"
    ).strftime("%a, %d %b %Y 00:00:00 GMT")

    items.append(f"""
    <item>
        <title>{escape(title)}</title>
        <link>{escape(link)}</link>
        <guid isPermaLink="false">{escape(cve)}</guid>
        <pubDate>{pub_date}</pubDate>
        <description><![CDATA[
<b>{escape(vuln_name)}</b><br/>
Vendor: {escape(vendor)}<br/>
Product: {escape(product)}<br/><br/>
{escape(description)}
        ]]></description>
    </item>
""")

# Data/ora di generazione del feed
build_date = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

rss = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
<channel>
<title>CISA KEV Daily Feed</title>
<link>https://GL-TS.github.io/cisa-kev-rss/rss.xml</link>
<description>CISA KEV vulnerabilities added yesterday</description>
<lastBuildDate>{build_date}</lastBuildDate>
{''.join(items)}
</channel>
</rss>
"""

with open("rss.xml", "w", encoding="utf-8") as f:
    f.write(rss)

print(f"Generated RSS for dateAdded={yesterday}")
print(f"Build date: {build_date}")
