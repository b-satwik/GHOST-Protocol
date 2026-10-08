import subprocess
from bs4 import BeautifulSoup
import re

url = "https://0x00sec.org/t/cve-2024-38077-windows-remote-desktop-licensing-service-rce/39564"
cmd = ["curl", "-s", "-L", "-A", "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0", url]
res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
html = res.stdout
soup = BeautifulSoup(html, "html.parser")

print("TITLE:", soup.find("title").get_text() if soup.find("title") else "None")

# Find itemprops or itemprop="name", itemprop="articleBody", itemprop="author", itemprop="position"
titles = soup.find_all(attrs={"itemprop": "name"})
print("ITEMPROP NAME:", [t.get_text().strip() for t in titles])

authors = soup.find_all(attrs={"itemprop": "author"})
print("ITEMPROP AUTHOR:", [a.get_text().strip() for a in authors])

dates = soup.find_all(attrs={"itemprop": "datePublished"})
print("ITEMPROP DATES:", [d.get("content") or d.get_text().strip() for d in dates])

bodies = soup.find_all(attrs={"itemprop": "articleBody"})
print("ITEMPROP BODIES count:", len(bodies))
if bodies:
    print("Root Body Snippet:", bodies[0].get_text()[:200].replace("\n", " "))

posts = soup.find_all(class_="topic-body")
if not posts:
    posts = soup.find_all(attrs={"itemprop": "comment"})
print("Comments count:", len(posts))
