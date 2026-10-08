import subprocess
from bs4 import BeautifulSoup

url = "https://0x00sec.org/t/cve-2024-38077-windows-remote-desktop-licensing-service-rce/39564"
cmd = ["curl", "-s", "-L", "-A", "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0", url]
res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
html = res.stdout
soup = BeautifulSoup(html, "html.parser")

links = [a["href"] for a in soup.find_all("a", href=True)]
print(f"Total links: {len(links)}")
for l in links[:30]:
    print("  ", l)
