import subprocess
from bs4 import BeautifulSoup

url = "https://0x00sec.org/t/cve-2024-38077-windows-remote-desktop-licensing-service-rce/39564"
cmd = ["curl", "-s", "-L", "-A", "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0", url]
res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
html = res.stdout
soup = BeautifulSoup(html, "html.parser")

print("TITLE TAG:", soup.title.get_text() if soup.title else "None")
print("H1 TAGS:", [h1.get_text().strip() for h1 in soup.find_all("h1")])
print("SPAN CREATOR / USERNAME:", [s.get_text().strip() for s in soup.find_all(class_=["creator", "username", "author", "full-name"])[:5]])
print("TIME TAGS:", [t.get_text().strip() or t.get("datetime") or t.get("title") for t in soup.find_all("time")[:5]])

print("\n--- SAMPLE POST CONTAINERS ---")
posts = soup.find_all(class_=["topic-body", "post-stream", "topic-post", "post"])
print("Found post containers:", len(posts))
for i, p in enumerate(posts[:3]):
    print(f"Post {i+1} snippet:", p.get_text()[:150].replace("\n", " "))
