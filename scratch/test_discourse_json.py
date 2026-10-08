import subprocess
import json

url = "https://0x00sec.org/t/cve-2024-38077-windows-remote-desktop-licensing-service-rce/39564.json"
cmd = ["curl", "-s", "-L", "-A", "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0", url]
res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
body = res.stdout
print("Body len:", len(body))
print("Header snippet:", body[:200])

try:
    data = json.loads(body)
    print("TITLE:", data.get("title"))
    print("SLUG:", data.get("slug"))
    print("POSTS COUNT:", data.get("posts_count"))
    post_stream = data.get("post_stream", {})
    posts = post_stream.get("posts", [])
    print("POSTS IN STREAM:", len(posts))
    if posts:
        root_post = posts[0]
        print("Root Author:", root_post.get("username") or root_post.get("display_username"))
        print("Root Timestamp:", root_post.get("created_at"))
        print("Root Content snippet:", root_post.get("cooked")[:150] if root_post.get("cooked") else "")
        print("Replies count:", len(posts) - 1)
except Exception as e:
    print("JSON parse error:", e)
