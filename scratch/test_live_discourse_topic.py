import sys
import os
import subprocess

repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from src.observer.adapters.discourse_adapter import DiscourseAdapter
from src.collector.sanitizer import ContentSanitizer
from src.filter.threat_filter import ThreatFilter
from src.pipeline.lab_bridge import DarkWatchLabBridge
from src.discovery.observation_record import ObservationRecord
import datetime

url = "https://0x00sec.org/t/cve-2024-38077-windows-remote-desktop-licensing-service-rce/39564"
cmd = ["curl", "-s", "-L", "-A", "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0", url]
res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
html = res.stdout

adapter = DiscourseAdapter()
thread_info = adapter.extract_thread_info(url, html)

print("Title:      ", thread_info.get("title"))
print("Author:     ", thread_info.get("author"))
print("Timestamp:  ", thread_info.get("timestamp"))
print("Content len:", len(thread_info.get("content") or ""))
print("Reported replies:", thread_info.get("reported_comments_count"))
print("Observed replies:", thread_info.get("observed_comments_count"))
print("Direct replies:  ", len(thread_info.get("direct_replies", [])))

sanitizer = ContentSanitizer()
clean_text, _, clean_sha = sanitizer.sanitize_html(html)

tf = ThreatFilter()
filter_res = tf.filter_and_categorize(clean_text)
print("Threat Filter Match:", filter_res.get("is_threat"), "| Category:", filter_res.get("category"))

bridge = DarkWatchLabBridge()
obs_rec = ObservationRecord(
    source_id="src_0x00sec_test",
    url=url,
    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    status="CONTENT_ACCESSIBLE",
    raw_sha256="raw_sha",
    clean_sha256=clean_sha,
    raw_html=html,
    clean_text=clean_text
)
bridge_out = bridge.process_stage1_observation(obs_rec)
print("Risk Score: ", bridge_out.get("risk_score"))
print("CTI count:  ", len(bridge_out.get("cti", {}).get("indicators", [])))
print("STIX ID:    ", bridge_out.get("stix", {}).get("bundle_id"))
print("MITRE techs:", [t.get("id") for t in bridge_out.get("mitre_mapping", {}).get("techniques", [])])
print("XAI summary:", bridge_out.get("xai", {}).get("summary_narrative"))
