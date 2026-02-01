import json
import os
import pandas as pd
import matplotlib.pyplot as plt

LOG_FILE = os.path.join("logs", "events.jsonl")
OUT_DIR = "reports"
os.makedirs(OUT_DIR, exist_ok=True)

events = []
with open(LOG_FILE, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            pass

df = pd.DataFrame(events)
if df.empty:
    print("No events found in logs/events.jsonl")
    raise SystemExit(0)

df["ts"] = pd.to_datetime(df["ts"], errors="coerce")
df = df.dropna(subset=["ts"])
df["hour"] = df["ts"].dt.floor("h")

# Summaries
top_ips = df["ip"].value_counts().head(20)
top_paths = df["path"].value_counts().head(20)
top_classes = df.get("classification", pd.Series(dtype=str)).value_counts().head(20)

top_ips.to_csv(os.path.join(OUT_DIR, "top_ips.csv"), header=["count"])
top_paths.to_csv(os.path.join(OUT_DIR, "top_paths.csv"), header=["count"])
top_classes.to_csv(os.path.join(OUT_DIR, "top_classifications.csv"), header=["count"])

# Hits over time
hits = df.groupby("hour").size()
plt.figure()
hits.plot()
plt.title("Honeypot Hits Over Time (Hourly)")
plt.xlabel("Time (UTC)")
plt.ylabel("Hits")
plt.tight_layout()
plt.savefig(os.path.join(OUT_DIR, "hits_over_time.png"), dpi=150)

# Markdown report
summary_path = os.path.join(OUT_DIR, "summary.md")
with open(summary_path, "w", encoding="utf-8") as f:
    f.write("# Honeypot Summary Report\n\n")
    f.write(f"- Total events: **{len(df)}**\n")
    f.write(f"- Unique IPs: **{df['ip'].nunique()}**\n")
    f.write(f"- Time range (UTC): **{df['ts'].min()} → {df['ts'].max()}**\n\n")

    f.write("## Top Classifications\n")
    for k, v in top_classes.items():
        f.write(f"- {k}: {v}\n")

    f.write("\n## Top Paths\n")
    for k, v in top_paths.items():
        f.write(f"- {k}: {v}\n")

    f.write("\n## Top IPs\n")
    for k, v in top_ips.items():
        f.write(f"- {k}: {v}\n")

print(f"Saved: {summary_path}")
print(f"Saved: {os.path.join(OUT_DIR, 'hits_over_time.png')}")
