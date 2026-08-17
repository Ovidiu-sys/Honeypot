"""
Generates png graphics from hoenypot_final.db database
output: graphs/ folder with all the png graphs
"""

import sqlite3
import os
from collections import Counter
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import pandas as pd

DB_PATH = os.path.expanduser("~/honeypot_final.db")
OUT_DIR = os.path.expanduser("~/honeypot_graphs")
os.makedirs(OUT_DIR, exist_ok=True)

conn = sqlite3.connect(DB_PATH)

COLORS = {
    "blue": "#2E75B6",
    "dark_blue": "#1F4E79",
    "red": "#C0392B",
    "orange": "#E67E22",
    "green": "#27AE60",
    "purple": "#8E44AD",
    "gray": "#7F8C8D",
    "bg": "#0d1117",
    "grid": "#21262d",
    "text": "#c9d1d9",
}

LAYOUT = dict(
    paper_bgcolor=COLORS["bg"],
    plot_bgcolor=COLORS["bg"],
    font=dict(color=COLORS["text"], family="Calibri", size=13),
)

DEFAULT_MARGIN = dict(l=60, r=40, t=70, b=60)


def save(fig, name, margin=None):
    if margin:
        fig.update_layout(margin=margin)
    else:
        fig.update_layout(margin=DEFAULT_MARGIN)
    path = os.path.join(OUT_DIR, name)
    fig.write_image(path, width=1000, height=550, scale=2)
    print(f"    Saved: {path}")


print("Generating graphs")

# 3. SSH + HTTP combined per day
ssh_rows = conn.execute("""
    SELECT DATE(timestamp) as day, COUNT(*) as cnt
    FROM ssh_attempts GROUP BY day ORDER BY day
""").fetchall()
http_rows = conn.execute("""
    SELECT DATE(timestamp) as day, COUNT(*) as cnt
    FROM http_requests GROUP BY day ORDER BY day
""").fetchall()

df_ssh = pd.DataFrame(ssh_rows, columns=["day", "ssh"])
df_http = pd.DataFrame(http_rows, columns=["day", "http"])
df = pd.merge(df_ssh, df_http, on="day", how="outer").fillna(0)

fig = go.Figure()
fig.add_trace(go.Bar(x=df["day"], y=df["ssh"], name="SSH", marker_color=COLORS["blue"]))
fig.add_trace(go.Bar(x=df["day"], y=df["http"], name="HTTP", marker_color=COLORS["orange"]))
fig.update_layout(**LAYOUT,
    title=dict(text="SSH vs HTTP Activity per Day", font=dict(size=18, color=COLORS["text"])),
    barmode="group",
    xaxis=dict(gridcolor=COLORS["grid"], title="Date"),
    yaxis=dict(gridcolor=COLORS["grid"], title="Events"),
    legend=dict(bgcolor=COLORS["bg"]),
)
save(fig, "3_ssh_vs_http_per_day.png")

# 4. Top 15 countries SSH 
rows = conn.execute("""
    SELECT country, COUNT(*) as cnt FROM ssh_attempts
    WHERE country IS NOT NULL
    GROUP BY country ORDER BY cnt DESC LIMIT 15
""").fetchall()
df = pd.DataFrame(rows, columns=["country", "cnt"])

fig = go.Figure(go.Bar(
    x=df["cnt"], y=df["country"],
    orientation="h",
    marker_color=COLORS["blue"],
    text=df["cnt"], textposition="outside",
))
fig.update_layout(**LAYOUT,
    title=dict(text="Top 15 Countries — SSH Attempts", font=dict(size=18, color=COLORS["text"])),
    xaxis=dict(gridcolor=COLORS["grid"], title="Attempts"),
    yaxis=dict(gridcolor=COLORS["grid"], autorange="reversed"),
    height=600,
)
save(fig, "4_top_countries_ssh.png")

# 8. CVEs detected 
cves = [
    ("phpunit",     "CVE-2017-9841\nPHPUnit RCE"),
    ("ignition",    "CVE-2021-3129\nLaravel RCE"),
    ("actuator",    "CVE-2022-22947\nSpring Cloud RCE"),
    ("GponForm",    "CVE-2018-10561\nGPON Router RCE"),
    ("webLanguage", "CVE-2021-36260\nHikvision RCE"),
    (".env",        "Env File\nExposure"),
    ("wp-admin",    "WordPress\nAdmin"),
    ("graphql",     "GraphQL\nDiscovery"),
    ("shell.php",   "Web Shell\nAccess"),
]

labels, counts = [], []
for kw, label in cves:
    cnt = conn.execute(
        f"SELECT COUNT(*) FROM http_requests WHERE path LIKE '%{kw}%'"
    ).fetchone()[0]
    if cnt > 0:
        labels.append(label)
        counts.append(cnt)

fig = go.Figure(go.Bar(
    x=counts, y=labels,
    orientation="h",
    marker_color=COLORS["red"],
    text=counts, textposition="outside",
))
fig.update_layout(**LAYOUT,
    title=dict(text="Attack Vectors Detected (HTTP)", font=dict(size=18, color=COLORS["text"])),
    xaxis=dict(gridcolor=COLORS["grid"], title="Hits"),
    yaxis=dict(gridcolor=COLORS["grid"], autorange="reversed"),
    height=500,
)
save(fig, "8_cve_detections.png", margin=dict(l=200, r=80, t=70, b=60))

# 14. Unique ips SSH per day
rows = conn.execute("""
    SELECT DATE(timestamp) as day,
           COUNT(DISTINCT ip) as unique_ips,
           COUNT(*) as total
    FROM ssh_attempts GROUP BY day ORDER BY day
""").fetchall()
df = pd.DataFrame(rows, columns=["day", "unique_ips", "total"])

fig = make_subplots(specs=[[{"secondary_y": True}]])
fig.add_trace(go.Bar(x=df["day"], y=df["total"], name="Total attempts",
                     marker_color=COLORS["blue"], opacity=0.7), secondary_y=False)
fig.add_trace(go.Scatter(x=df["day"], y=df["unique_ips"], name="Unique IPs",
                         mode="lines+markers",
                         line=dict(color=COLORS["orange"], width=2),
                         marker=dict(size=7)), secondary_y=True)
fig.update_layout(**LAYOUT,
    title=dict(text="SSH: Total Attempts vs Unique IPs per Day", font=dict(size=18, color=COLORS["text"])),
    legend=dict(bgcolor=COLORS["bg"]),
)
fig.update_yaxes(title_text="Total Attempts", gridcolor=COLORS["grid"], secondary_y=False)
fig.update_yaxes(title_text="Unique IPs", gridcolor=COLORS["grid"], secondary_y=True)
save(fig, "14_ssh_unique_ips_vs_total.png")

conn.close()
print(f"\nDone {len(os.listdir(OUT_DIR))} graphics saved in {OUT_DIR}")
