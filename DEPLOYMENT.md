# Deployment on DigitalOcean

Step-by-step guide to running the honeypot on a public VPS and collecting
real attack data.

---

## 1. Create a Droplet

- Image: **Ubuntu 24.04 LTS**
- Plan: **Basic, $4/month** (1 vCPU, 512 MB RAM — sufficient)
- Datacenter region: any
- Authentication: **SSH Key** (recommended over password)

After creation, note the Droplet's public IP address.

---

## 2. Connect to the VPS

```bash
ssh root@YOUR_VPS_IP
```

---

## 3. Initial setup

```bash
apt update && apt upgrade -y
apt install python3 python3-pip git -y
```

---

## 4. Move the real SSH port — do this before anything else

The honeypot will listen on port 22. You need to move the real SSH daemon
to a different port so you do not lock yourself out.

```bash
vim /etc/ssh/sshd_config
# change the line:  Port 22  →  Port 2222

systemctl restart sshd
```

**Before closing the current session**, open a new terminal and verify
the new port works:

```bash
ssh -p 2222 root@YOUR_VPS_IP
```

Only close the old session after confirming the new one connects.

---

## 5. Clone the project

```bash
cd /opt
git clone https://github.com/Ovidiu-sys/honeypot.git
cd honeypot
pip install -r requirements.txt
```

---

## 6. Download the GeoLite2 database

Register for free at MaxMind:
https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

Download `GeoLite2-City.mmdb` and copy it to the VPS:

```bash
# run this from your local machine, not the VPS
scp -P 2222 GeoLite2-City.mmdb root@YOUR_VPS_IP:/opt/honeypot/data/
```

---

## 7. Configure the firewall

```bash
ufw allow 2222/tcp   # your real SSH port
ufw allow 22/tcp     # honeypot SSH
ufw allow 80/tcp     # honeypot HTTP
ufw enable
```

---

## 8. Run as a systemd service

This ensures the honeypot starts automatically on reboot and runs in the
background without an active terminal session.

```bash
cat > /etc/systemd/system/honeypot.service << EOF
[Unit]
Description=SSH + HTTP Honeypot
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/honeypot
ExecStart=/usr/bin/python3 /opt/honeypot/main.py --no-print
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable honeypot
systemctl start honeypot
```

Verify it is running:

```bash
systemctl status honeypot
```

---

## 9. Monitor live events

```bash
# watch incoming events in real time
tail -f /opt/honeypot/data/honeypot.log

# or via systemd journal
journalctl -u honeypot -f
```

---

## 10. Query the data (after a few weeks)

```bash
cd /opt/honeypot

# top 10 passwords tried
python3 -c "
from core.db import Database
db = Database()
rows = db.query('''
    SELECT password, COUNT(*) as cnt
    FROM ssh_attempts
    GROUP BY password
    ORDER BY cnt DESC
    LIMIT 10
''')
for r in rows: print(r)
"

# top 10 countries of origin
python3 -c "
from core.db import Database
db = Database()
rows = db.query('''
    SELECT country, COUNT(*) as cnt
    FROM ssh_attempts
    WHERE country IS NOT NULL
    GROUP BY country
    ORDER BY cnt DESC
    LIMIT 10
''')
for r in rows: print(r)
"

# most requested HTTP paths
python3 -c "
from core.db import Database
db = Database()
rows = db.query('''
    SELECT path, COUNT(*) as cnt
    FROM http_requests
    GROUP BY path
    ORDER BY cnt DESC
    LIMIT 20
''')
for r in rows: print(r)
"
```

---

## 11. Stop and clean up

```bash
systemctl stop honeypot
systemctl disable honeypot

# copy the database to your local machine before deleting the Droplet
scp -P 2222 root@YOUR_VPS_IP:/opt/honeypot/data/honeypot.db ./
```

Then delete the Droplet from the DigitalOcean dashboard — billing stops
immediately.
