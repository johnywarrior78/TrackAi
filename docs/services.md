# Keep TrackAi running on Kali / Linux

This is a setup guide. Your dashboard and database stay on your computer.

Install TrackAi and configure PostgreSQL in the project `.env` first. Run `./scripts/aivi initialize` successfully before enabling these services. Keep the repository at a permanent path; do not move it after installing the services. The commands below use `~/Desktop/TrackAi`; change the first command if yours is elsewhere.

## Install both services

Run these commands in the same terminal session. Each `sudo tee` command includes the entire block through the final `EOF`. The variables expand to your actual username and absolute project path. Existing units with these names are replaced.

```bash
cd ~/Desktop/TrackAi
TRACKAI_DIR="$(pwd -P)"
TRACKAI_USER="$(id -un)"

sudo tee /etc/systemd/system/trackai.service >/dev/null <<EOF
[Unit]
Description=TrackAi daily vulnerability collection
Wants=network-online.target
After=network-online.target postgresql.service

[Service]
Type=simple
User=${TRACKAI_USER}
WorkingDirectory=${TRACKAI_DIR}
ExecStart="${TRACKAI_DIR}/scripts/aivi" scheduler
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/trackai-dashboard.service >/dev/null <<EOF
[Unit]
Description=TrackAi local dashboard
Wants=network-online.target
After=network-online.target postgresql.service

[Service]
Type=simple
User=${TRACKAI_USER}
WorkingDirectory=${TRACKAI_DIR}
ExecStart="${TRACKAI_DIR}/scripts/aivi" dashboard
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

sudo systemd-analyze verify /etc/systemd/system/trackai.service /etc/systemd/system/trackai-dashboard.service
sudo systemctl daemon-reload
sudo systemctl enable --now trackai.service trackai-dashboard.service
sudo systemctl status trackai.service trackai-dashboard.service --no-pager -l
```

## Open the dashboard

Open http://127.0.0.1:8501 in your browser, or bookmark it. The dashboard starts at boot and stays available after you close the terminal. It binds to loopback; this guide does not publish your dashboard to the internet.

The collector runs once daily at 07:00 UTC by default. Adjust `SCHEDULE_HOUR` and `SCHEDULE_MINUTE` in `.env`, then restart `trackai.service`. The machine must be on at the scheduled time; the scheduler does not replay a missed daily run automatically. Initialization may delay the dashboard's first startup while history is collected.

## Logs and maintenance

```bash
sudo journalctl -u trackai.service -n 100 --no-pager
sudo journalctl -u trackai-dashboard.service -n 100 --no-pager
sudo systemctl restart trackai.service trackai-dashboard.service
```

After updating TrackAi, restart both services. To stop and disable automatic startup:

```bash
sudo systemctl disable --now trackai.service trackai-dashboard.service
```

## Troubleshooting

If systemd reports a bad unit setting, use `systemd-analyze verify` above and inspect `systemctl status --no-pager -l`. `WorkingDirectory=` must contain the actual absolute path without literal quote characters. Do not paste shell expressions such as `$HOME` into the unit file itself. The commands above expand the path before writing it.

If a service restarts repeatedly, inspect its journal for database connection, dependency or initial collection errors. Confirm `.env` belongs to the service user and PostgreSQL is running. Stop any manually started dashboard or scheduler before enabling these units to avoid port or scheduler-lock conflicts.

For remote access use an SSH tunnel: `ssh -L 8501:127.0.0.1:8501 USER@HOST`, then open the same local URL. Do not expose port 8501 publicly without authentication and TLS.
