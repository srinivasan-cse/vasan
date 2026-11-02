# ZTACS – Zero-Trust Access Console with Local PC File Manager

Working prototype with password + OTP (MFA), continuous trust scoring, dynamic thresholds, graded account
restriction, session monitoring with forced logout, a trust-gated local PC folder manager, optional
account-isolated app-server storage, an admin console, and a tamper-evident audit log.

## Run
```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python backend/app.py                                  # http://localhost:5000
```
Admin login: `admin` / `Admin@12345` (change with `ZTACS_ADMIN_PW` before first run).
OTPs are printed in the server console and `backend/sms_outbox.log`. In demo mode (default) the UI also shows
a virtual phone notification. Set `ZTACS_DEMO=0` in production and plug a real SMS gateway into `send_sms()`.

## Try it
1. Create an account (trust starts at 0.10), sign in, enter the OTP.
2. Resources: request `dashboard:view` and `storage:read` a few times – trust rises.
3. Request `storage:delete` or press **Run attacker simulation** – requests are denied, the account goes
   NORMAL → BLOCKED → RESTRICTED (forced logout) → LOCKED.
4. Sign in as admin: unlock the account, review alerts, edit thresholds, verify the audit hash chain.
5. Leave a session idle (default 3 min) or close the tab (heartbeat lost after 45 s) – it is revoked automatically.
6. Open **PC files**, choose a folder on this device, and manage its files under the trust-policy checks.

## Local PC file manager
Open **PC files** and choose **Choose device folder** to grant the browser access to a folder you select on
this PC. The manager supports navigating subfolders, viewing files, editing text files up to 1 MB, and
deleting files. Viewing/listing requires `storage:read`, editing requires `storage:write`, and deleting
requires `storage:delete`. The active policy thresholds determine the displayed Low, Medium, and High
levels; the server checks each action. Editing and deleting also require the browser's read/write permission
for the selected folder. Folder access uses the browser File System Access API (typically available in
Chromium browsers on localhost or HTTPS). The app does not scan your PC or access folders until you select
one and grant permission. Local folder data stays on this PC and is not uploaded by the manager.

## Optional app-server file storage
The **Optional: files uploaded to the ZTAC app server** section lets you separately upload individual
files into account-isolated storage under `backend/user_files/<account-id>` by default, with metadata in
SQLite. This feature is separate from the local PC file manager. Set `ZTACS_FILES_DIR` to choose another
persistent server directory. Uploads are limited to 25 MB; read, write, and delete operations use the
`storage:read`, `storage:write`, and `storage:delete` trust policies. Back up the storage directory and
database together.

Trust is reassessed for each access request and file operation. A score below 0.20 automatically blocks
sensitive resources; below 0.10 it restricts the account and ends active sessions. A score recovering to
0.30 clears restrictions created specifically by low trust. The existing heartbeat and server sweeper
continue to enforce idle, maximum-duration, and lost-session timeouts.

## Layout
```
backend/app.py       REST API (Flask) + serves the frontend
backend/engines.py   MFA, trust model, Q-learning rule engine, restriction, session monitor, audit chain
backend/db.py        SQLite schema (portable to MySQL)
backend/user_files/  Account-isolated managed file data (created at runtime)
frontend/            index.html, css/style.css, js/app.js (no build step)
```
Config via env vars: `ZTACS_IDLE_TIMEOUT`, `ZTACS_HEARTBEAT_TIMEOUT`, `ZTACS_MAX_SESSION`, `ZTACS_OTP_VALID`,
`ZTACS_BLOCK_SECONDS`, `ZTACS_RESTRICT_SECONDS`, `ZTACS_SECRET`, `PORT`.

## SRS mapping and honest limits
| SRS item | Implementation |
|---|---|
| MFA (password + time-bound OTP) | PyOTP HOTP code, 2 min expiry, single use, 3 attempts |
| Trust init T = 0.1 | on registration |
| LSTM trust assessment | **Stand-in**: per-user transition model + time-slot + rate features in `engines.anomaly()`. Replace with your trained CLSTM/Bi-LSTM (PyTorch) behind the same function. |
| DQN dynamic rules | **Stand-in**: tabular Q-learning agent, trained offline at start-up on a synthetic replay buffer (C-1); live experiences are stored in `replay` for offline retraining |
| Graded restriction | NORMAL / BLOCKED / RESTRICTED / LOCKED, alerts to admin |
| Session monitoring | idle, max duration, heartbeat-loss, suspicious pattern; sweeper thread every 5 s |
| Fail-safe (C-4) | any token/session/server error denies access |
| Audit | append-only SHA-256 hash chain, verifiable from the admin console |
| Not included | real SMS gateway, OpenStack Nova policy.json enforcement, TLS (run behind a TLS proxy, A-2) |
