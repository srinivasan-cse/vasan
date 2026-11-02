"""ZTACS engines: MFA, Trust Assessment, Dynamic Rules, Restriction, Session Monitor, Audit.

Honest note on the ML parts
---------------------------
* TrustModel  : a lightweight, explainable next-action anomaly model (per-user Markov transitions blended
                with a sensitivity prior + time-slot + request-rate features). It exposes the same interface
                an LSTM would (score(prev, next, ctx) -> anomaly in [0,1]) so the CLSTM/Bi-LSTM from the
                base paper can be dropped in by replacing `anomaly()`.
* RuleEngine  : a tabular Q-learning agent (a DQN with a lookup table instead of a neural net), trained OFFLINE
                at start-up on a synthetic replay buffer (constraint C-1) and used greedily online. Live
                experiences are stored in the `replay` table for later offline retraining.
"""
import os, time, json, hashlib, hmac, math, random, secrets, threading
import pyotp
from werkzeug.security import generate_password_hash, check_password_hash
import db

def _f(k, d): return float(os.environ.get(k, d))
CFG = dict(
    OTP_VALID=_f("ZTACS_OTP_VALID", 120),          # seconds an OTP stays valid
    IDLE_TIMEOUT=_f("ZTACS_IDLE_TIMEOUT", 180),    # no real activity -> forced logout
    MAX_SESSION=_f("ZTACS_MAX_SESSION", 3600),
    HEARTBEAT_TIMEOUT=_f("ZTACS_HEARTBEAT_TIMEOUT", 45),  # session-lifecycle signal lost -> revoke
    BLOCK_SECONDS=_f("ZTACS_BLOCK_SECONDS", 120),
    RESTRICT_SECONDS=_f("ZTACS_RESTRICT_SECONDS", 300),
    INIT_TRUST=0.1,
    DEMO_MODE=os.environ.get("ZTACS_DEMO", "1") == "1",   # DEMO: return OTP in API so the UI can show a virtual phone
)
now = time.time
_lock = threading.RLock()

# ------------------------------------------------------------------ audit / alerts
def audit(event, user=None, detail=None):
    with _lock:
        last = db.run("SELECT hash FROM audit ORDER BY id DESC LIMIT 1", fetch="one")
        prev = last["hash"] if last else "0" * 64
        ts = now(); d = json.dumps(detail or {}, sort_keys=True)
        h = hashlib.sha256(f"{prev}|{ts!r}|{event}|{user}|{d}".encode()).hexdigest()
        db.run("INSERT INTO audit(ts,event,user,detail,prev_hash,hash) VALUES(?,?,?,?,?,?)", (ts, event, user, d, prev, h))

def verify_audit():
    prev = "0" * 64
    for r in db.run("SELECT * FROM audit ORDER BY id", fetch="all"):
        h = hashlib.sha256(f"{prev}|{r['ts']!r}|{r['event']}|{r['user']}|{r['detail']}".encode()).hexdigest()
        if r["prev_hash"] != prev or r["hash"] != h:
            return False, r["id"]
        prev = h
    return True, None

def alert(user, severity, message):
    db.run("INSERT INTO alerts(ts,user_id,username,severity,message) VALUES(?,?,?,?,?)",
           (now(), user["id"], user["username"], severity, message))

# ------------------------------------------------------------------ users / MFA
def get_user(uid=None, username=None):
    if uid is not None:
        u = db.run("SELECT * FROM users WHERE id=?", (uid,), "one")
    else:
        u = db.run("SELECT * FROM users WHERE username=? COLLATE NOCASE", (username,), "one")
    return refresh_state(u) if u else None

def create_user(username, password, mobile, role="user"):
    uid = db.run("INSERT INTO users(username,password_hash,mobile,role,trust,otp_secret,created) VALUES(?,?,?,?,?,?,?)",
                 (username, generate_password_hash(password), mobile, role, CFG["INIT_TRUST"], pyotp.random_base32(), now()))
    audit("REGISTER", username, {"role": role, "initial_trust": CFG["INIT_TRUST"]})
    return uid

def mask(m): return m[:3] + "*" * max(0, len(m) - 5) + m[-2:]

def send_sms(mobile, text):
    """Replace with Twilio / AWS SNS / Fast2SMS. Default: console + outbox file."""
    line = f"[SMS -> {mobile}] {text}"
    print(line, flush=True)
    with open(os.path.join(os.path.dirname(__file__), "sms_outbox.log"), "a") as fh:
        fh.write(f"{time.strftime('%F %T')} {line}\n")

def issue_otp(user):
    counter = user["otp_counter"] + 1
    code = pyotp.HOTP(user["otp_secret"], digits=6).at(counter)
    db.run("UPDATE users SET otp_counter=?, otp_expires=?, otp_attempts=0 WHERE id=?",
           (counter, now() + CFG["OTP_VALID"], user["id"]))
    send_sms(user["mobile"], f"Your ZTACS verification code is {code}. It expires in {int(CFG['OTP_VALID'])//60} min.")
    audit("OTP_ISSUED", user["username"], {"mobile": mask(user["mobile"])})
    return code

def check_otp(user, code):
    """One-time, time-bound, max 3 attempts."""
    u = db.run("SELECT * FROM users WHERE id=?", (user["id"],), "one")
    if u["otp_expires"] < now():
        return False, "Code expired. Request a new one."
    if u["otp_attempts"] >= 3:
        return False, "Too many wrong codes. Request a new one."
    expected = pyotp.HOTP(u["otp_secret"], digits=6).at(u["otp_counter"])
    if hmac.compare_digest(expected, str(code)):
        db.run("UPDATE users SET otp_expires=0, otp_attempts=0, failed_logins=0 WHERE id=?", (u["id"],))
        return True, ""
    db.run("UPDATE users SET otp_attempts=otp_attempts+1 WHERE id=?", (u["id"],))
    reduced = max(0.0, float(u["trust"]) - 0.08)
    db.run("UPDATE users SET trust=? WHERE id=?", (reduced, u["id"]))
    return False, "Incorrect code."

def password_failed(user):
    n = user["failed_logins"] + 1
    new_trust = max(0.0, float(user["trust"]) - 0.10)
    db.run("UPDATE users SET failed_logins=?, trust=? WHERE id=?", (n, new_trust, user["id"]))
    audit("LOGIN_FAILED", user["username"], {"count": n, "trust_after": new_trust})
    if n >= 5:
        set_state(user, "RESTRICTED", "5 failed sign-in attempts", CFG["RESTRICT_SECONDS"])
        db.run("UPDATE users SET failed_logins=0 WHERE id=?", (user["id"],))

# ------------------------------------------------------------------ restriction module
def set_state(user, new, reason, seconds=0):
    until = now() + seconds if seconds else 0
    db.run("UPDATE users SET state=?, state_until=?, state_reason=?, consecutive_denials=0 WHERE id=?",
           (new, until, reason, user["id"]))
    audit("STATE_" + new, user["username"], {"reason": reason, "seconds": seconds})
    if new != "NORMAL":
        sev = {"BLOCKED": "medium", "RESTRICTED": "high", "LOCKED": "critical"}[new]
        alert(user, sev, f"Account {new}: {reason}")
    if new in ("RESTRICTED", "LOCKED"):
        terminate_user_sessions(user["id"], f"account {new.lower()}")

def refresh_state(u):
    if u["state"] in ("BLOCKED", "RESTRICTED") and u["state_until"] and u["state_until"] < now():
        db.run("UPDATE users SET state='NORMAL', state_until=0, state_reason='', consecutive_denials=0 WHERE id=?", (u["id"],))
        audit("STATE_NORMAL", u["username"], {"reason": "restriction expired"})
        u = db.run("SELECT * FROM users WHERE id=?", (u["id"],), "one")
    return u

def unlock(user, by):
    db.run("UPDATE users SET state='NORMAL', state_until=0, state_reason='', consecutive_denials=0, failed_logins=0, trust=MAX(trust,0.3) WHERE id=?", (user["id"],))
    audit("ADMIN_UNLOCK", by, {"target": user["username"]})

def escalate(user, denials):
    if denials >= 8 and user["state"] != "LOCKED":
        set_state(user, "LOCKED", "repeated denied requests (8)")
    elif denials >= 5 and user["state"] not in ("RESTRICTED", "LOCKED"):
        set_state(user, "RESTRICTED", "repeated denied requests (5)", CFG["RESTRICT_SECONDS"])
    elif denials >= 3 and user["state"] == "NORMAL":
        set_state(user, "BLOCKED", "repeated denied requests (3): sensitive resources blocked", CFG["BLOCK_SECONDS"])

# ------------------------------------------------------------------ session monitor
def create_session(user, ip, ua):
    sid = secrets.token_hex(8); t = now()
    db.run("INSERT INTO sessions(id,user_id,created,last_activity,last_heartbeat,ip,ua) VALUES(?,?,?,?,?,?,?)",
           (sid, user["id"], t, t, t, ip, (ua or "")[:200]))
    db.run("UPDATE users SET last_login=? WHERE id=?", (t, user["id"]))
    audit("SESSION_START", user["username"], {"sid": sid, "ip": ip})
    return sid

def terminate_session(sid, reason, by="system"):
    s = db.run("SELECT * FROM sessions WHERE id=?", (sid,), "one")
    if not s or s["status"] != "ACTIVE":
        return
    db.run("UPDATE sessions SET status='TERMINATED', reason=?, ended=? WHERE id=?", (reason, now(), sid))
    u = db.run("SELECT username FROM users WHERE id=?", (s["user_id"],), "one")
    audit("SESSION_END", u["username"] if u else None, {"sid": sid, "reason": reason, "by": by})

def terminate_user_sessions(uid, reason, by="system"):
    for s in db.run("SELECT id FROM sessions WHERE user_id=? AND status='ACTIVE'", (uid,), "all"):
        terminate_session(s["id"], reason, by)

def validate_session(sid):
    s = db.run("SELECT * FROM sessions WHERE id=?", (sid,), "one")
    if not s: return False, "unknown session"
    if s["status"] != "ACTIVE": return False, s["reason"] or "session ended"
    t = now(); why = None
    if t - s["last_activity"] > CFG["IDLE_TIMEOUT"]: why = "idle timeout"
    elif t - s["created"] > CFG["MAX_SESSION"]: why = "maximum session duration reached"
    elif t - s["last_heartbeat"] > CFG["HEARTBEAT_TIMEOUT"]: why = "session channel lost (heartbeat timeout)"
    if why:
        terminate_session(sid, why)
        u = db.run("SELECT * FROM users WHERE id=?", (s["user_id"],), "one")
        if u: alert(u, "low", f"Session {sid[:6]} closed automatically: {why}")
        return False, why
    return True, ""

def sweep():
    for s in db.run("SELECT id FROM sessions WHERE status='ACTIVE'", fetch="all"):
        validate_session(s["id"])

def session_timers(sid):
    s = db.run("SELECT * FROM sessions WHERE id=?", (sid,), "one"); t = now()
    return dict(idle_remaining=max(0, int(CFG["IDLE_TIMEOUT"] - (t - s["last_activity"]))),
                max_remaining=max(0, int(CFG["MAX_SESSION"] - (t - s["created"]))),
                idle_total=int(CFG["IDLE_TIMEOUT"]), started=s["created"])

# ------------------------------------------------------------------ policies
POLICIES = [  # permission, threshold, sensitivity, role, title, description
    ("dashboard:view",  0.05, 0.05, "any",   "Console overview",    "View your tenant overview"),
    ("storage:read",    0.30, 0.20, "any",   "Read object storage", "Download files from your buckets"),
    ("storage:write",   0.50, 0.45, "any",   "Write object storage","Upload and overwrite files"),
    ("compute:start",   0.75, 0.60, "any",   "Start instance",      "Boot a virtual machine (compute:start)"),
    ("compute:stop",    0.60, 0.55, "any",   "Stop instance",       "Shut down a running virtual machine"),
    ("storage:delete",  0.80, 0.85, "any",   "Delete bucket",       "Permanently delete a storage bucket"),
    ("network:admin",   0.85, 0.95, "admin", "Edit firewall rules", "Change tenant-wide network policy"),
    ("identity:list",   0.70, 0.70, "admin", "List all users",      "See every account in the tenancy"),
]

def seed_policies():
    for p in POLICIES:
        db.run("INSERT OR IGNORE INTO policies(permission,base_threshold,threshold,sens,role,title,description) VALUES(?,?,?,?,?,?,?)",
               (p[0], p[1], p[1], p[2], p[3], p[4], p[5]))

def policies(): return db.run("SELECT * FROM policies ORDER BY sens", fetch="all")
def policy(perm): return db.run("SELECT * FROM policies WHERE permission=?", (perm,), "one")

# ------------------------------------------------------------------ trust assessment
def anomaly(user_id, prev, nxt, ts):
    pols = {p["permission"]: p for p in policies()}
    w = {k: 1 / (1 + 4 * p["sens"]) for k, p in pols.items()}
    for k in w:                                   # same-service actions are naturally sequential
        if prev and k.split(":")[0] == prev.split(":")[0]: w[k] *= 1.5
    z = sum(w.values()); prior = {k: v / z for k, v in w.items()}
    rows = db.run("SELECT action, COUNT(*) c FROM logs WHERE user_id=? AND prev_action=? AND allowed=1 GROUP BY action",
                  (user_id, prev or "login"), "all")
    cnt = {r["action"]: r["c"] for r in rows}; tot = sum(cnt.values()); K = 5
    p = {k: (cnt.get(k, 0) + K * prior[k]) / (tot + K) for k in prior}
    a = 1 - p[nxt] / max(p.values())
    hour = time.localtime(ts).tm_hour
    if 0 <= hour < 5: a += 0.15                   # unusual time slot (3-hour slot feature, simplified)
    burst = db.run("SELECT COUNT(*) c FROM logs WHERE user_id=? AND ts>?", (user_id, ts - 10), "one")["c"]
    if burst >= 8: a += 0.30                      # request-rate feature
    return round(max(0.0, min(1.0, a)), 3)

# ------------------------------------------------------------------ dynamic rule engine (offline-trained Q agent)
DELTAS = [-0.05, 0.0, 0.05]
Q = {}
def _state(thr, deny_rate):
    return f"{min(4, int(thr / 0.2))}:{0 if deny_rate < 0.2 else 1 if deny_rate < 0.5 else 2}"

def _qrow(s): return Q.setdefault(s, [0.0, 0.0, 0.0])

def pretrain(steps=4000, seed=7):
    """Offline training on a synthetic replay buffer: 90% benign users (trust~N(.62,.2)), 10% malicious (N(.25,.15))."""
    rnd = random.Random(seed); Q.clear()
    for _ in range(steps):
        thr = rnd.uniform(0.1, 0.95); dr = rnd.random() * 0.8
        s = _state(thr, dr); eps = 0.3
        a = rnd.randrange(3) if rnd.random() < eps else max(range(3), key=lambda i: _qrow(s)[i])
        thr2 = min(0.95, max(0.05, thr + DELTAS[a])); r = 0; denies = 0
        for _ in range(20):
            mal = rnd.random() < 0.10
            t = rnd.gauss(0.25, 0.15) if mal else rnd.gauss(0.62, 0.2)
            allow = t >= thr2; denies += (not allow)
            r += (1 if (not allow and mal) else -2 if (allow and mal) else 1 if allow else -1) / 20
        s2 = _state(thr2, denies / 20)
        row = _qrow(s); row[a] += 0.1 * (r + 0.9 * max(_qrow(s2)) - row[a])

def feedback(perm, allowed, anom):
    """Called after every decision; every 5th decision on a permission the agent may move the threshold."""
    n = db.run("SELECT COUNT(*) c FROM logs WHERE action=?", (perm,), "one")["c"]
    if n == 0 or n % 5: return
    p = policy(perm)
    rec = db.run("SELECT allowed, anomaly FROM logs WHERE action=? ORDER BY id DESC LIMIT 10", (perm,), "all")
    dr = sum(1 for r in rec if not r["allowed"]) / len(rec)
    s = _state(p["threshold"], dr)
    row = _qrow(s); a = random.randrange(3) if random.random() < 0.05 else max(range(3), key=lambda i: row[i])
    lo, hi = max(0.05, p["base_threshold"] - 0.15), min(0.95, p["base_threshold"] + 0.15)
    new = round(min(hi, max(lo, p["threshold"] + DELTAS[a])), 3)
    reward = sum((1 if (not r["allowed"] and r["anomaly"] >= .5) else -2 if (r["allowed"] and r["anomaly"] >= .5)
                  else 1 if r["allowed"] else -1) for r in rec) / len(rec)
    db.run("INSERT INTO replay(ts,permission,state,action,reward,next_state) VALUES(?,?,?,?,?,?)",
           (now(), perm, s, a, reward, _state(new, dr)))
    if new != p["threshold"]:
        db.run("UPDATE policies SET threshold=? WHERE permission=?", (new, perm))
        audit("THRESHOLD_UPDATE", "dqn-agent", {"permission": perm, "from": p["threshold"], "to": new, "state": s})

# ------------------------------------------------------------------ policy decision point
def access(user, sid, perm):
    pol = policy(perm)
    if not pol: return None
    user = refresh_state(user)
    last = db.run("SELECT action FROM logs WHERE user_id=? AND session_id=? ORDER BY id DESC LIMIT 1", (user["id"], sid), "one")
    prev = last["action"] if last else "login"
    T = user["trust"]; st = user["state"]; thr = pol["threshold"]
    if st == "LOCKED": allow, why = False, "Account locked. Ask an administrator to unlock it."
    elif st == "RESTRICTED" and pol["sens"] > 0.2: allow, why = False, "Account restricted: only low-risk actions are allowed."
    elif st == "BLOCKED" and pol["sens"] >= 0.5: allow, why = False, "Sensitive resources are blocked for this account."
    elif pol["role"] == "admin" and user["role"] != "admin": allow, why = False, "Administrator role required."
    elif T < thr: allow, why = False, f"Trust {T:.2f} is below the required {thr:.2f}."
    else: allow, why = True, "Access granted."
    ts = now(); an = anomaly(user["id"], prev, perm, ts)
    s = 1 - an
    newT = round(min(1, max(0, 0.8 * T + 0.2 * s)) if allow else min(1, max(0, 0.8 * T + 0.2 * (s * 0.5))), 4)
    db.run("INSERT INTO logs(ts,user_id,session_id,action,prev_action,allowed,reason,anomaly,trust_before,trust_after,threshold) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
           (ts, user["id"], sid, perm, prev, int(allow), why, an, T, newT, thr))
    db.run("UPDATE users SET trust=? WHERE id=?", (newT, user["id"]))
    den = max(0, user["consecutive_denials"] - 1) if allow else user["consecutive_denials"] + 1
    db.run("UPDATE users SET consecutive_denials=? WHERE id=?", (den, user["id"]))
    audit("ACCESS_" + ("ALLOW" if allow else "DENY"), user["username"], {"perm": perm, "trust": newT, "threshold": thr, "anomaly": an})
    if not allow: escalate(get_user(user["id"]), den)
    else: db.run("UPDATE sessions SET last_activity=? WHERE id=?", (ts, sid))
    assessed = get_user(user["id"])
    if assessed and assessed["state"] != "LOCKED":
        if newT < 0.10 and assessed["state"] != "RESTRICTED":
            set_state(assessed, "RESTRICTED", f"Low trust score ({newT:.2f})", CFG["RESTRICT_SECONDS"])
        elif newT < 0.20 and assessed["state"] == "NORMAL":
            set_state(assessed, "BLOCKED", f"Low trust score ({newT:.2f})", CFG["BLOCK_SECONDS"])
        elif newT >= 0.30 and assessed["state"] in ("BLOCKED", "RESTRICTED") and assessed["state_reason"].startswith("Low trust score"):
            set_state(assessed, "NORMAL", "Trust score recovered")
    feedback(perm, allow, an)
    # suspicious-session rule: 4 of last 5 actions highly anomalous
    last5 = db.run("SELECT anomaly FROM logs WHERE session_id=? ORDER BY id DESC LIMIT 5", (sid,), "all")
    if len(last5) == 5 and sum(1 for r in last5 if r["anomaly"] > 0.7) >= 4:
        terminate_session(sid, "suspicious behaviour detected"); alert(user, "high", "Session closed: suspicious behaviour pattern")
    return dict(allowed=allow, reason=why, trust=newT, trust_before=T, threshold=thr, anomaly=an, permission=perm)

def seed_admin():
    if not db.run("SELECT 1 x FROM users WHERE username='admin'", fetch="one"):
        create_user("admin", os.environ.get("ZTACS_ADMIN_PW", "Admin@12345"), "+919999900000", "admin")
        db.run("UPDATE users SET trust=0.9 WHERE username='admin'")
