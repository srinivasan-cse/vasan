"""ZTACS REST backend (Flask). Serves the frontend from ../frontend as well."""
import os, re, time, threading, secrets
from uuid import uuid4
from functools import wraps
import jwt
from flask import Flask, request, jsonify, g, send_file, send_from_directory
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash
import db, engines as E

HERE = os.path.dirname(os.path.abspath(__file__))
FILE_ROOT = os.environ.get("ZTACS_FILES_DIR", os.path.join(HERE, "user_files"))
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
app = Flask(__name__, static_folder=os.path.join(HERE, "..", "frontend"), static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

@app.errorhandler(413)
def upload_too_large(_):
    return err("Files must be 25 MB or smaller.", 413)

def _secret():
    if os.environ.get("ZTACS_SECRET"): return os.environ["ZTACS_SECRET"]
    p = os.path.join(HERE, ".secret")
    if not os.path.exists(p):
        with open(p, "w") as f: f.write(secrets.token_hex(32))
    return open(p).read().strip()
SECRET = _secret()

def tok(payload, ttl):
    return jwt.encode({**payload, "exp": int(time.time() + ttl)}, SECRET, algorithm="HS256")

def public(u):
    return {k: u[k] for k in ("id", "username", "role", "trust", "state", "state_until", "state_reason", "last_login")} | {"mobile": E.mask(u["mobile"])}

def err(msg, code=400, **kw): return jsonify(error=msg, **kw), code

def auth(admin=False):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            h = request.headers.get("Authorization", "")
            if not h.startswith("Bearer "): return err("Missing token", 401)
            try: p = jwt.decode(h[7:], SECRET, algorithms=["HS256"])
            except jwt.PyJWTError: return err("Invalid or expired token", 401, forced=True, reason="token expired")
            if p.get("purpose") != "session": return err("Wrong token type", 401)
            ok, reason = E.validate_session(p["sid"])      # fail-safe: any doubt -> deny (C-4)
            if not ok: return err("Session terminated", 401, forced=True, reason=reason)
            g.user = E.get_user(p["uid"]); g.sid = p["sid"]
            if not g.user: return err("Unknown user", 401)
            if admin and g.user["role"] != "admin": return err("Administrator only", 403)
            return f(*a, **k)
        return w
    return deco

# ---------------------------------------------------------------- public / MFA
@app.get("/")
def index(): return send_from_directory(app.static_folder, "index.html")

@app.post("/api/register")
def register():
    d = request.get_json(silent=True) or {}
    u, pw, m = (d.get("username") or "").strip(), d.get("password") or "", re.sub(r"[\s-]", "", d.get("mobile") or "")
    if not re.fullmatch(r"[A-Za-z0-9_]{3,24}", u): return err("Username must be 3-24 letters, numbers or underscores.")
    if len(pw) < 8 or not re.search(r"[A-Za-z]", pw) or not re.search(r"\d", pw): return err("Password needs 8+ characters with a letter and a number.")
    if not re.fullmatch(r"\+?\d{10,15}", m): return err("Enter a mobile number with 10-15 digits, e.g. +919876543210.")
    if E.get_user(username=u): return err("That username is taken.", 409)
    E.create_user(u, pw, m)
    return jsonify(ok=True, message="Account created. Sign in to continue.", initial_trust=E.CFG["INIT_TRUST"]), 201

@app.post("/api/login")
def login():
    d = request.get_json(silent=True) or {}
    user = E.get_user(username=(d.get("username") or "").strip())
    if not user or not check_password_hash(user["password_hash"], d.get("password") or ""):
        if user: E.password_failed(user)
        else: E.audit("LOGIN_UNKNOWN_USER", d.get("username"), {"ip": request.remote_addr})
        return err("Wrong username or password.", 401)
    if user["state"] == "LOCKED": return err("This account is locked. Contact an administrator.", 423)
    if user["state"] == "RESTRICTED" and user["state_until"] > time.time() and user["failed_logins"] == 0 and user["state_reason"].startswith("5 failed"):
        return err("Too many failed attempts. Try again later.", 423)
    code = E.issue_otp(user)
    out = dict(mfa_required=True, mfa_token=tok({"uid": user["id"], "purpose": "mfa"}, 300),
               mobile=E.mask(user["mobile"]), valid_seconds=int(E.CFG["OTP_VALID"]))
    if E.CFG["DEMO_MODE"]: out["demo_otp"] = code   # never enable in production
    return jsonify(out)

@app.post("/api/resend-otp")
def resend():
    d = request.get_json(silent=True) or {}
    try: p = jwt.decode(d.get("mfa_token", ""), SECRET, algorithms=["HS256"])
    except jwt.PyJWTError: return err("Sign-in step expired. Start again.", 401)
    user = E.get_user(p["uid"])
    if p.get("purpose") != "mfa" or not user: return err("Invalid request.", 401)
    code = E.issue_otp(user)
    return jsonify(ok=True, **({"demo_otp": code} if E.CFG["DEMO_MODE"] else {}))

@app.post("/api/verify-otp")
def verify():
    d = request.get_json(silent=True) or {}
    try: p = jwt.decode(d.get("mfa_token", ""), SECRET, algorithms=["HS256"])
    except jwt.PyJWTError: return err("Sign-in step expired. Start again.", 401)
    user = E.get_user(p["uid"])
    if p.get("purpose") != "mfa" or not user: return err("Invalid request.", 401)
    ok, why = E.check_otp(user, str(d.get("otp", "")).strip())
    if not ok:
        E.audit("OTP_FAILED", user["username"], {"why": why}); E.password_failed(user) if "Incorrect" in why else None
        return err(why, 401)
    sid = E.create_session(user, request.remote_addr, request.headers.get("User-Agent"))
    E.audit("LOGIN_SUCCESS", user["username"], {"sid": sid})
    return jsonify(token=tok({"uid": user["id"], "sid": sid, "purpose": "session"}, E.CFG["MAX_SESSION"]),
                   user=public(E.get_user(user["id"])), config=dict(idle=E.CFG["IDLE_TIMEOUT"], heartbeat=E.CFG["HEARTBEAT_TIMEOUT"]))

# ---------------------------------------------------------------- authenticated user
@app.get("/api/me")
@auth()
def me():
    logs = db.run("SELECT ts,action,allowed,reason,anomaly,trust_after,threshold FROM logs WHERE user_id=? ORDER BY id DESC LIMIT 40", (g.user["id"],), "all")
    return jsonify(user=public(g.user), policies=E.policies(), timers=E.session_timers(g.sid), logs=logs,
                   config=dict(idle=E.CFG["IDLE_TIMEOUT"], heartbeat=E.CFG["HEARTBEAT_TIMEOUT"]))

@app.post("/api/heartbeat")
@auth()
def heartbeat():
    db.run("UPDATE sessions SET last_heartbeat=? WHERE id=?", (time.time(), g.sid))
    return jsonify(ok=True, timers=E.session_timers(g.sid), user=public(g.user))

@app.post("/api/access")
@auth()
def access():
    perm = (request.get_json(silent=True) or {}).get("permission", "")
    r = E.access(g.user, g.sid, perm)
    if r is None: return err("Unknown permission", 404)
    ok, reason = E.validate_session(g.sid)
    r["session_ended"] = not ok; r["session_reason"] = reason
    r["user"] = public(E.get_user(g.user["id"]))
    return jsonify(r), (200 if r["allowed"] else 403)

@app.get("/api/my/sessions")
@auth()
def my_sessions():
    return jsonify(sessions=db.run("SELECT id,created,last_activity,status,reason,ended,ip FROM sessions WHERE user_id=? ORDER BY created DESC LIMIT 15", (g.user["id"],), "all"), current=g.sid)

@app.post("/api/logout")
@auth()
def logout():
    E.terminate_session(g.sid, "signed out", by=g.user["username"])
    return jsonify(ok=True)

@app.get("/api/files")
@auth()
def list_files():
    decision = E.access(g.user, g.sid, "storage:read")
    if not decision["allowed"]:
        return jsonify(**decision, files=[], user=public(E.get_user(g.user["id"]))), 403
    files = db.run(
        "SELECT id,filename,size,content_type,uploaded FROM files WHERE user_id=? ORDER BY uploaded DESC",
        (g.user["id"],), "all")
    return jsonify(**decision, files=files, user=public(E.get_user(g.user["id"])))

@app.post("/api/files")
@auth()
def upload_file():
    upload = request.files.get("file")
    if not upload or not upload.filename:
        return err("Choose a file to upload.")
    filename = secure_filename(upload.filename)
    if not filename:
        return err("The filename is not valid.")
    decision = E.access(g.user, g.sid, "storage:write")
    if not decision["allowed"]:
        return jsonify(**decision, user=public(E.get_user(g.user["id"]))), 403
    content = upload.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        return err("Files must be 25 MB or smaller.", 413)
    stored_name = uuid4().hex
    user_dir = os.path.join(FILE_ROOT, str(g.user["id"]))
    os.makedirs(user_dir, exist_ok=True)
    path = os.path.join(user_dir, stored_name)
    with open(path, "wb") as output:
        output.write(content)
    file_id = db.run(
        "INSERT INTO files(user_id,filename,stored_name,size,content_type,uploaded) VALUES(?,?,?,?,?,?)",
        (g.user["id"], filename, stored_name, len(content),
         upload.mimetype or "application/octet-stream", time.time()))
    E.audit("FILE_UPLOAD", g.user["username"], {"file_id": file_id, "filename": filename, "size": len(content)})
    return jsonify(ok=True, user=public(E.get_user(g.user["id"]))), 201

@app.get("/api/files/<int:file_id>/download")
@auth()
def download_file(file_id):
    decision = E.access(g.user, g.sid, "storage:read")
    if not decision["allowed"]:
        return jsonify(**decision, user=public(E.get_user(g.user["id"]))), 403
    stored = db.run("SELECT * FROM files WHERE id=? AND user_id=?", (file_id, g.user["id"]), "one")
    if not stored:
        return err("File not found.", 404)
    path = os.path.join(FILE_ROOT, str(g.user["id"]), stored["stored_name"])
    if not os.path.isfile(path):
        return err("Stored file is missing. Contact an administrator.", 404)
    E.audit("FILE_DOWNLOAD", g.user["username"], {"file_id": file_id})
    return send_file(path, as_attachment=True, download_name=stored["filename"],
                     mimetype=stored["content_type"])

@app.delete("/api/files/<int:file_id>")
@auth()
def delete_file(file_id):
    decision = E.access(g.user, g.sid, "storage:delete")
    if not decision["allowed"]:
        return jsonify(**decision, user=public(E.get_user(g.user["id"]))), 403
    stored = db.run("SELECT * FROM files WHERE id=? AND user_id=?", (file_id, g.user["id"]), "one")
    if not stored:
        return err("File not found.", 404)
    path = os.path.join(FILE_ROOT, str(g.user["id"]), stored["stored_name"])
    if not os.path.isfile(path):
        return err("Stored file is missing. Contact an administrator.", 404)
    os.remove(path)
    db.run("DELETE FROM files WHERE id=? AND user_id=?", (file_id, g.user["id"]))
    E.audit("FILE_DELETE", g.user["username"], {"file_id": file_id})
    return jsonify(ok=True, user=public(E.get_user(g.user["id"])))

# ---------------------------------------------------------------- admin
@app.get("/api/admin/overview")
@auth(admin=True)
def overview():
    q = lambda s, a=(): db.run(s, a, "one")["c"]
    users = db.run("SELECT id,username,role,trust,state,state_reason,state_until,last_login,mobile FROM users ORDER BY id", fetch="all")
    for u in users: u["mobile"] = E.mask(u["mobile"])
    return jsonify(
        stats=dict(users=len(users), active_sessions=q("SELECT COUNT(*) c FROM sessions WHERE status='ACTIVE'"),
                   open_alerts=q("SELECT COUNT(*) c FROM alerts WHERE ack=0"),
                   denied_hour=q("SELECT COUNT(*) c FROM logs WHERE allowed=0 AND ts>?", (time.time() - 3600,)),
                   restricted=q("SELECT COUNT(*) c FROM users WHERE state!='NORMAL'")),
        users=users,
        sessions=db.run("SELECT s.id,u.username,s.created,s.last_activity,s.ip FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.status='ACTIVE' ORDER BY s.created DESC", fetch="all"),
        alerts=db.run("SELECT * FROM alerts WHERE ack=0 ORDER BY id DESC LIMIT 30", fetch="all"),
        policies=E.policies(),
        replay=q("SELECT COUNT(*) c FROM replay"))

@app.get("/api/admin/audit")
@auth(admin=True)
def audit_log():
    ok, bad = E.verify_audit()
    rows = db.run("SELECT id,ts,event,user,detail,hash FROM audit ORDER BY id DESC LIMIT 100", fetch="all")
    return jsonify(rows=rows, chain_ok=ok, broken_at=bad)

@app.post("/api/admin/users/<int:uid>/<action>")
@auth(admin=True)
def user_action(uid, action):
    u = E.get_user(uid)
    if not u: return err("No such user", 404)
    if action == "unlock": E.unlock(u, g.user["username"])
    elif action == "lock":
        if u["id"] == g.user["id"]: return err("You cannot lock your own account.")
        E.set_state(u, "LOCKED", f"locked by {g.user['username']}")
    else: return err("Unknown action", 404)
    return jsonify(ok=True)

@app.post("/api/admin/sessions/<sid>/terminate")
@auth(admin=True)
def kill_session(sid):
    E.terminate_session(sid, f"terminated by {g.user['username']}", by=g.user["username"]); return jsonify(ok=True)

@app.post("/api/admin/alerts/<int:aid>/ack")
@auth(admin=True)
def ack(aid):
    db.run("UPDATE alerts SET ack=1 WHERE id=?", (aid,)); return jsonify(ok=True)

@app.post("/api/admin/policies")
@auth(admin=True)
def set_policy():
    d = request.get_json(silent=True) or {}
    try: t = float(d["threshold"]); assert 0.05 <= t <= 0.95
    except Exception: return err("Threshold must be between 0.05 and 0.95.")
    if not E.policy(d.get("permission")): return err("Unknown permission", 404)
    db.run("UPDATE policies SET base_threshold=?, threshold=? WHERE permission=?", (t, t, d["permission"]))
    E.audit("POLICY_CHANGED", g.user["username"], {"permission": d["permission"], "threshold": t})
    return jsonify(ok=True)

def boot():
    db.init(); E.seed_policies(); E.seed_admin(); E.pretrain()
    def loop():
        while True:
            try: E.sweep()
            except Exception as e: print("sweeper:", e)
            time.sleep(5)
    threading.Thread(target=loop, daemon=True).start()

boot()
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  ZTACS running on http://localhost:{port}\n  Admin login: admin / {os.environ.get('ZTACS_ADMIN_PW','Admin@12345')}  (OTP appears in this console)\n")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
