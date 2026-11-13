#!/usr/bin/env bash
# =====================================================================
#  Mobilearn — Termux installer
#  v3: 0.0.0.0 bind · dark/light theme · pro landing page
#  (previous: icon dashboard, drawer, banners, auto-approve,
#   forgot password, leaderboard, challenges, admin live monitor)
# =====================================================================
set -euo pipefail
APP_DIR="$HOME/mobilearn"
PORT="${PORT:-8082}"
DB_FILE="$APP_DIR/mobilearn.db"

echo "=================================================="
echo "  Mobilearn — installing dependencies..."
echo "=================================================="
if command -v pkg >/dev/null 2>&1; then
    pkg update -y >/dev/null 2>&1 || true
    pkg install -y python >/dev/null 2>&1 || true
fi
python3 -m ensurepip --upgrade 2>/dev/null || true
python3 -m pip install --upgrade pip 2>/dev/null || true
if ! python3 -c "import flask, werkzeug" 2>/dev/null; then
    echo "Installing Flask + werkzeug..."
    python3 -m pip install --quiet flask || { echo "Install failed."; exit 1; }
fi
mkdir -p "$APP_DIR"; cd "$APP_DIR"

# ─────────────────────────────────────────────────────────────────────
# 1) Backend — 0.0.0.0 bind · PORT env aware (Render/Railway/Heroku OK)
# ─────────────────────────────────────────────────────────────────────
cat > server.py << 'PYEOF'
#!/usr/bin/env python3
"""Mobilearn backend — Flask + SQLite.

Bind:   0.0.0.0 (all interfaces) so cloud platforms can forward
        public traffic. Port resolves from $PORT (cloud platforms set
        this), then $MOBILEARN_PORT, then 8082.
"""
import os, re, sqlite3, uuid, time, hashlib, secrets
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, send_file
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, 'mobilearn.db')

def _resolve_port():
    for key in ('PORT', 'MOBILEARN_PORT'):
        v = os.environ.get(key)
        if v:
            try: return int(v)
            except ValueError: pass
    return 8082

PORT = _resolve_port()
HOST = '0.0.0.0'

SESSION_TTL_SECONDS = 60 * 60 * 24 * 30
WITHDRAW_MIN = 20000
REFERRAL_BONUS = 450
REFERRAL_PREFIX = "try your luck — don't retreat, signup now!!!"
ONLINE_WINDOW = 90

app = Flask(__name__, static_folder=None)

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def _col_exists(conn, table, column):
    return any(r['name'] == column for r in conn.execute(f"PRAGMA table_info({table})").fetchall())

def _hash(pw):
    return generate_password_hash(pw, method='pbkdf2:sha256', salt_length=16)

def _verify_and_upgrade(conn, table, ident_col, ident_val, plain_pw):
    row = conn.execute(f"SELECT * FROM {table} WHERE {ident_col}=?", (ident_val,)).fetchone()
    if not row: return None
    algo = row['pw_algo'] if 'pw_algo' in row.keys() else 'sha256'
    if algo == 'pbkdf2':
        ok = check_password_hash(row['password'], plain_pw)
    else:
        ok = hashlib.sha256(plain_pw.encode()).hexdigest() == row['password']
    if not ok: return None
    if algo == 'sha256':
        if table == 'users':
            conn.execute("UPDATE users SET password=?, pw_algo='pbkdf2' WHERE id=?", (_hash(plain_pw), row['id']))
        else:
            conn.execute("UPDATE admins SET password=?, pw_algo='pbkdf2', updated_at=? WHERE username=?", (_hash(plain_pw), time.time(), row['username']))
        conn.commit()
    return row

def _gen_ref_code(conn):
    for _ in range(20):
        code = secrets.token_hex(4).upper()
        if not conn.execute("SELECT 1 FROM users WHERE referral_code=?", (code,)).fetchone():
            return code
    return secrets.token_hex(6).upper()

def _get_setting(conn, key, default='0'):
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row['value'] if row else default

def _set_setting(conn, key, value):
    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)", (key, str(value)))

def _credit_referral(conn, user_row):
    try:
        referred_by = user_row['referred_by']
        credited = user_row['referral_credited']
    except (KeyError, IndexError):
        return
    if not referred_by or credited:
        return
    referrer = conn.execute("SELECT id, username FROM users WHERE username=?", (referred_by,)).fetchone()
    if not referrer:
        return
    conn.execute("UPDATE users SET balance=balance+?, total_earned=total_earned+? WHERE id=?",
                 (REFERRAL_BONUS, REFERRAL_BONUS, referrer['id']))
    conn.execute("UPDATE users SET referral_credited=1 WHERE id=?", (user_row['id'],))
    _msg(conn, referrer['username'],
         f"Referral bonus: {user_row['username']} was approved. "
         f"You earned UGX {REFERRAL_BONUS:,} into your balance.")
    _audit(conn, 'system', 'referral-credit', target=referrer['username'],
           payload=f'{REFERRAL_BONUS} for {user_row["username"]}')

def init_db():
    conn = get_db(); c = conn.cursor()
    c.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, phone TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
            balance REAL NOT NULL DEFAULT 0, verified INTEGER NOT NULL DEFAULT 0,
            note TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL, last_login REAL,
            pw_algo TEXT NOT NULL DEFAULT 'sha256',
            referral_code TEXT, referred_by TEXT,
            referral_credited INTEGER NOT NULL DEFAULT 0,
            total_earned REAL NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS admins (
            username TEXT PRIMARY KEY, password TEXT NOT NULL,
            pw_algo TEXT NOT NULL DEFAULT 'sha256', updated_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS videos (
            id TEXT PRIMARY KEY, video_id TEXT NOT NULL, title TEXT NOT NULL,
            reward REAL NOT NULL, published INTEGER NOT NULL DEFAULT 1, created_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS merchant_ids (
            id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, merchant_id TEXT NOT NULL,
            submitted_at REAL NOT NULL, updated_at REAL);
        CREATE TABLE IF NOT EXISTS credit_log (
            id TEXT PRIMARY KEY, username TEXT NOT NULL, video_id TEXT NOT NULL,
            reward REAL NOT NULL, credited_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY, user_id TEXT NOT NULL,
            created_at REAL NOT NULL, expires_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS audit_log (
            id TEXT PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL,
            target TEXT, payload TEXT, created_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY, from_username TEXT NOT NULL, to_username TEXT NOT NULL,
            body TEXT NOT NULL, created_at REAL NOT NULL, read_at REAL);
        CREATE TABLE IF NOT EXISTS announcements (
            id TEXT PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL,
            created_by TEXT NOT NULL, created_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS announcement_reads (
            username TEXT NOT NULL, announcement_id TEXT NOT NULL,
            read_at REAL NOT NULL, PRIMARY KEY (username, announcement_id));
        CREATE TABLE IF NOT EXISTS deal_requests (
            id TEXT PRIMARY KEY, username TEXT NOT NULL, kind TEXT NOT NULL,
            message TEXT NOT NULL, video_id TEXT, status TEXT NOT NULL DEFAULT 'pending',
            admin_note TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL, resolved_at REAL);
        CREATE TABLE IF NOT EXISTS withdrawals (
            id TEXT PRIMARY KEY, username TEXT NOT NULL, amount REAL NOT NULL,
            merchant_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
            admin_note TEXT NOT NULL DEFAULT '', created_at REAL NOT NULL, resolved_at REAL);
        CREATE TABLE IF NOT EXISTS banners (
            id TEXT PRIMARY KEY, image_url TEXT NOT NULL,
            link_url TEXT NOT NULL DEFAULT '', title TEXT NOT NULL DEFAULT '',
            active INTEGER NOT NULL DEFAULT 1, created_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS challenges (
            id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
            goal_type TEXT NOT NULL DEFAULT 'videos',
            goal_value INTEGER NOT NULL DEFAULT 5,
            reward REAL NOT NULL DEFAULT 500,
            active INTEGER NOT NULL DEFAULT 1, created_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS challenge_claims (
            username TEXT NOT NULL, challenge_id TEXT NOT NULL, claimed_at REAL NOT NULL,
            PRIMARY KEY (username, challenge_id));
    ''')
    for tbl, col, ddl in [
        ('sessions','expires_at',"ALTER TABLE sessions ADD COLUMN expires_at REAL"),
        ('users','pw_algo',"ALTER TABLE users ADD COLUMN pw_algo TEXT NOT NULL DEFAULT 'sha256'"),
        ('admins','pw_algo',"ALTER TABLE admins ADD COLUMN pw_algo TEXT NOT NULL DEFAULT 'sha256'"),
        ('admins','updated_at',"ALTER TABLE admins ADD COLUMN updated_at REAL NOT NULL DEFAULT 0"),
        ('users','referral_code',"ALTER TABLE users ADD COLUMN referral_code TEXT"),
        ('users','referred_by',"ALTER TABLE users ADD COLUMN referred_by TEXT"),
        ('users','referral_credited',"ALTER TABLE users ADD COLUMN referral_credited INTEGER NOT NULL DEFAULT 0"),
        ('users','last_seen',"ALTER TABLE users ADD COLUMN last_seen REAL"),
        ('users','total_earned',"ALTER TABLE users ADD COLUMN total_earned REAL NOT NULL DEFAULT 0"),
    ]:
        if not _col_exists(conn, tbl, col):
            c.execute(ddl)
    c.execute("UPDATE sessions SET expires_at=? WHERE expires_at IS NULL",
              (time.time() + SESSION_TTL_SECONDS,))
    for row in c.execute("SELECT id FROM users WHERE referral_code IS NULL OR referral_code=''").fetchall():
        c.execute("UPDATE users SET referral_code=? WHERE id=?", (_gen_ref_code(conn), row['id']))
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_refcode ON users(referral_code)")
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('auto_approve','0')")
    if not c.execute("SELECT 1 FROM admins WHERE username='admin'").fetchone():
        c.execute("INSERT INTO admins (username, password, pw_algo, updated_at) VALUES (?,?,?,?)",
                  ('admin', _hash('mobilearn2025'), 'pbkdf2', time.time()))
    if not c.execute("SELECT 1 FROM users WHERE username='amara'").fetchone():
        c.execute("""INSERT INTO users (id, username, phone, password, status, balance,
            verified, note, created_at, pw_algo, referral_code) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            ('u-demo', 'amara', '0701234567', _hash('amara123'), 'active', 0, 0, '', time.time(), 'pbkdf2', _gen_ref_code(conn)))
    if not c.execute("SELECT 1 FROM videos WHERE id='v-seed'").fetchone():
        c.execute("""INSERT INTO videos (id, video_id, title, reward, published, created_at)
            VALUES (?,?,?,?,?,?)""",
            ('v-seed', 'AWOXpzQzkp8', 'Sponsored video — watch to the end', 1900, 1, time.time()))
    conn.commit(); conn.close()

def _audit(conn, actor, action, target=None, payload=None):
    conn.execute("INSERT INTO audit_log (id, actor, action, target, payload, created_at) VALUES (?,?,?,?,?,?)",
                 ('a' + uuid.uuid4().hex[:12], actor, action, target, payload, time.time()))

def _msg(conn, to_username, body, from_username='admin'):
    conn.execute("INSERT INTO messages (id, from_username, to_username, body, created_at) VALUES (?,?,?,?,?)",
                 ('msg' + uuid.uuid4().hex[:12], from_username, to_username, body, time.time()))

def _create_session(conn, user_id):
    token = secrets.token_urlsafe(32)
    now = time.time()
    conn.execute("INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?,?,?,?)",
                 (token, user_id, now, now + SESSION_TTL_SECONDS))
    return token

def _bearer_token():
    a = request.headers.get('Authorization', '')
    return a[7:].strip() or None if a.startswith('Bearer ') else None

def _current_user():
    tok = _bearer_token()
    if not tok: return None
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM sessions WHERE token=?", (tok,)).fetchone()
        if not row: return None
        if row['expires_at'] and row['expires_at'] < time.time():
            conn.execute("DELETE FROM sessions WHERE token=?", (tok,)); conn.commit(); return None
        if row['user_id'] == '__admin__': return {'is_admin': True, 'username': 'admin'}
        u = conn.execute("SELECT * FROM users WHERE id=?", (row['user_id'],)).fetchone()
        return dict(u) if u else None
    finally:
        conn.close()

def require_member(fn):
    @wraps(fn)
    def w(*a, **kw):
        u = _current_user()
        if not u or u.get('is_admin'): return jsonify({'error': 'Unauthorized'}), 401
        if u['status'] != 'active': return jsonify({'error': 'Account not active.'}), 403
        return fn(*a, **kw)
    return w

def require_admin(fn):
    @wraps(fn)
    def w(*a, **kw):
        u = _current_user()
        if not u or not u.get('is_admin'): return jsonify({'error': 'Unauthorized'}), 401
        return fn(*a, **kw)
    return w

def _unread_count(conn, username):
    msg = conn.execute("SELECT COUNT(*) FROM messages WHERE to_username=? AND from_username='admin' AND read_at IS NULL",
                       (username,)).fetchone()[0]
    ann = conn.execute("""SELECT COUNT(*) FROM announcements a
        WHERE NOT EXISTS (SELECT 1 FROM announcement_reads r
                          WHERE r.username=? AND r.announcement_id=a.id)""",
                       (username,)).fetchone()[0]
    return msg + ann

@app.after_request
def no_cache(resp):
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    return resp

@app.route('/')
def index(): return send_from_directory(BASE_DIR, 'index.html')

PHONE_RE = re.compile(r'^(\+?256|0)(70|74|75|76)\d{7}$')
_clean = lambda p: re.sub(r'[\s\-()]', '', (p or '').strip())

@app.post('/api/signup')
def signup():
    d = request.get_json() or {}
    username = (d.get('username') or '').strip()
    phone = _clean(d.get('phone'))
    password = d.get('password') or ''
    ref_code = (d.get('ref') or '').strip().upper()
    if len(username) < 3: return jsonify({'error': 'Username must be at least 3 characters.'}), 400
    if not PHONE_RE.match(phone): return jsonify({'error': 'Airtel Uganda numbers only (070/074/075/076 + 7 digits).'}), 400
    if len(password) < 6: return jsonify({'error': 'Password must be at least 6 characters.'}), 400
    conn = get_db(); c = conn.cursor()
    try:
        if c.execute("SELECT 1 FROM users WHERE lower(username)=?", (username.lower(),)).fetchone():
            return jsonify({'error': 'Username already taken.'}), 409
        if c.execute("SELECT 1 FROM users WHERE phone=?", (phone,)).fetchone():
            return jsonify({'error': 'Airtel number already registered.'}), 409
        referred_by = None
        if ref_code:
            ref_user = c.execute("SELECT username FROM users WHERE referral_code=?", (ref_code,)).fetchone()
            if ref_user: referred_by = ref_user['username']
        auto = _get_setting(conn, 'auto_approve', '0') == '1'
        status = 'active' if auto else 'pending'
        uid = 'u' + uuid.uuid4().hex[:12]
        rcode = _gen_ref_code(conn)
        c.execute("""INSERT INTO users (id, username, phone, password, status, balance,
            verified, note, created_at, pw_algo, referral_code, referred_by)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (uid, username, phone, _hash(password), status, 0, 0, '', time.time(),
             'pbkdf2', rcode, referred_by))
        new_row = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if auto and referred_by:
            _credit_referral(conn, new_row)
        _audit(conn, username, 'signup', target=uid,
               payload=('referred_by=' + referred_by) if referred_by else None)
        conn.commit()
        if auto:
            message = 'Account created! Auto-approve is on — you can log in right away and start earning.'
        else:
            message = ('Account created! Pending admin approval. '
                       'Pay UGX 19,500 via *185*9# → 7285061 (MOBILE LABS), then submit '
                       'your activation request in the Inbox.')
        extra = ""
        if referred_by:
            extra = f" You were referred by {referred_by} — once approved, they earn UGX {REFERRAL_BONUS}."
        return jsonify({'message': message + extra, 'referral_code': rcode,
                        'auto_approved': auto}), 201
    finally:
        conn.close()

@app.post('/api/forgot-password')
def forgot_password():
    d = request.get_json() or {}
    username = (d.get('username') or '').strip()
    phone = _clean(d.get('phone'))
    nw = d.get('new_password') or ''
    if not username: return jsonify({'error': 'Enter your username.'}), 400
    if not PHONE_RE.match(phone): return jsonify({'error': 'Enter the Airtel number on the account.'}), 400
    if len(nw) < 6: return jsonify({'error': 'New password must be at least 6 characters.'}), 400
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM users WHERE lower(username)=? AND phone=?",
                           (username.lower(), phone)).fetchone()
        if not row: return jsonify({'error': 'No account matches that username and number.'}), 404
        conn.execute("UPDATE users SET password=?, pw_algo='pbkdf2' WHERE id=?", (_hash(nw), row['id']))
        conn.execute("DELETE FROM sessions WHERE user_id=?", (row['id'],))
        _msg(conn, row['username'], "Your password was reset from the login page. If this wasn't you, contact admin immediately.")
        _audit(conn, row['username'], 'forgot-password', target=row['id'])
        conn.commit()
        return jsonify({'ok': True})
    finally:
        conn.close()

@app.post('/api/login')
def login():
    d = request.get_json() or {}
    ident = (d.get('identifier') or '').strip()
    pw = d.get('password') or ''
    if not ident or not pw: return jsonify({'error': 'Enter username/number and password.'}), 400
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM users WHERE lower(username)=? OR phone=?", (ident.lower(), _clean(ident))).fetchone()
        if not row: return jsonify({'error': 'No account found.'}), 404
        matched = _verify_and_upgrade(conn, 'users', 'id', row['id'], pw)
        if not matched: return jsonify({'error': 'Incorrect password.'}), 401
        if matched['status'] == 'pending':
            if _get_setting(conn, 'auto_approve', '0') == '1':
                conn.execute("UPDATE users SET status='active' WHERE id=?", (matched['id'],))
                _credit_referral(conn, matched)
                _audit(conn, 'system', 'auto-approve-login', target=matched['id'])
                conn.commit()
                matched = conn.execute("SELECT * FROM users WHERE id=?", (matched['id'],)).fetchone()
            else:
                return jsonify({'error': 'Account pending admin approval.'}), 403
        if matched['status'] == 'suspended': return jsonify({'error': 'Account suspended. Contact support.'}), 403
        if matched['status'] == 'blocked': return jsonify({'error': 'Account blocked. Contact support.'}), 403
        tok = _create_session(conn, matched['id'])
        now = time.time()
        conn.execute("UPDATE users SET last_login=?, last_seen=? WHERE id=?", (now, now, matched['id']))
        conn.commit()
        unread = _unread_count(conn, matched['username'])
        return jsonify({'token': tok, 'unread': unread, 'user': {
            'id': matched['id'], 'username': matched['username'], 'phone': matched['phone'],
            'balance': matched['balance'], 'verified': bool(matched['verified']),
            'status': matched['status'], 'referral_code': matched['referral_code'] or ''}})
    finally:
        conn.close()

@app.get('/api/me')
def me():
    u = _current_user()
    if not u: return jsonify({'error': 'Unauthorized'}), 401
    if u.get('is_admin'): return jsonify({'is_admin': True})
    conn = get_db()
    try:
        now = time.time()
        conn.execute("UPDATE users SET last_seen=? WHERE id=?", (now, u['id']))
        conn.commit()
        return jsonify({'id': u['id'], 'username': u['username'], 'phone': u['phone'],
                        'balance': u['balance'], 'verified': bool(u['verified']),
                        'status': u['status'], 'unread': _unread_count(conn, u['username']),
                        'referral_code': u.get('referral_code') or '',
                        'total_earned': u.get('total_earned') or 0,
                        'last_seen': now})
    finally:
        conn.close()

@app.post('/api/logout')
def logout():
    tok = _bearer_token()
    if tok:
        conn = get_db(); conn.execute("DELETE FROM sessions WHERE token=?", (tok,)); conn.commit(); conn.close()
    return jsonify({'ok': True})

@app.post('/api/change-password')
@require_member
def change_password():
    d = request.get_json() or {}
    cur = d.get('current_password') or ''
    nw = d.get('new_password') or ''
    if len(nw) < 6: return jsonify({'error': 'New password must be at least 6 characters.'}), 400
    if cur == nw: return jsonify({'error': 'New password must differ from current.'}), 400
    conn = get_db()
    try:
        uid = _current_user()['id']
        m = _verify_and_upgrade(conn, 'users', 'id', uid, cur)
        if not m: return jsonify({'error': 'Current password is incorrect.'}), 401
        conn.execute("UPDATE users SET password=?, pw_algo='pbkdf2' WHERE id=?", (_hash(nw), uid))
        keep = _bearer_token()
        conn.execute("DELETE FROM sessions WHERE user_id=? AND token<>?", (uid, keep))
        _audit(conn, m['username'], 'change-password', target=uid)
        conn.commit(); return jsonify({'ok': True})
    finally:
        conn.close()

@app.get('/api/videos')
@require_member
def list_videos():
    conn = get_db()
    rows = conn.execute("SELECT * FROM videos WHERE published=1 ORDER BY created_at DESC").fetchall()
    conn.close(); return jsonify([dict(r) for r in rows])

@app.get('/api/credits')
@require_member
def my_credits():
    conn = get_db()
    rows = conn.execute("SELECT video_id FROM credit_log WHERE username=?", (_current_user()['username'],)).fetchall()
    conn.close(); return jsonify([r['video_id'] for r in rows])

@app.post('/api/credit')
@require_member
def credit():
    u = _current_user()
    vid = (request.get_json() or {}).get('video_id')
    if not vid: return jsonify({'error': 'Missing video_id'}), 400
    conn = get_db()
    try:
        video = conn.execute("SELECT * FROM videos WHERE id=?", (vid,)).fetchone()
        if not video: return jsonify({'error': 'Video not found'}), 404
        if conn.execute("SELECT 1 FROM credit_log WHERE username=? AND video_id=?", (u['username'], vid)).fetchone():
            return jsonify({'error': 'Already earned from this video.', 'balance': u['balance']}), 409
        reward = video['reward']
        conn.execute("UPDATE users SET balance=balance+?, total_earned=total_earned+?, verified=0 WHERE id=?",
                     (reward, reward, u['id']))
        conn.execute("INSERT INTO credit_log (id, username, video_id, reward, credited_at) VALUES (?,?,?,?,?)",
                     ('c' + uuid.uuid4().hex[:12], u['username'], vid, reward, time.time()))
        conn.commit()
        nb = conn.execute("SELECT balance FROM users WHERE id=?", (u['id'],)).fetchone()['balance']
        return jsonify({'ok': True, 'reward': reward, 'balance': nb})
    finally:
        conn.close()

@app.get('/api/leaderboard')
@require_member
def leaderboard():
    u = _current_user()
    conn = get_db()
    try:
        rows = conn.execute("""SELECT username, total_earned, balance FROM users
            WHERE status='active'
            ORDER BY total_earned DESC, balance DESC LIMIT 10""").fetchall()
        entries = [{'rank': i + 1, 'username': r['username'], 'earned': r['total_earned'] or 0}
                   for i, r in enumerate(rows)]
        mine = conn.execute("SELECT total_earned FROM users WHERE id=?", (u['id'],)).fetchone()
        my_earned = (mine['total_earned'] or 0) if mine else 0
        my_rank = conn.execute(
            "SELECT COUNT(*) FROM users WHERE status='active' AND total_earned > ?",
            (my_earned,)).fetchone()[0] + 1
        return jsonify({'leaderboard': entries,
                        'me': {'username': u['username'], 'earned': my_earned, 'rank': my_rank}})
    finally:
        conn.close()

def _challenge_progress(conn, username, ch):
    if ch['goal_type'] == 'referrals':
        return conn.execute("SELECT COUNT(*) FROM users WHERE referred_by=? AND referral_credited=1",
                            (username,)).fetchone()[0]
    return conn.execute("SELECT COUNT(*) FROM credit_log WHERE username=?", (username,)).fetchone()[0]

@app.get('/api/challenges')
@require_member
def list_challenges():
    u = _current_user()
    conn = get_db()
    try:
        rows = conn.execute("SELECT * FROM challenges WHERE active=1 ORDER BY created_at DESC").fetchall()
        claimed = {r['challenge_id'] for r in
                   conn.execute("SELECT challenge_id FROM challenge_claims WHERE username=?",
                                (u['username'],)).fetchall()}
        out = []
        for r in rows:
            d = dict(r)
            d['progress'] = _challenge_progress(conn, u['username'], r)
            d['claimed'] = r['id'] in claimed
            d['complete'] = d['progress'] >= r['goal_value']
            out.append(d)
        return jsonify(out)
    finally:
        conn.close()

@app.post('/api/challenges/<cid>/claim')
@require_member
def claim_challenge(cid):
    u = _current_user()
    conn = get_db()
    try:
        ch = conn.execute("SELECT * FROM challenges WHERE id=? AND active=1", (cid,)).fetchone()
        if not ch: return jsonify({'error': 'Challenge not found.'}), 404
        if conn.execute("SELECT 1 FROM challenge_claims WHERE username=? AND challenge_id=?",
                        (u['username'], cid)).fetchone():
            return jsonify({'error': 'Already claimed.'}), 409
        progress = _challenge_progress(conn, u['username'], ch)
        if progress < ch['goal_value']:
            return jsonify({'error': f'Not complete yet ({progress}/{ch["goal_value"]}).'}), 400
        conn.execute("UPDATE users SET balance=balance+?, total_earned=total_earned+? WHERE id=?",
                     (ch['reward'], ch['reward'], u['id']))
        conn.execute("INSERT INTO challenge_claims (username, challenge_id, claimed_at) VALUES (?,?,?)",
                     (u['username'], cid, time.time()))
        _msg(conn, u['username'],
             f"Challenge complete: {ch['title']}. UGX {ch['reward']:,.0f} added to your balance!")
        _audit(conn, u['username'], 'challenge-claim', target=cid, payload=ch['title'])
        conn.commit()
        bal = conn.execute("SELECT balance FROM users WHERE id=?", (u['id'],)).fetchone()['balance']
        return jsonify({'ok': True, 'reward': ch['reward'], 'balance': bal})
    finally:
        conn.close()

@app.get('/api/merchant')
@require_member
def get_merchant():
    conn = get_db()
    row = conn.execute("SELECT merchant_id FROM merchant_ids WHERE username=?", (_current_user()['username'],)).fetchone()
    conn.close(); return jsonify({'merchant_id': row['merchant_id'] if row else ''})

@app.post('/api/merchant')
@require_member
def submit_merchant():
    u = _current_user()
    mid = _clean((request.get_json() or {}).get('merchant_id'))
    if not PHONE_RE.match(mid): return jsonify({'error': 'Invalid Airtel number (e.g. 0701234567).'}), 400
    conn = get_db()
    try:
        now = time.time()
        if conn.execute("SELECT 1 FROM merchant_ids WHERE username=?", (u['username'],)).fetchone():
            conn.execute("UPDATE merchant_ids SET merchant_id=?, updated_at=? WHERE username=?", (mid, now, u['username']))
        else:
            conn.execute("INSERT INTO merchant_ids (id, username, merchant_id, submitted_at) VALUES (?,?,?,?)",
                         ('m' + uuid.uuid4().hex[:12], u['username'], mid, now))
        _audit(conn, u['username'], 'merchant-submit', payload=mid)
        conn.commit(); return jsonify({'ok': True, 'merchant_id': mid})
    finally:
        conn.close()

@app.get('/api/withdrawals')
@require_member
def my_withdrawals():
    u = _current_user()
    conn = get_db()
    try:
        merchant = conn.execute("SELECT merchant_id FROM merchant_ids WHERE username=?", (u['username'],)).fetchone()
        merchant_id = merchant['merchant_id'] if merchant else ''
        pending = conn.execute("SELECT COUNT(*) FROM withdrawals WHERE username=? AND status='pending'", (u['username'],)).fetchone()[0]
        rows = conn.execute("""SELECT * FROM withdrawals WHERE username=?
            ORDER BY created_at DESC LIMIT 30""", (u['username'],)).fetchall()
        return jsonify({
            'balance': u['balance'], 'merchant_id': merchant_id, 'min': WITHDRAW_MIN,
            'has_pending': pending > 0, 'withdrawals': [dict(r) for r in rows],
        })
    finally:
        conn.close()

@app.post('/api/withdraw')
@require_member
def request_withdrawal():
    u = _current_user()
    d = request.get_json() or {}
    try: amount = float(d.get('amount') or 0)
    except (TypeError, ValueError): return jsonify({'error': 'Invalid amount.'}), 400
    if amount < WITHDRAW_MIN:
        return jsonify({'error': f'Minimum withdrawal is UGX {WITHDRAW_MIN:,}.'}), 400
    conn = get_db()
    try:
        merchant = conn.execute("SELECT merchant_id FROM merchant_ids WHERE username=?", (u['username'],)).fetchone()
        if not merchant or not merchant['merchant_id']:
            return jsonify({'error': 'Save your Airtel merchant ID first (Payout details).'}), 400
        merchant_id = merchant['merchant_id']
        if conn.execute("SELECT 1 FROM withdrawals WHERE username=? AND status='pending'", (u['username'],)).fetchone():
            return jsonify({'error': 'You already have a pending withdrawal. Please wait for admin approval.'}), 400
        fresh = conn.execute("SELECT balance FROM users WHERE id=?", (u['id'],)).fetchone()
        if (fresh['balance'] or 0) < amount:
            return jsonify({'error': 'Insufficient balance.'}), 400
        wid = 'w' + uuid.uuid4().hex[:12]
        conn.execute("INSERT INTO withdrawals (id, username, amount, merchant_id, status, created_at) VALUES (?,?,?,?,?,?)",
                     (wid, u['username'], amount, merchant_id, 'pending', time.time()))
        msg_body = (f"Withdrawal request of UGX {amount:,.0f} to {merchant_id} received. "
                    "Please allow up to 2 hours for admin to approve and confirm your payment. Be patient.")
        _msg(conn, u['username'], msg_body)
        _audit(conn, u['username'], 'withdraw-request', target=wid, payload=f'{amount} → {merchant_id}')
        conn.commit()
        return jsonify({'ok': True, 'id': wid, 'message': msg_body}), 201
    finally:
        conn.close()

@app.get('/api/referrals')
@require_member
def my_referrals():
    u = _current_user()
    conn = get_db()
    try:
        rows = conn.execute("""SELECT username, status, referral_credited, created_at
            FROM users WHERE referred_by=? ORDER BY created_at DESC""", (u['username'],)).fetchall()
        total = len(rows)
        credited = sum(1 for r in rows if r['referral_credited'])
        return jsonify({
            'code': u.get('referral_code') or '', 'bonus': REFERRAL_BONUS, 'prefix': REFERRAL_PREFIX,
            'referred_total': total, 'credited_total': credited,
            'earned': credited * REFERRAL_BONUS, 'referrals': [dict(r) for r in rows],
        })
    finally:
        conn.close()

@app.get('/api/inbox')
@require_member
def inbox():
    u = _current_user()
    conn = get_db()
    try:
        ann = conn.execute("""SELECT a.*, CASE WHEN r.read_at IS NULL THEN 0 ELSE 1 END AS is_read
            FROM announcements a
            LEFT JOIN announcement_reads r ON r.announcement_id=a.id AND r.username=?
            ORDER BY a.created_at DESC LIMIT 50""", (u['username'],)).fetchall()
        msgs = conn.execute("""SELECT id, from_username, to_username, body, created_at, read_at
            FROM messages WHERE from_username=? OR to_username=?
            ORDER BY created_at ASC LIMIT 200""", (u['username'], u['username'])).fetchall()
        reqs = conn.execute("""SELECT id, kind, message, video_id, status, admin_note, created_at, resolved_at
            FROM deal_requests WHERE username=? ORDER BY created_at DESC LIMIT 50""", (u['username'],)).fetchall()
        return jsonify({'announcements': [dict(r) for r in ann],
                        'messages': [dict(r) for r in msgs],
                        'deal_requests': [dict(r) for r in reqs],
                        'unread': _unread_count(conn, u['username'])})
    finally:
        conn.close()

@app.post('/api/inbox/message')
@require_member
def inbox_send():
    u = _current_user()
    body = ((request.get_json() or {}).get('body') or '').strip()
    if not body: return jsonify({'error': 'Message is empty.'}), 400
    if len(body) > 4000: return jsonify({'error': 'Message too long.'}), 400
    conn = get_db()
    try:
        conn.execute("INSERT INTO messages (id, from_username, to_username, body, created_at) VALUES (?,?,?,?,?)",
                     ('msg' + uuid.uuid4().hex[:12], u['username'], 'admin', body, time.time()))
        conn.commit(); return jsonify({'ok': True})
    finally:
        conn.close()

@app.post('/api/inbox/mark-read')
@require_member
def inbox_mark_read():
    u = _current_user()
    conn = get_db()
    try:
        now = time.time()
        conn.execute("UPDATE messages SET read_at=? WHERE to_username=? AND read_at IS NULL", (now, u['username']))
        for row in conn.execute("SELECT id FROM announcements").fetchall():
            conn.execute("INSERT OR IGNORE INTO announcement_reads (username, announcement_id, read_at) VALUES (?,?,?)",
                         (u['username'], row['id'], now))
        conn.commit(); return jsonify({'ok': True, 'unread': 0})
    finally:
        conn.close()

@app.post('/api/deal-request')
@require_member
def create_deal_request():
    u = _current_user()
    d = request.get_json() or {}
    kind = (d.get('kind') or '').strip()
    msg = (d.get('message') or '').strip()
    vid = (d.get('video_id') or '').strip() or None
    if kind not in ('verification', 'activation', 'payout', 'other'):
        return jsonify({'error': 'Invalid request type.'}), 400
    if len(msg) < 5: return jsonify({'error': 'Describe your request (at least 5 characters).'}), 400
    conn = get_db()
    try:
        rid = 'dr' + uuid.uuid4().hex[:12]
        conn.execute("INSERT INTO deal_requests (id, username, kind, message, video_id, status, created_at) VALUES (?,?,?,?,?,?,?)",
                     (rid, u['username'], kind, msg, vid, 'pending', time.time()))
        _audit(conn, u['username'], f'deal-{kind}', payload=msg[:200])
        conn.commit(); return jsonify({'ok': True, 'id': rid})
    finally:
        conn.close()

@app.get('/api/banners')
@require_member
def list_banners():
    conn = get_db()
    rows = conn.execute("SELECT * FROM banners WHERE active=1 ORDER BY created_at DESC LIMIT 5").fetchall()
    conn.close(); return jsonify([dict(r) for r in rows])

@app.post('/api/admin/login')
def admin_login():
    d = request.get_json() or {}
    u = (d.get('username') or '').strip()
    p = d.get('password') or ''
    conn = get_db()
    try:
        m = _verify_and_upgrade(conn, 'admins', 'username', u, p)
        if not m: return jsonify({'error': 'Invalid admin credentials.'}), 401
        tok = _create_session(conn, '__admin__')
        conn.commit(); return jsonify({'token': tok})
    finally:
        conn.close()

@app.post('/api/admin/change-password')
@require_admin
def admin_change_password():
    d = request.get_json() or {}
    cur = d.get('current_password') or ''
    nw = d.get('new_password') or ''
    if len(nw) < 8: return jsonify({'error': 'New admin password must be at least 8 characters.'}), 400
    if cur == nw: return jsonify({'error': 'New password must differ.'}), 400
    conn = get_db()
    try:
        m = _verify_and_upgrade(conn, 'admins', 'username', 'admin', cur)
        if not m: return jsonify({'error': 'Current password is incorrect.'}), 401
        conn.execute("UPDATE admins SET password=?, pw_algo='pbkdf2', updated_at=? WHERE username='admin'",
                     (_hash(nw), time.time()))
        keep = _bearer_token()
        conn.execute("DELETE FROM sessions WHERE user_id='__admin__' AND token<>?", (keep,))
        _audit(conn, 'admin', 'admin-change-password')
        conn.commit(); return jsonify({'ok': True})
    finally:
        conn.close()

@app.get('/api/admin/settings')
@require_admin
def admin_get_settings():
    conn = get_db()
    try:
        return jsonify({'auto_approve': _get_setting(conn, 'auto_approve', '0') == '1'})
    finally:
        conn.close()

@app.post('/api/admin/settings')
@require_admin
def admin_set_settings():
    d = request.get_json() or {}
    conn = get_db()
    try:
        if 'auto_approve' in d:
            val = '1' if d['auto_approve'] else '0'
            _set_setting(conn, 'auto_approve', val)
            if val == '1':
                pend = conn.execute("SELECT * FROM users WHERE status='pending'").fetchall()
                for p in pend:
                    conn.execute("UPDATE users SET status='active' WHERE id=?", (p['id'],))
                    _credit_referral(conn, p)
            _audit(conn, 'admin', 'settings-auto-approve-' + ('on' if val == '1' else 'off'))
        conn.commit()
        return jsonify({'ok': True,
                        'auto_approve': _get_setting(conn, 'auto_approve', '0') == '1'})
    finally:
        conn.close()

@app.get('/api/admin/online')
@require_admin
def admin_online():
    conn = get_db()
    try:
        now = time.time()
        rows = conn.execute("""SELECT username, phone, balance, last_seen, status
            FROM users WHERE last_seen > ? ORDER BY last_seen DESC""",
            (now - ONLINE_WINDOW,)).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()

@app.get('/api/admin/users')
@require_admin
def admin_users():
    conn = get_db()
    now = time.time()
    rows = conn.execute("""SELECT id, username, phone, status, balance, verified, note,
        created_at, last_login, last_seen, referral_code, referred_by, referral_credited,
        total_earned
        FROM users ORDER BY created_at DESC""").fetchall()
    result = []
    for r in rows:
        d = dict(r)
        ls = d.get('last_seen')
        d['is_online'] = bool(ls and (now - ls) < ONLINE_WINDOW)
        result.append(d)
    conn.close(); return jsonify(result)

@app.post('/api/admin/users/<uid>/status')
@require_admin
def admin_user_status(uid):
    d = request.get_json() or {}
    status = d.get('status'); note = (d.get('note') or '').strip()
    if status not in ('pending', 'active', 'suspended', 'blocked'):
        return jsonify({'error': 'Invalid status'}), 400
    conn = get_db()
    try:
        target = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not target: return jsonify({'error': 'User not found.'}), 404
        conn.execute("UPDATE users SET status=?, note=? WHERE id=?", (status, note, uid))
        if status in ('suspended', 'blocked'):
            conn.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
        if status == 'active':
            _credit_referral(conn, target)
        _audit(conn, 'admin', f'user-{status}', target=uid, payload=note)
        conn.commit(); return jsonify({'ok': True})
    finally:
        conn.close()

@app.post('/api/admin/users/<uid>/reset-password')
@require_admin
def admin_reset_user_password(uid):
    d = request.get_json() or {}
    nw = d.get('new_password') or ''
    if len(nw) < 6: return jsonify({'error': 'Password must be at least 6 characters.'}), 400
    conn = get_db()
    try:
        u = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not u: return jsonify({'error': 'User not found.'}), 404
        conn.execute("UPDATE users SET password=?, pw_algo='pbkdf2' WHERE id=?", (_hash(nw), uid))
        conn.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
        _msg(conn, u['username'], "Your password was reset by admin. Use the new password to log in.")
        _audit(conn, 'admin', 'reset-user-password', target=uid)
        conn.commit(); return jsonify({'ok': True})
    finally:
        conn.close()

@app.delete('/api/admin/users/<uid>')
@require_admin
def admin_delete_user(uid):
    conn = get_db()
    try:
        row = conn.execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()
        conn.execute("DELETE FROM users WHERE id=?", (uid,))
        conn.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
        if row:
            uname = row['username']
            conn.execute("DELETE FROM merchant_ids WHERE username=?", (uname,))
            conn.execute("DELETE FROM messages WHERE from_username=? OR to_username=?", (uname, uname))
            conn.execute("DELETE FROM deal_requests WHERE username=?", (uname,))
            conn.execute("DELETE FROM withdrawals WHERE username=?", (uname,))
            conn.execute("DELETE FROM challenge_claims WHERE username=?", (uname,))
        _audit(conn, 'admin', 'user-delete', target=uid)
        conn.commit(); return jsonify({'ok': True})
    finally:
        conn.close()

@app.get('/api/admin/videos')
@require_admin
def admin_videos():
    conn = get_db()
    rows = conn.execute("SELECT * FROM videos ORDER BY created_at DESC").fetchall()
    conn.close(); return jsonify([dict(r) for r in rows])

YT_PATTERNS = [
    r'(?:youtube\.com\/watch\?(?:.*&)?v=)([a-zA-Z0-9_-]{11})',
    r'(?:youtu\.be\/)([a-zA-Z0-9_-]{11})',
    r'(?:youtube\.com\/embed\/)([a-zA-Z0-9_-]{11})',
    r'(?:youtube\.com\/shorts\/)([a-zA-Z0-9_-]{11})',
    r'^([a-zA-Z0-9_-]{11})$',
]

@app.post('/api/admin/videos')
@require_admin
def admin_publish_video():
    d = request.get_json() or {}
    url = (d.get('url') or '').strip()
    title = (d.get('title') or '').strip()
    try: reward = float(d.get('reward', 1900))
    except (TypeError, ValueError): return jsonify({'error': 'Reward must be a number.'}), 400
    vid = next((m.group(1) for p in YT_PATTERNS for m in [re.search(p, url)] if m), None)
    if not vid: return jsonify({'error': 'Invalid YouTube URL.'}), 400
    if not title: return jsonify({'error': 'Title required.'}), 400
    if reward <= 0: return jsonify({'error': 'Reward must be positive.'}), 400
    conn = get_db()
    try:
        conn.execute("INSERT INTO videos (id, video_id, title, reward, published, created_at) VALUES (?,?,?,?,?,?)",
                     ('v' + uuid.uuid4().hex[:12], vid, title, reward, 1, time.time()))
        _audit(conn, 'admin', 'video-publish', payload=f'{vid} · {title}')
        conn.commit(); return jsonify({'ok': True})
    finally:
        conn.close()

@app.delete('/api/admin/videos/<vid>')
@require_admin
def admin_delete_video(vid):
    conn = get_db()
    try:
        conn.execute("DELETE FROM videos WHERE id=?", (vid,))
        _audit(conn, 'admin', 'video-delete', target=vid)
        conn.commit(); return jsonify({'ok': True})
    finally:
        conn.close()

@app.get('/api/admin/merchants')
@require_admin
def admin_merchants():
    conn = get_db()
    rows = conn.execute("SELECT * FROM merchant_ids ORDER BY COALESCE(updated_at, submitted_at) DESC").fetchall()
    conn.close(); return jsonify([dict(r) for r in rows])

@app.get('/api/admin/banners')
@require_admin
def admin_banners():
    conn = get_db()
    rows = conn.execute("SELECT * FROM banners ORDER BY created_at DESC").fetchall()
    conn.close(); return jsonify([dict(r) for r in rows])

@app.post('/api/admin/banners')
@require_admin
def admin_create_banner():
    d = request.get_json() or {}
    image_url = (d.get('image_url') or '').strip()
    link_url = (d.get('link_url') or '').strip()
    title = (d.get('title') or '').strip() or 'Banner'
    if not image_url: return jsonify({'error': 'Image URL required.'}), 400
    if not (image_url.startswith('http://') or image_url.startswith('https://') or image_url.startswith('data:image')):
        return jsonify({'error': 'Image URL must start with http(s):// or data:image'}), 400
    conn = get_db()
    try:
        bid = 'bn' + uuid.uuid4().hex[:12]
        conn.execute("INSERT INTO banners (id, image_url, link_url, title, active, created_at) VALUES (?,?,?,?,?,?)",
                     (bid, image_url, link_url, title, 1, time.time()))
        _audit(conn, 'admin', 'banner-create', target=bid, payload=image_url[:200])
        conn.commit(); return jsonify({'ok': True, 'id': bid})
    finally:
        conn.close()

@app.delete('/api/admin/banners/<bid>')
@require_admin
def admin_delete_banner(bid):
    conn = get_db()
    try:
        conn.execute("DELETE FROM banners WHERE id=?", (bid,))
        _audit(conn, 'admin', 'banner-delete', target=bid)
        conn.commit(); return jsonify({'ok': True})
    finally:
        conn.close()

@app.post('/api/admin/banners/<bid>/toggle')
@require_admin
def admin_toggle_banner(bid):
    conn = get_db()
    try:
        row = conn.execute("SELECT active FROM banners WHERE id=?", (bid,)).fetchone()
        if not row: return jsonify({'error': 'Not found.'}), 404
        new_active = 0 if row['active'] else 1
        conn.execute("UPDATE banners SET active=? WHERE id=?", (new_active, bid))
        _audit(conn, 'admin', f'banner-{"activate" if new_active else "deactivate"}', target=bid)
        conn.commit()
        return jsonify({'ok': True, 'active': bool(new_active)})
    finally:
        conn.close()

@app.get('/api/admin/challenges')
@require_admin
def admin_challenges():
    conn = get_db()
    try:
        rows = conn.execute("SELECT * FROM challenges ORDER BY created_at DESC").fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()

@app.post('/api/admin/challenges')
@require_admin
def admin_create_challenge():
    d = request.get_json() or {}
    title = (d.get('title') or '').strip()
    desc = (d.get('description') or '').strip()
    goal_type = d.get('goal_type') or 'videos'
    try: goal_value = int(d.get('goal_value') or 5)
    except (TypeError, ValueError): return jsonify({'error': 'Invalid goal.'}), 400
    try: reward = float(d.get('reward') or 0)
    except (TypeError, ValueError): return jsonify({'error': 'Invalid reward.'}), 400
    if not title: return jsonify({'error': 'Title required.'}), 400
    if goal_type not in ('videos', 'referrals'): return jsonify({'error': 'Invalid challenge type.'}), 400
    if goal_value < 1: return jsonify({'error': 'Goal must be at least 1.'}), 400
    if reward <= 0: return jsonify({'error': 'Reward must be positive.'}), 400
    conn = get_db()
    try:
        cid = 'ch' + uuid.uuid4().hex[:12]
        conn.execute("""INSERT INTO challenges
            (id, title, description, goal_type, goal_value, reward, active, created_at)
            VALUES (?,?,?,?,?,?,?,?)""",
            (cid, title, desc, goal_type, goal_value, reward, 1, time.time()))
        _audit(conn, 'admin', 'challenge-create', target=cid, payload=title)
        conn.commit(); return jsonify({'ok': True, 'id': cid})
    finally:
        conn.close()

@app.delete('/api/admin/challenges/<cid>')
@require_admin
def admin_delete_challenge(cid):
    conn = get_db()
    try:
        conn.execute("DELETE FROM challenges WHERE id=?", (cid,))
        conn.execute("DELETE FROM challenge_claims WHERE challenge_id=?", (cid,))
        _audit(conn, 'admin', 'challenge-delete', target=cid)
        conn.commit(); return jsonify({'ok': True})
    finally:
        conn.close()

@app.get('/api/admin/kpis')
@require_admin
def admin_kpis():
    conn = get_db()
    q = lambda sql, *a: conn.execute(sql, a).fetchone()[0]
    now = time.time()
    data = {
        'users': q("SELECT COUNT(*) FROM users"),
        'active': q("SELECT COUNT(*) FROM users WHERE status='active'"),
        'pending': q("SELECT COUNT(*) FROM users WHERE status='pending'"),
        'suspended': q("SELECT COUNT(*) FROM users WHERE status='suspended'"),
        'blocked': q("SELECT COUNT(*) FROM users WHERE status='blocked'"),
        'online_now': q("SELECT COUNT(*) FROM users WHERE last_seen > ?", now - ONLINE_WINDOW),
        'live_videos': q("SELECT COUNT(*) FROM videos WHERE published=1"),
        'total_videos': q("SELECT COUNT(*) FROM videos"),
        'merchants': q("SELECT COUNT(*) FROM merchant_ids"),
        'credits': q("SELECT COUNT(*) FROM credit_log"),
        'total_balance': round(q("SELECT COALESCE(SUM(balance),0) FROM users") or 0, 2),
        'pending_requests': q("SELECT COUNT(*) FROM deal_requests WHERE status='pending'"),
        'unread_msgs': q("SELECT COUNT(*) FROM messages WHERE to_username='admin' AND read_at IS NULL"),
        'pending_withdrawals': q("SELECT COUNT(*) FROM withdrawals WHERE status='pending'"),
        'total_withdrawn': round(q("SELECT COALESCE(SUM(amount),0) FROM withdrawals WHERE status='approved'") or 0, 2),
        'referrals_credited': q("SELECT COUNT(*) FROM users WHERE referral_credited=1"),
        'active_banners': q("SELECT COUNT(*) FROM banners WHERE active=1"),
        'active_challenges': q("SELECT COUNT(*) FROM challenges WHERE active=1"),
        'challenge_claims': q("SELECT COUNT(*) FROM challenge_claims"),
        'auto_approve': _get_setting(conn, 'auto_approve', '0') == '1',
    }
    conn.close(); return jsonify(data)

@app.get('/api/admin/audit')
@require_admin
def admin_audit():
    conn = get_db()
    rows = conn.execute("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 200").fetchall()
    conn.close(); return jsonify([dict(r) for r in rows])

@app.get('/api/admin/backup')
@require_admin
def admin_backup():
    return send_file(DB_PATH, as_attachment=True, download_name=f'mobilearn-{int(time.time())}.db')

@app.get('/api/admin/withdrawals')
@require_admin
def admin_withdrawals():
    conn = get_db()
    rows = conn.execute("""SELECT w.*, u.balance AS user_balance
        FROM withdrawals w LEFT JOIN users u ON u.username=w.username
        ORDER BY COALESCE(w.resolved_at, w.created_at) DESC, w.created_at DESC""").fetchall()
    conn.close(); return jsonify([dict(r) for r in rows])

@app.post('/api/admin/withdrawals/<wid>/approve')
@require_admin
def admin_approve_withdrawal(wid):
    conn = get_db()
    try:
        w = conn.execute("SELECT * FROM withdrawals WHERE id=?", (wid,)).fetchone()
        if not w: return jsonify({'error': 'Not found.'}), 404
        if w['status'] != 'pending': return jsonify({'error': 'Already resolved.'}), 400
        user = conn.execute("SELECT * FROM users WHERE username=?", (w['username'],)).fetchone()
        if not user: return jsonify({'error': 'User not found.'}), 404
        if (user['balance'] or 0) < w['amount']:
            return jsonify({'error': 'User balance is now less than the withdrawal amount.'}), 400
        conn.execute("UPDATE users SET balance = balance - ? WHERE id=?", (w['amount'], user['id']))
        conn.execute("UPDATE withdrawals SET status='approved', resolved_at=? WHERE id=?", (time.time(), wid))
        _msg(conn, w['username'],
             f"Your withdrawal of UGX {w['amount']:,.0f} to {w['merchant_id']} has been approved. "
             "Payment will reflect on your Airtel line shortly. Thank you for using Mobilearn.")
        _audit(conn, 'admin', 'withdraw-approve', target=wid, payload=f"{w['amount']} → {w['username']}")
        conn.commit(); return jsonify({'ok': True})
    finally:
        conn.close()

@app.post('/api/admin/withdrawals/<wid>/reject')
@require_admin
def admin_reject_withdrawal(wid):
    note = ((request.get_json() or {}).get('admin_note') or '').strip()
    conn = get_db()
    try:
        w = conn.execute("SELECT * FROM withdrawals WHERE id=?", (wid,)).fetchone()
        if not w: return jsonify({'error': 'Not found.'}), 404
        if w['status'] != 'pending': return jsonify({'error': 'Already resolved.'}), 400
        conn.execute("UPDATE withdrawals SET status='rejected', admin_note=?, resolved_at=? WHERE id=?",
                     (note, time.time(), wid))
        _msg(conn, w['username'],
             f"Your withdrawal request of UGX {w['amount']:,.0f} was declined."
             + (f" Reason: {note}" if note else ""))
        _audit(conn, 'admin', 'withdraw-reject', target=wid, payload=note)
        conn.commit(); return jsonify({'ok': True})
    finally:
        conn.close()

@app.get('/api/admin/conversations')
@require_admin
def admin_conversations():
    conn = get_db()
    rows = conn.execute("""
        SELECT u.username AS username, u.status AS status,
               (SELECT body FROM messages m
                  WHERE (m.from_username=u.username AND m.to_username='admin')
                     OR (m.from_username='admin' AND m.to_username=u.username)
                  ORDER BY m.created_at DESC LIMIT 1) AS last_body,
               (SELECT created_at FROM messages m
                  WHERE (m.from_username=u.username AND m.to_username='admin')
                     OR (m.from_username='admin' AND m.to_username=u.username)
                  ORDER BY m.created_at DESC LIMIT 1) AS last_at,
               (SELECT COUNT(*) FROM messages m
                  WHERE m.from_username=u.username AND m.to_username='admin' AND m.read_at IS NULL) AS unread
        FROM users u
        ORDER BY COALESCE(last_at, 0) DESC, u.username ASC""").fetchall()
    conn.close(); return jsonify([dict(r) for r in rows])

@app.get('/api/admin/messages/<username>')
@require_admin
def admin_messages(username):
    conn = get_db()
    try:
        u = conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
        if not u: return jsonify({'error': 'User not found.'}), 404
        msgs = conn.execute("""SELECT id, from_username, to_username, body, created_at, read_at
            FROM messages WHERE (from_username=? AND to_username='admin')
                          OR (from_username='admin' AND to_username=?)
            ORDER BY created_at ASC""", (username, username)).fetchall()
        conn.execute("UPDATE messages SET read_at=? WHERE from_username=? AND to_username='admin' AND read_at IS NULL",
                     (time.time(), username))
        conn.commit()
        return jsonify([dict(r) for r in msgs])
    finally:
        conn.close()

@app.post('/api/admin/messages/<username>/reply')
@require_admin
def admin_reply(username):
    body = ((request.get_json() or {}).get('body') or '').strip()
    if not body: return jsonify({'error': 'Reply is empty.'}), 400
    if len(body) > 4000: return jsonify({'error': 'Reply too long.'}), 400
    conn = get_db()
    try:
        u = conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
        if not u: return jsonify({'error': 'User not found.'}), 404
        conn.execute("INSERT INTO messages (id, from_username, to_username, body, created_at) VALUES (?,?,?,?,?)",
                     ('msg' + uuid.uuid4().hex[:12], 'admin', username, body, time.time()))
        _audit(conn, 'admin', 'reply', target=username, payload=body[:200])
        conn.commit(); return jsonify({'ok': True})
    finally:
        conn.close()

@app.get('/api/admin/announcements')
@require_admin
def admin_announcements():
    conn = get_db()
    rows = conn.execute("""SELECT a.*, 
        (SELECT COUNT(*) FROM announcement_reads r WHERE r.announcement_id=a.id) AS read_count,
        (SELECT COUNT(*) FROM users) AS total_users
        FROM announcements a ORDER BY a.created_at DESC""").fetchall()
    conn.close(); return jsonify([dict(r) for r in rows])

@app.post('/api/admin/announcements')
@require_admin
def admin_create_announcement():
    d = request.get_json() or {}
    title = (d.get('title') or '').strip()
    body = (d.get('body') or '').strip()
    if not title: return jsonify({'error': 'Title required.'}), 400
    if not body: return jsonify({'error': 'Body required.'}), 400
    if len(body) > 4000: return jsonify({'error': 'Too long.'}), 400
    conn = get_db()
    try:
        aid = 'ann' + uuid.uuid4().hex[:12]
        conn.execute("INSERT INTO announcements (id, title, body, created_by, created_at) VALUES (?,?,?,?,?)",
                     (aid, title, body, 'admin', time.time()))
        _audit(conn, 'admin', 'announce', target=aid, payload=title)
        conn.commit(); return jsonify({'ok': True, 'id': aid})
    finally:
        conn.close()

@app.delete('/api/admin/announcements/<aid>')
@require_admin
def admin_delete_announcement(aid):
    conn = get_db()
    try:
        conn.execute("DELETE FROM announcements WHERE id=?", (aid,))
        conn.execute("DELETE FROM announcement_reads WHERE announcement_id=?", (aid,))
        _audit(conn, 'admin', 'announce-delete', target=aid)
        conn.commit(); return jsonify({'ok': True})
    finally:
        conn.close()

@app.get('/api/admin/deal-requests')
@require_admin
def admin_deal_requests():
    conn = get_db()
    rows = conn.execute("SELECT * FROM deal_requests ORDER BY COALESCE(resolved_at, created_at) DESC, created_at DESC").fetchall()
    conn.close(); return jsonify([dict(r) for r in rows])

@app.post('/api/admin/deal-requests/<rid>/resolve')
@require_admin
def admin_resolve_deal(rid):
    note = ((request.get_json() or {}).get('admin_note') or '').strip()
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM deal_requests WHERE id=?", (rid,)).fetchone()
        if not row: return jsonify({'error': 'Not found.'}), 404
        conn.execute("UPDATE deal_requests SET status='resolved', admin_note=?, resolved_at=? WHERE id=?",
                     (note, time.time(), rid))
        _audit(conn, 'admin', 'deal-resolve', target=rid, payload=note)
        conn.commit(); return jsonify({'ok': True})
    finally:
        conn.close()

if __name__ == '__main__':
    init_db()
    print("=" * 66)
    print("  Mobilearn — running")
    print("=" * 66)
    print(f"  Bind         :  {HOST}:{PORT} (all interfaces — cloud-forwardable)")
    print(f"  DB file      :  {DB_PATH}")
    print(f"  Homepage     :  http://localhost:{PORT}")
    print(f"  Admin        :  http://localhost:{PORT}/#/admin")
    print("  Admin login  :  admin / mobilearn2025")
    print("  Demo member  :  amara / amara123")
    print("  Auto-approve :  toggle inside admin Access control panel")
    print("  Theme        :  sun/moon button in top nav (saved per device)")
    print("=" * 66)
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
PYEOF
chmod +x server.py

# ─────────────────────────────────────────────────────────────────────
# 2) Frontend — landing page + dark/light theme + all previous features
# ─────────────────────────────────────────────────────────────────────
cat > index.html << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Mobilearn — Watch YouTube. Get Paid. | Mobilelabs UG</title>
<meta name="description" content="Watch sponsored YouTube videos, earn UGX 1,900 per video, withdraw from UGX 20,000 to your Airtel Money. Refer friends, earn UGX 450 each. Built for Uganda." />
<meta name="theme-color" content="#1e40af" />
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Crect width='24' height='24' rx='6' fill='%231e40af'/%3E%3Cpath d='M4 17l5-6 4 3 5-7 4 4' fill='none' stroke='%23fff' stroke-width='2.2' stroke-linecap='round'/%3E%3C/svg%3E" />

<!-- Theme init — runs before first paint to prevent flash -->
<script>
(function(){
  try {
    var saved = localStorage.getItem("ml_theme");
    if (!saved) {
      saved = (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) ? "dark" : "light";
    }
    document.documentElement.setAttribute("data-theme", saved);
  } catch(e) {}
})();
</script>

<style>
/* ──────── THEME TOKENS ──────── */
:root{
  --bg:#fff;--bg-soft:#f8fafc;--card:#fff;
  --line:#e2e8f0;--line-strong:#cbd5e1;
  --text:#0f172a;--text-soft:#334155;--muted:#64748b;
  --primary:#1d4ed8;--primary-deep:#1e3a8a;
  --accent:#059669;--accent-soft:#d1fae5;
  --whatsapp:#25d366;--whatsapp-deep:#128c7e;
  --red:#dc2626;--amber:#b45309;
  --grad:linear-gradient(135deg,#1e40af 0%,#0f766e 100%);
  --radius-lg:20px;--max:1160px;
  --shadow-sm:0 1px 2px rgba(15,23,42,.06);
  --shadow:0 4px 20px rgba(15,23,42,.08);
  --shadow-lg:0 24px 60px -20px rgba(15,23,42,.18);
  --mono:'SF Mono',ui-monospace,'Courier New',monospace;
  color-scheme: light;
}
:root[data-theme="dark"]{
  --bg:#0a0f1c;--bg-soft:#0f1629;--card:#111c33;
  --line:#1f2b41;--line-strong:#334155;
  --text:#e6edf7;--text-soft:#cbd5e1;--muted:#8b9bb4;
  --primary:#60a5fa;--primary-deep:#93c5fd;
  --accent:#34d399;--accent-soft:#064e3b;
  --whatsapp:#25d366;--whatsapp-deep:#128c7e;
  --red:#f87171;--amber:#fbbf24;
  --grad:linear-gradient(135deg,#60a5fa 0%,#34d399 100%);
  --shadow-sm:0 1px 2px rgba(0,0,0,.4);
  --shadow:0 4px 20px rgba(0,0,0,.5);
  --shadow-lg:0 24px 60px -20px rgba(0,0,0,.7);
  color-scheme: dark;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,Arial,sans-serif;line-height:1.6;-webkit-font-smoothing:antialiased;overflow-x:hidden;transition:background .25s,color .25s}
img,svg{display:block;max-width:100%}a{color:inherit;text-decoration:none}button{font:inherit;color:inherit;background:none;border:none;cursor:pointer}input,select,textarea{font:inherit}
.container{width:100%;max-width:var(--max);margin-inline:auto;padding-inline:24px}
.icon{width:1em;height:1em;flex:none;display:inline-block;vertical-align:-.125em;fill:currentColor}.icon-sm{width:.85em;height:.85em}
.grad-text{background:var(--grad);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;color:transparent}
.eyebrow{display:inline-flex;align-items:center;gap:8px;font-size:.76rem;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:var(--accent)}
.section{padding:clamp(56px,8vw,96px) 0}.section-head{max-width:600px;margin:0 auto clamp(34px,5vw,48px);text-align:center}
.section-head h2{font-size:clamp(1.7rem,4vw,2.5rem);line-height:1.12;letter-spacing:-.025em;margin:12px 0 10px;font-weight:800}.section-head p{color:var(--muted)}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:9px;padding:14px 26px;border-radius:10px;font-weight:600;font-size:.95rem;transition:.2s;white-space:nowrap;cursor:pointer}
.btn-lg{padding:16px 32px;font-size:1rem;border-radius:12px}
.btn-primary{background:var(--grad);color:#fff;box-shadow:0 8px 20px -6px rgba(30,64,175,.4)}
:root[data-theme="dark"] .btn-primary{color:#0a0f1c;font-weight:800}
.btn-primary:hover{transform:translateY(-1px);box-shadow:0 14px 28px -8px rgba(30,64,175,.5)}
.btn-ghost{border:1px solid var(--line-strong);background:var(--card);color:var(--text)}
.btn-ghost:hover{background:var(--bg-soft);border-color:var(--line-strong)}
.btn-wa{background:var(--whatsapp);color:#fff}.btn-wa:hover{background:#1ebe5a}.btn-block{width:100%}
.spinner{display:inline-block;width:16px;height:16px;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;animation:spin .7s linear infinite;flex:none;vertical-align:-.15em}
@keyframes spin{to{transform:rotate(360deg)}}
.btn.loading{pointer-events:none;opacity:.9;cursor:wait}
.btn.loading .spinner{margin-right:2px}

/* ──────── NAV ──────── */
.nav{position:sticky;top:0;z-index:100;background:color-mix(in srgb,var(--bg) 85%,transparent);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border-bottom:1px solid transparent;transition:.3s}
@supports not (background:color-mix(in srgb,red,blue)){
  .nav{background:rgba(255,255,255,.85)}
  :root[data-theme="dark"] .nav{background:rgba(10,15,28,.85)}
}
.nav.scrolled{border-bottom-color:var(--line);box-shadow:0 1px 12px rgba(15,23,42,.04)}
.nav-inner{display:flex;align-items:center;justify-content:space-between;gap:20px;height:72px}
.logo{display:flex;align-items:center;gap:10px;font-weight:800;font-size:1.12rem;letter-spacing:-.02em}
.logo-mark{width:36px;height:36px;border-radius:10px;background:var(--grad);display:grid;place-items:center;color:#fff}
.logo-mark .icon{width:20px;height:20px;fill:none;stroke:currentColor;stroke-width:2.4}
.nav-links{display:flex;align-items:center;gap:24px}.nav-links a{font-size:.92rem;color:var(--muted);font-weight:500;position:relative;padding:4px 0;display:inline-flex;align-items:center;gap:6px}
.nav-links a:hover,.nav-links a.active{color:var(--primary);font-weight:700}.nav-links a.active::after{content:"";position:absolute;left:0;right:0;bottom:-6px;height:2px;border-radius:2px;background:var(--grad)}
.nav-cta{display:flex;align-items:center;gap:10px}.nav-cta .btn{padding:10px 20px;font-size:.9rem}
.theme-toggle{width:42px;height:42px;border-radius:10px;border:1px solid var(--line);background:var(--bg-soft);display:grid;place-items:center;transition:.2s;color:var(--text);flex:none}
.theme-toggle:hover{background:var(--card);border-color:var(--line-strong);transform:translateY(-1px)}
.theme-toggle .icon{width:20px;height:20px;fill:none;stroke:currentColor;stroke-width:2.2}
.theme-toggle .icon-sun{display:none}
:root[data-theme="dark"] .theme-toggle .icon-moon{display:none}
:root[data-theme="dark"] .theme-toggle .icon-sun{display:block}
.nav-badge{display:none;min-width:18px;height:18px;padding:0 5px;border-radius:9px;background:var(--red);color:#fff;font-size:.68rem;font-weight:800;line-height:18px;text-align:center}.nav-badge.on{display:inline-block}
.burger{display:none;width:42px;height:42px;border-radius:10px;border:1px solid var(--line);place-items:center;background:var(--card);color:var(--text)}
.burger .icon{width:20px;height:20px;fill:none;stroke:currentColor;stroke-width:2.2}.burger .icon-close{display:none}.burger[aria-expanded="true"] .icon-menu{display:none}.burger[aria-expanded="true"] .icon-close{display:block}
.mobile-menu{display:none;flex-direction:column;gap:4px;padding:12px 24px 22px;border-top:1px solid var(--line);background:var(--bg)}
.mobile-menu.open{display:flex}.mobile-menu a{padding:12px 4px;color:var(--muted);border-bottom:1px solid var(--line);display:inline-flex;align-items:center;gap:8px;font-weight:500}.mobile-menu a.active{color:var(--primary);font-weight:700}.mobile-menu .btn{margin-top:14px;border-bottom:none}

/* ──────── PAGES / ROUTES ──────── */
.page{display:none}.page.active{display:block;animation:pageIn .35s cubic-bezier(.22,1,.36,1)}
@keyframes pageIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
.page-head{max-width:680px;margin-inline:auto;text-align:center;padding-top:clamp(36px,6vw,60px)}
.page-head h1{font-size:clamp(2rem,4.4vw,3rem);line-height:1.1;letter-spacing:-.03em;font-weight:800;margin:14px 0 12px}.page-head p{color:var(--muted)}

/* ──────── LANDING: HERO v2 ──────── */
.hero-v2{position:relative;overflow:hidden;padding:clamp(48px,8vw,100px) 0 clamp(56px,9vw,110px);background:linear-gradient(180deg,var(--bg) 0%,var(--bg-soft) 100%)}
.hero-bg{position:absolute;inset:0;background:radial-gradient(circle at 15% 10%,rgba(29,78,216,.12),transparent 45%),radial-gradient(circle at 85% 90%,rgba(5,150,105,.10),transparent 45%);pointer-events:none}
:root[data-theme="dark"] .hero-bg{background:radial-gradient(circle at 15% 10%,rgba(96,165,250,.18),transparent 45%),radial-gradient(circle at 85% 90%,rgba(52,211,153,.14),transparent 45%)}
.hero-v2-inner{display:grid;grid-template-columns:1.05fr .95fr;gap:clamp(32px,5vw,64px);align-items:center;position:relative}
.hero-badge{display:inline-flex;align-items:center;gap:10px;padding:8px 16px 8px 8px;border-radius:999px;background:var(--card);border:1px solid var(--line);box-shadow:var(--shadow-sm);font-size:.82rem;color:var(--muted);margin-bottom:22px}
.hero-badge .live-dot{width:22px;height:22px;border-radius:50%;background:var(--grad);display:grid;place-items:center;color:#fff;flex:none;position:relative}
.hero-badge .live-dot::after{content:"";position:absolute;inset:-3px;border-radius:50%;border:2px solid var(--accent);opacity:.4;animation:pulse 2s infinite}
.hero-badge b{color:var(--text)}
.hero-v2 h1{font-size:clamp(2.2rem,5.2vw,4rem);line-height:1.02;letter-spacing:-.04em;font-weight:800;margin:0 0 20px}
.hero-v2-sub{color:var(--muted);font-size:clamp(1rem,1.7vw,1.15rem);max-width:540px;line-height:1.65}
.hero-v2-sub b{color:var(--text)}
.hero-v2-actions{display:flex;flex-wrap:wrap;gap:12px;margin-top:32px}
.hero-v2-trust{display:flex;flex-wrap:wrap;gap:12px 24px;margin-top:26px;font-size:.85rem;color:var(--muted)}
.hero-v2-trust span{display:inline-flex;align-items:center;gap:8px}
.check{width:18px;height:18px;border-radius:50%;background:var(--accent-soft);color:var(--accent);display:grid;place-items:center;flex:none;font-style:normal}
.check .icon{width:11px;height:11px;fill:none;stroke:currentColor;stroke-width:3}
.hero-v2-visual{display:flex;justify-content:center;align-items:center}
.hero-phone{position:relative;width:100%;max-width:320px;background:var(--card);border:1px solid var(--line);border-radius:32px;padding:14px;box-shadow:0 40px 80px -30px rgba(15,23,42,.35),0 0 0 8px var(--bg-soft);transform:rotate(-2deg);transition:transform .3s}
.hero-phone:hover{transform:rotate(0)}
.hero-phone-notch{width:100px;height:22px;background:var(--bg-soft);border-radius:0 0 14px 14px;margin:0 auto 6px}
.hero-phone-body{background:var(--bg-soft);border-radius:22px;padding:16px 14px;display:flex;flex-direction:column;gap:10px;min-height:360px}
.hp-balance{background:var(--grad);border-radius:16px;padding:16px;color:#fff;position:relative;overflow:hidden}
.hp-balance small{font-size:.6rem;letter-spacing:.14em;text-transform:uppercase;opacity:.85;font-weight:800;display:block}
.hp-balance div{font-size:1.4rem;font-weight:800;letter-spacing:-.03em;margin:4px 0}
.hp-balance span{font-size:.74rem;color:#bbf7d0;font-weight:700}
.hp-row{display:flex;justify-content:space-between;align-items:center;background:var(--card);border-radius:10px;padding:10px 12px;font-size:.78rem;font-weight:700;color:var(--muted)}
.hp-row span:last-child{color:var(--accent);font-weight:800}
.hp-card{background:var(--card);border-radius:12px;padding:10px 12px}
.hp-card-title{font-size:.62rem;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);font-weight:800;margin-bottom:6px}
.hp-feed{display:flex;flex-direction:column;gap:0;max-height:130px;overflow:hidden}
.hp-feed-row{display:flex;justify-content:space-between;align-items:center;font-size:.72rem;color:var(--text);font-weight:600;padding:6px 0;border-bottom:1px dashed var(--line)}
.hp-feed-row:last-child{border-bottom:none}
.hp-feed-row span{color:var(--muted);font-size:.64rem}
@keyframes pulse{70%{box-shadow:0 0 0 9px rgba(5,150,105,0)}100%{box-shadow:0 0 0 0 rgba(5,150,105,0)}}
.pill-live{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--accent);animation:pulse 2s infinite}

/* ──────── LANDING: STATS ──────── */
.stats-strip{background:var(--card);border-top:1px solid var(--line);border-bottom:1px solid var(--line);padding:clamp(28px,4vw,44px) 0}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:24px;text-align:center}
.stat{display:flex;flex-direction:column;gap:4px}
.stat b{font-size:clamp(1.4rem,2.4vw,2rem);font-weight:800;letter-spacing:-.03em;background:var(--grad);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent;color:transparent}
.stat span{font-size:.8rem;color:var(--muted);font-weight:600;letter-spacing:.02em}

/* ──────── LANDING: HOW ──────── */
.how-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:20px}
.how-step{position:relative;background:var(--card);border:1px solid var(--line);border-radius:20px;padding:32px 24px 28px;transition:.25s;overflow:hidden}
.how-step:hover{transform:translateY(-4px);border-color:#93c5fd;box-shadow:var(--shadow-lg)}
:root[data-theme="dark"] .how-step:hover{border-color:var(--primary)}
.how-num{position:absolute;top:16px;right:20px;font-size:3rem;font-weight:800;color:var(--line);letter-spacing:-.04em;line-height:1}
.how-ic{width:56px;height:56px;border-radius:16px;background:var(--grad);display:grid;place-items:center;color:#fff;margin-bottom:18px}
.how-ic .icon{width:26px;height:26px;fill:none;stroke:currentColor;stroke-width:2.2}
.how-step h3{font-size:1.15rem;font-weight:800;margin-bottom:8px;letter-spacing:-.01em}
.how-step p{color:var(--muted);font-size:.92rem;line-height:1.55}

/* ──────── LANDING: WHY ──────── */
.why-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:18px}
.why-card{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:26px 22px;transition:.2s}
.why-card:hover{border-color:#93c5fd;box-shadow:var(--shadow)}
:root[data-theme="dark"] .why-card:hover{border-color:var(--primary)}
.why-ic{width:44px;height:44px;border-radius:12px;display:grid;place-items:center;margin-bottom:14px;background:var(--bg-soft);color:var(--primary);border:1px solid var(--line)}
.why-ic .icon{width:22px;height:22px;fill:none;stroke:currentColor;stroke-width:2.2}
.why-card h3{font-size:1rem;font-weight:800;margin-bottom:6px}
.why-card p{color:var(--muted);font-size:.88rem;line-height:1.55}

/* ──────── LANDING: TESTIMONIALS ──────── */
.testi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:20px}
.testi-card{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:24px;display:flex;flex-direction:column;gap:16px;position:relative}
.testi-card::before{content:"\201C";position:absolute;top:-8px;left:18px;font-size:3rem;color:var(--line-strong);font-family:Georgia,serif;line-height:1}
.testi-quote{color:var(--text);font-size:.95rem;line-height:1.6;font-weight:500;padding-top:12px}
.testi-who{display:flex;align-items:center;gap:12px;border-top:1px solid var(--line);padding-top:14px}
.testi-av{width:38px;height:38px;border-radius:50%;background:var(--grad);color:#fff;display:grid;place-items:center;font-weight:800;font-size:.95rem;flex:none}
.testi-who b{display:block;font-size:.9rem}
.testi-who small{display:block;font-size:.76rem;color:var(--muted);margin-top:1px}

/* ──────── LANDING: FAQ ──────── */
.faq-list{max-width:760px;margin:0 auto;display:flex;flex-direction:column;gap:10px}
.faq-item{background:var(--card);border:1px solid var(--line);border-radius:14px;overflow:hidden;transition:.2s}
.faq-item[open]{border-color:#93c5fd;box-shadow:var(--shadow-sm)}
:root[data-theme="dark"] .faq-item[open]{border-color:var(--primary)}
.faq-item summary{list-style:none;padding:18px 22px;cursor:pointer;font-weight:700;font-size:.98rem;display:flex;align-items:center;justify-content:space-between;gap:12px}
.faq-item summary::-webkit-details-marker{display:none}
.faq-item summary::after{content:"+";font-size:1.4rem;font-weight:400;color:var(--muted);transition:transform .2s;flex:none;line-height:1}
.faq-item[open] summary::after{transform:rotate(45deg);color:var(--primary)}
.faq-item p{padding:0 22px 20px;color:var(--muted);font-size:.92rem;line-height:1.65}

/* ──────── LANDING: CTA BAND ──────── */
.cta-band{padding:clamp(56px,8vw,90px) 0;background:var(--grad);position:relative;overflow:hidden}
.cta-band::before{content:"";position:absolute;inset:0;background:radial-gradient(circle at 20% 20%,rgba(255,255,255,.15),transparent 40%),radial-gradient(circle at 80% 80%,rgba(255,255,255,.12),transparent 40%);pointer-events:none}
.cta-inner{text-align:center;position:relative;color:#fff;max-width:640px;margin:0 auto}
.cta-inner h2{font-size:clamp(1.8rem,4vw,2.6rem);font-weight:800;letter-spacing:-.03em;margin-bottom:12px;line-height:1.1}
.cta-inner p{font-size:1rem;opacity:.9;margin-bottom:28px}
.cta-inner .btn{background:#fff;color:#1e3a8a;box-shadow:0 12px 30px -8px rgba(0,0,0,.3)}
.cta-inner .btn:hover{background:#f8fafc;transform:translateY(-1px)}

/* ──────── CARDS, FORMS, PANELS (used across pages) ──────── */
.grid-3{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:22px}
.grid-2{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:22px}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius-lg);padding:26px;transition:.25s}
.card:hover{border-color:#93c5fd;box-shadow:var(--shadow);transform:translateY(-3px)}
.card h3{font-size:1.02rem;font-weight:700;margin-bottom:6px;display:flex;align-items:center;gap:8px}.card p{color:var(--muted);font-size:.9rem}
.step-num{display:inline-grid;place-items:center;width:40px;height:40px;border-radius:12px;margin-bottom:16px;font-weight:800;color:#fff;background:var(--grad)}.step-num .icon{width:20px;height:20px;fill:none;stroke:currentColor;stroke-width:2.2}
.panel{background:var(--card);border:1px solid var(--line);border-radius:var(--radius-lg);padding:clamp(22px,3.5vw,34px);box-shadow:var(--shadow-sm)}
.panel h3{font-size:1.05rem;font-weight:700;margin-bottom:10px;display:flex;align-items:center;gap:8px}.panel>p{color:var(--muted);font-size:.93rem}
.panel-accent{background:linear-gradient(150deg,rgba(239,246,255,.6),rgba(236,253,245,.6));border-color:#bfdbfe}
:root[data-theme="dark"] .panel-accent{background:linear-gradient(150deg,rgba(30,64,175,.15),rgba(15,118,110,.15))}
.form-stack{display:flex;flex-direction:column;gap:12px}
.form-stack input,.form-stack textarea{width:100%;padding:14px 18px;border-radius:10px;border:1px solid var(--line-strong);background:var(--card);color:var(--text);outline:none;transition:.2s}
.form-stack input:focus,.form-stack textarea:focus{border-color:var(--primary);box-shadow:0 0 0 4px rgba(29,78,216,.1)}
.auth-msg{font-size:.86rem;margin-top:14px;min-height:20px;font-weight:600;color:var(--accent)}.auth-msg.err{color:var(--red)}.auth-msg.warn{color:var(--amber)}
.auth-wrap{max-width:440px;margin:0 auto;width:100%}
.auth-card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius-lg);padding:clamp(26px,4vw,40px);box-shadow:var(--shadow-lg)}
.auth-card h1{font-size:1.55rem;font-weight:800;margin-bottom:6px}.auth-card .sub{color:var(--muted);font-size:.92rem;margin-bottom:24px}
.auth-alt{margin-top:18px;font-size:.88rem;color:var(--muted);text-align:center}.auth-alt a{color:var(--primary);font-weight:700}
.merchant-box{display:flex;align-items:center;gap:12px;background:var(--card);border:1px dashed #93c5fd;border-radius:12px;padding:11px 14px;margin:14px 0}
.merchant-box .mb-label{font-size:.62rem;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);font-weight:800;flex:none;line-height:1.2}
.merchant-box .mb-value{flex:1;font-family:var(--mono);font-size:1.25rem;font-weight:800;letter-spacing:.18em;color:var(--primary-deep);text-align:center}
.merchant-box .mb-copy{flex:none;padding:6px 12px;border-radius:7px;background:var(--primary);color:#fff;font-weight:800;font-size:.72rem;display:inline-flex;align-items:center;gap:5px}
.merchant-box .mb-copy .icon{width:12px;height:12px;fill:none;stroke:currentColor;stroke-width:2.4}
.pay-steps{display:grid;gap:10px;margin-top:14px}.pay-step{display:flex;gap:12px;align-items:flex-start;background:var(--card);border:1px solid var(--line);border-radius:11px;padding:12px 14px}
.pay-step-num{width:27px;height:27px;border-radius:50%;flex:none;background:var(--grad);color:#fff;font-weight:800;font-size:.78rem;display:grid;place-items:center}
.pay-step b{display:block;font-size:.9rem;line-height:1.35}.pay-step .desc{display:block;font-size:.8rem;color:var(--muted);margin-top:2px}
.pay-step code{font-family:var(--mono);background:rgba(59,130,246,.1);color:var(--primary-deep);padding:1px 7px;border-radius:4px;font-weight:800;border:1px solid rgba(59,130,246,.25)}

/* ──────── DASHBOARD ──────── */
.dash-container{max-width:860px;padding-bottom:clamp(60px,10vw,100px)}
.dash-topbar{position:sticky;top:72px;z-index:50;background:color-mix(in srgb,var(--bg) 95%,transparent);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border-bottom:1px solid var(--line);display:flex;align-items:center;gap:10px;padding:10px 0;margin-bottom:16px}
.dash-topbar .dash-burger{width:42px;height:42px;border-radius:11px;background:var(--bg-soft);border:1px solid var(--line);display:grid;place-items:center;flex:none;transition:.15s}
.dash-topbar .dash-burger:hover{background:var(--card);border-color:var(--line-strong)}
.dash-topbar .dash-burger .icon{width:20px;height:20px;fill:none;stroke:var(--text);stroke-width:2.4}
.dash-topbar .dash-ttl{flex:1;min-width:0;font-weight:800;font-size:1.02rem;letter-spacing:-.01em;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dash-topbar .dash-bell{position:relative;width:42px;height:42px;border-radius:11px;background:var(--bg-soft);border:1px solid var(--line);display:grid;place-items:center;flex:none;transition:.15s}
.dash-topbar .dash-bell:hover{background:var(--card);border-color:var(--line-strong)}
.dash-topbar .dash-bell .icon{width:20px;height:20px;fill:none;stroke:var(--text);stroke-width:2.2}
.dash-topbar .dash-bell .dash-bell-badge{position:absolute;top:-4px;right:-4px;min-width:18px;height:18px;padding:0 5px;border-radius:9px;background:var(--red);color:#fff;font-size:.66rem;font-weight:800;line-height:18px;text-align:center;display:none}
.dash-topbar .dash-bell .dash-bell-badge.on{display:inline-block;animation:bellpop .4s ease}
@keyframes bellpop{0%{transform:scale(0)}60%{transform:scale(1.2)}100%{transform:scale(1)}}
.dash-drawer-overlay{position:fixed;inset:0;background:rgba(15,23,42,.45);opacity:0;pointer-events:none;transition:opacity .25s;z-index:200}
.dash-drawer-overlay.open{opacity:1;pointer-events:auto}
.dash-drawer{position:fixed;top:0;left:0;bottom:0;width:290px;max-width:82vw;background:var(--card);box-shadow:4px 0 30px rgba(15,23,42,.25);transform:translateX(-100%);transition:transform .28s cubic-bezier(.22,1,.36,1);z-index:201;display:flex;flex-direction:column;padding:20px 16px}
.dash-drawer.open{transform:translateX(0)}
.dash-drawer-head{display:flex;align-items:center;gap:12px;padding-bottom:16px;border-bottom:1px solid var(--line);margin-bottom:14px}
.dash-avatar{width:44px;height:44px;border-radius:12px;background:var(--grad);color:#fff;display:grid;place-items:center;font-weight:800;font-size:1.05rem;flex:none}
.dash-drawer-head b{display:block;font-size:.98rem;font-weight:800;line-height:1.2}
.dash-drawer-head small{display:block;font-size:.78rem;color:var(--muted);margin-top:2px}
.dash-drawer-nav{display:flex;flex-direction:column;gap:4px;flex:1;overflow-y:auto}
.dash-drawer-nav a{display:flex;align-items:center;gap:12px;padding:12px 12px;border-radius:10px;color:var(--text);font-weight:600;font-size:.92rem;transition:.15s;position:relative}
.dash-drawer-nav a:hover{background:var(--bg-soft)}
.dash-drawer-nav a .dn-ic{width:34px;height:34px;border-radius:9px;display:grid;place-items:center;flex:none;color:#fff}
.dash-drawer-nav a .dn-ic .icon{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:2.2}
.dash-drawer-nav .dn-badge{margin-left:auto;min-width:18px;height:18px;padding:0 5px;border-radius:9px;background:var(--red);color:#fff;font-size:.66rem;font-weight:800;line-height:18px;text-align:center;display:none}
.dash-drawer-nav .dn-badge.on{display:inline-block}
.dash-drawer-foot{padding-top:14px;border-top:1px solid var(--line);margin-top:14px}
.dash-quicknav{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:22px}
@media (min-width:640px){.dash-quicknav{grid-template-columns:repeat(6,1fr)}}
.qn-item{display:flex;flex-direction:column;align-items:center;gap:8px;padding:14px 6px;background:var(--card);border:1px solid var(--line);border-radius:14px;transition:.18s;text-align:center;min-width:0}
.qn-item:hover{border-color:#93c5fd;box-shadow:var(--shadow-sm);transform:translateY(-2px)}
.qn-item .qn-icon{width:44px;height:44px;border-radius:12px;display:grid;place-items:center;color:#fff;position:relative;flex:none}
.qn-item .qn-icon .icon{width:22px;height:22px;fill:none;stroke:currentColor;stroke-width:2.2}
.qn-item .qn-badge{position:absolute;top:-4px;right:-4px;min-width:18px;height:18px;padding:0 5px;border-radius:9px;background:var(--red);color:#fff;font-size:.66rem;font-weight:800;line-height:18px;text-align:center;display:none}
.qn-item .qn-badge.on{display:inline-block}
.qn-item span{font-size:.74rem;font-weight:700;color:var(--text-soft);letter-spacing:.01em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%}
.banner-ad{display:block;width:100%;height:60px;border-radius:12px;overflow:hidden;margin-bottom:14px;position:relative;background:var(--bg-soft);border:1px solid var(--line);transition:.2s}
.banner-ad:hover{transform:translateY(-1px);box-shadow:var(--shadow);border-color:#93c5fd}
.banner-ad img{width:100%;height:100%;object-fit:cover;display:block}
.banner-ad .bn-label{position:absolute;top:4px;right:8px;font-size:.6rem;font-weight:800;letter-spacing:.1em;text-transform:uppercase;background:rgba(0,0,0,.55);color:#fff;padding:2px 6px;border-radius:4px}
@media (min-width:768px){.banner-ad{height:80px}}
.dash-head{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;flex-wrap:wrap;padding-bottom:18px}
.dash-head h1{font-size:clamp(1.55rem,3.4vw,2.1rem);font-weight:800;letter-spacing:-.025em;margin:8px 0 6px;word-break:break-word}.dash-head p{color:var(--muted);font-size:.94rem;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.status-active{display:inline-flex;align-items:center;gap:7px;background:var(--accent-soft);color:#065f46;padding:3px 11px;border-radius:999px;font-weight:800;font-size:.78rem}
:root[data-theme="dark"] .status-active{color:#6ee7b7}
.status-active::before{content:"";width:8px;height:8px;border-radius:50%;background:var(--accent);animation:pulse 2s infinite}
.status-pending{background:rgba(245,158,11,.15);color:#92400e}.status-pending::before{background:#f59e0b}
:root[data-theme="dark"] .status-pending{color:#fbbf24}
.status-online{display:inline-flex;align-items:center;gap:7px;background:rgba(16,185,129,.15);color:#047857;border:1px solid rgba(16,185,129,.3);padding:3px 11px;border-radius:999px;font-weight:800;font-size:.78rem}
:root[data-theme="dark"] .status-online{color:#6ee7b7}
.status-online::before{content:"";width:8px;height:8px;border-radius:50%;background:#10b981;box-shadow:0 0 0 3px rgba(16,185,129,.25);animation:pulse 2s infinite}
.online-dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#10b981;box-shadow:0 0 0 3px rgba(16,185,129,.2);margin-right:6px;vertical-align:middle}
.offline-dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:#cbd5e1;margin-right:6px;vertical-align:middle}
.dash-balance-card{position:relative;overflow:hidden;border-radius:26px;padding:clamp(22px,4vw,36px);color:#fff;background:radial-gradient(130% 140% at 0% 0%,rgba(255,255,255,.22),transparent 55%),linear-gradient(150deg,#1e40af,#0f766e);box-shadow:0 30px 70px -30px rgba(30,64,175,.55)}
.dash-live{display:inline-flex;align-items:center;gap:7px;background:rgba(0,0,0,.25);border:1px solid rgba(255,255,255,.25);padding:5px 12px;border-radius:999px;font-size:.68rem;font-weight:800;letter-spacing:.12em;text-transform:uppercase}
.dash-live i{width:8px;height:8px;border-radius:50%;background:#4ade80;animation:pulse 2s infinite}
.dash-balance-card small{display:block;margin-top:16px;font-size:.72rem;letter-spacing:.12em;text-transform:uppercase;color:rgba(255,255,255,.8);font-weight:800}
.dash-balance{font-size:clamp(1.8rem,6vw,3rem);font-weight:800;letter-spacing:-.03em;line-height:1.05;margin:6px 0;font-variant-numeric:tabular-nums;word-break:break-word}
.dash-panel{background:var(--card);border:1px solid var(--line);border-radius:var(--radius-lg);padding:clamp(20px,3.5vw,30px);box-shadow:var(--shadow-sm);scroll-margin-top:140px}
.dash-panel h3{font-size:1.05rem;font-weight:800;margin-bottom:4px;display:flex;align-items:center;gap:8px}
.dash-panel h3 .icon{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:2.2;color:var(--primary);flex:none}
.dash-panel .sub{color:var(--muted);font-size:.86rem;margin-bottom:16px}
.video-head{display:flex;align-items:flex-start;justify-content:space-between;gap:14px;flex-wrap:wrap;margin-bottom:14px}
.video-head>div{min-width:0}
.video-frame{position:relative;width:100%;aspect-ratio:16/9;background:#0f172a;border-radius:14px;overflow:hidden;border:1px solid var(--line)}
.video-frame>div,.video-frame iframe{position:absolute;inset:0;width:100%;height:100%;border:0}
.video-frame .placeholder{position:absolute;inset:0;display:grid;place-items:center;color:rgba(255,255,255,.7);font-size:.88rem;font-weight:600;text-align:center;padding:20px}
.video-status{margin-top:12px;font-size:.85rem;font-weight:700;padding:9px 14px;border-radius:10px;background:var(--bg-soft);border:1px solid var(--line);display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.video-status .icon{width:14px;height:14px;fill:none;stroke:currentColor;stroke-width:2.4;flex:none}
.video-status.playing{background:rgba(59,130,246,.1);border-color:rgba(59,130,246,.3);color:var(--primary-deep)}
.video-status.paused{background:rgba(245,158,11,.1);border-color:rgba(245,158,11,.3);color:#92400e}
:root[data-theme="dark"] .video-status.paused{color:#fbbf24}
.video-status.earned{background:var(--accent-soft);border-color:rgba(16,185,129,.3);color:#065f46}
:root[data-theme="dark"] .video-status.earned{color:#6ee7b7}
.video-progress{display:none;margin-top:10px;height:7px;border-radius:999px;background:var(--line);overflow:hidden}.video-progress.on{display:block}
.video-progress i{display:block;height:100%;width:0;border-radius:999px;background:var(--grad);transition:width .4s linear}
.video-guard{display:flex;align-items:flex-start;gap:7px;font-size:.78rem;color:var(--muted);margin-top:10px}.video-guard .icon{width:14px;height:14px;flex:none;margin-top:2px;fill:none;stroke:currentColor;stroke-width:2.2;color:var(--accent)}
.video-list{display:grid;gap:12px}.video-card{display:flex;gap:14px;align-items:center;padding:12px;border:1px solid var(--line);border-radius:14px;background:var(--card);min-width:0}
.video-card .thumb-wrap{position:relative;flex:none;width:132px;aspect-ratio:16/9;border-radius:10px;overflow:hidden;background:#0f172a}
.video-card .thumb{width:100%;height:100%;object-fit:cover}
.video-card .meta{flex:1;min-width:0}.video-card .meta b{display:block;font-size:.92rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.video-card .meta small{display:flex;align-items:center;gap:6px;flex-wrap:wrap;font-size:.78rem;color:var(--muted);margin-top:4px}.video-card .meta .reward{color:var(--accent);font-weight:800}
.video-card.watching{border-color:var(--accent);background:rgba(16,185,129,.06)}.video-card.earned{opacity:.7}
.watch-btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;padding:10px 18px;border-radius:9px;background:var(--grad);color:#fff;font-weight:700;font-size:.82rem;white-space:nowrap}
:root[data-theme="dark"] .watch-btn{color:#0a0f1c;font-weight:800}
.watch-btn.playing{background:var(--card);color:var(--primary);border:1px solid var(--line-strong)}
:root[data-theme="dark"] .watch-btn.playing{color:var(--primary)}
.watch-btn.earned{background:var(--accent-soft);color:#065f46;border:1px solid rgba(16,185,129,.3);cursor:default;opacity:.85}
:root[data-theme="dark"] .watch-btn.earned{color:#6ee7b7}
.video-reward{display:inline-flex;align-items:center;gap:6px;background:var(--accent-soft);color:#065f46;padding:5px 12px;border-radius:999px;font-weight:800;font-size:.8rem;white-space:nowrap;border:1px solid rgba(16,185,129,.3);flex:none}
:root[data-theme="dark"] .video-reward{color:#6ee7b7}
.video-reward .icon{width:12px;height:12px;fill:none;stroke:currentColor;stroke-width:2.4}
.withdraw-info{display:flex;gap:12px;align-items:center;justify-content:space-between;flex-wrap:wrap;background:rgba(59,130,246,.08);border:1px solid rgba(59,130,246,.25);border-radius:12px;padding:12px 14px;margin-bottom:14px}
.withdraw-info .wi-lbl{font-size:.7rem;font-weight:800;letter-spacing:.1em;text-transform:uppercase;color:var(--primary);flex:none}
.withdraw-info .wi-val{font-family:var(--mono);font-weight:800;font-size:1rem;color:var(--primary-deep)}
.withdraw-info .wi-min{font-size:.78rem;color:var(--muted)}
.withdraw-form{display:flex;gap:10px;flex-wrap:wrap;align-items:stretch}
.withdraw-form input{flex:1;min-width:180px;padding:13px 16px;border-radius:10px;border:1px solid var(--line-strong);background:var(--card);color:var(--text);outline:none;font-size:1rem}
.withdraw-form input:focus{border-color:var(--primary);box-shadow:0 0 0 4px rgba(29,78,216,.1)}
.withdraw-form button{flex:none}
.withdraw-note{display:flex;align-items:flex-start;gap:8px;font-size:.82rem;color:#92400e;background:rgba(245,158,11,.12);border:1px solid rgba(245,158,11,.35);border-radius:10px;padding:10px 14px;margin-top:12px;line-height:1.45}
:root[data-theme="dark"] .withdraw-note{color:#fbbf24}
.withdraw-note .icon{width:15px;height:15px;flex:none;margin-top:1px;fill:none;stroke:currentColor;stroke-width:2.4}
.withdraw-history{margin-top:14px;display:flex;flex-direction:column;gap:8px}
.wd-row{display:flex;gap:10px;justify-content:space-between;align-items:flex-start;padding:11px 14px;border:1px solid var(--line);border-radius:10px;background:var(--card);flex-wrap:wrap}
.wd-row.pending{border-left:3px solid #f59e0b}.wd-row.approved{border-left:3px solid #059669;background:rgba(16,185,129,.04)}.wd-row.rejected{border-left:3px solid #dc2626;background:rgba(220,38,38,.04)}
.wd-row .wd-amt{font-family:var(--mono);font-weight:800;color:var(--text)}
.wd-row small{display:block;font-size:.76rem;color:var(--muted);margin-top:2px}
.ref-display{display:flex;flex-direction:column;gap:12px;padding:16px;background:linear-gradient(135deg,rgba(59,130,246,.08),rgba(16,185,129,.08));border:1px dashed rgba(59,130,246,.4);border-radius:14px;margin-bottom:14px}
.ref-code-label{font-size:.68rem;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);font-weight:800;margin-bottom:4px}
.ref-code-value{font-family:var(--mono);font-size:1.5rem;font-weight:800;letter-spacing:.18em;color:var(--primary-deep);word-break:break-all;line-height:1.15}
.ref-display .btn{width:100%;justify-content:center}
.ref-stats{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:14px}
.ref-stat{background:var(--bg-soft);border:1px solid var(--line);border-radius:10px;padding:10px 12px;text-align:center}
.ref-stat .v{font-size:1.15rem;font-weight:800;color:var(--primary);font-variant-numeric:tabular-nums}
.ref-stat .l{font-size:.68rem;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);font-weight:800;margin-top:2px}
.ref-msg{font-size:.86rem;color:var(--muted);padding:10px 14px;background:rgba(16,185,129,.06);border:1px solid rgba(16,185,129,.25);border-radius:10px;margin-top:4px}
.ref-msg b{color:var(--accent)}
.ref-pill{display:inline-flex;align-items:center;gap:6px;background:rgba(245,158,11,.12);color:#92400e;border:1px solid rgba(245,158,11,.35);padding:4px 10px;border-radius:999px;font-weight:800;font-size:.74rem;white-space:nowrap}
:root[data-theme="dark"] .ref-pill{color:#fbbf24}
.pw-section{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.pw-section input{width:100%;padding:12px 16px;border-radius:10px;border:1px solid var(--line-strong);background:var(--card);color:var(--text);outline:none}
.pw-section input:focus{border-color:var(--primary);box-shadow:0 0 0 4px rgba(29,78,216,.1)}
.notif-banner{display:none;margin-top:12px;padding:11px 14px;background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.35);border-radius:10px;font-size:.85rem;color:#92400e;align-items:center;gap:10px;flex-wrap:wrap;line-height:1.45}
:root[data-theme="dark"] .notif-banner{color:#fbbf24}
.notif-banner.show{display:flex}
.notif-banner.denied{background:rgba(220,38,38,.1);border-color:rgba(220,38,38,.35);color:#991b1b}
:root[data-theme="dark"] .notif-banner.denied{color:#f87171}
.notif-banner .nb-ic{width:18px;height:18px;flex:none;fill:none;stroke:currentColor;stroke-width:2.2}
.notif-banner .nb-tx{flex:1;min-width:180px}
.notif-banner .nb-tx b{display:block;color:inherit;font-weight:800;margin-bottom:2px}
.notif-banner .nb-btn{flex:none;padding:8px 14px;border-radius:8px;background:var(--amber);color:#fff;font-weight:700;font-size:.82rem;display:inline-flex;align-items:center;gap:6px;cursor:pointer;transition:.15s}
.notif-banner .nb-btn:hover{filter:brightness(1.1)}
.notif-banner.active{background:rgba(16,185,129,.1);border-color:rgba(16,185,129,.35);color:#047857}
:root[data-theme="dark"] .notif-banner.active{color:#6ee7b7}
.notif-banner.active .nb-btn{display:none}

/* ──────── ADMIN ──────── */
.admin-shell{max-width:1100px;padding-bottom:clamp(40px,6vw,80px)}
.admin-header{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;flex-wrap:wrap;padding-top:clamp(28px,5vw,48px);margin-bottom:22px}
.admin-header h1{font-size:clamp(1.6rem,3.6vw,2.2rem);font-weight:800;margin:8px 0 6px}.admin-header p{color:var(--muted);font-size:.94rem;max-width:560px}
.admin-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:22px}
.admin-kpi{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px 16px;box-shadow:var(--shadow-sm)}
.admin-kpi .k{font-size:.66rem;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);font-weight:800}
.admin-kpi .v{font-size:1.4rem;font-weight:800;letter-spacing:-.03em;margin-top:6px;line-height:1.1;font-variant-numeric:tabular-nums;word-break:break-word}
.admin-kpi .s{font-size:.72rem;color:var(--muted);margin-top:2px}
.admin-kpi.online .v{color:var(--accent)}
.admin-section{margin-bottom:22px}
.video-publish-form{display:grid;grid-template-columns:2fr 2fr 1fr auto;gap:10px;align-items:end;margin-top:14px}
.video-publish-form .field{display:flex;flex-direction:column;gap:4px}.video-publish-form label{font-size:.72rem;font-weight:800;color:var(--text-soft)}
.video-publish-form input{padding:11px 14px;border-radius:9px;border:1px solid var(--line-strong);background:var(--card);color:var(--text);outline:none}
.admin-table-wrap{overflow-x:auto;margin-top:12px;border:1px solid var(--line);border-radius:12px;-webkit-overflow-scrolling:touch}
.admin-table{width:100%;border-collapse:collapse;font-size:.86rem}
.admin-table th{text-align:left;font-size:.66rem;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);font-weight:800;padding:10px 14px;background:var(--bg-soft);border-bottom:1px solid var(--line);white-space:nowrap}
.admin-table td{padding:12px 14px;border-bottom:1px solid var(--line);vertical-align:middle}.admin-table tr:last-child td{border-bottom:none}
.admin-table b{color:var(--text);font-weight:700}.admin-table .mono{font-family:var(--mono);font-size:.82rem}
.admin-table .thumb-sm{width:70px;aspect-ratio:16/9;border-radius:6px;object-fit:cover;background:#000}
.user-toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:14px}
.user-select{padding:12px 16px;border-radius:10px;border:1px solid var(--line-strong);background:var(--card);color:var(--text);outline:none;font-weight:600;font-size:.88rem}
.user-actions{display:flex;gap:6px;flex-wrap:wrap}
.mini-btn{padding:5px 10px;border-radius:6px;font-size:.72rem;font-weight:800;border:1px solid var(--line-strong);background:var(--card);color:var(--text-soft);white-space:nowrap;cursor:pointer}
.mini-btn:hover{background:var(--bg-soft);border-color:var(--primary);color:var(--primary)}
.mini-btn.bad{border-color:rgba(220,38,38,.4);color:#991b1b}.mini-btn.good{border-color:rgba(22,163,74,.4);color:#166534}.mini-btn.warn{border-color:rgba(234,88,12,.4);color:#9a3412}
:root[data-theme="dark"] .mini-btn.bad{color:#f87171}
:root[data-theme="dark"] .mini-btn.good{color:#6ee7b7}
:root[data-theme="dark"] .mini-btn.warn{color:#fdba74}
.badge{display:inline-flex;align-items:center;gap:5px;padding:3px 9px;border-radius:999px;font-size:.7rem;font-weight:800;white-space:nowrap}
.badge-live{background:var(--accent-soft);color:#065f46}.badge-live::before{content:"";width:6px;height:6px;border-radius:50%;background:var(--accent)}
:root[data-theme="dark"] .badge-live{color:#6ee7b7}
.badge-pending{background:rgba(245,158,11,.15);color:#92400e}.badge-warn{background:rgba(249,115,22,.15);color:#9a3412}.badge-danger{background:rgba(220,38,38,.15);color:#991b1b}.badge-new{background:rgba(59,130,246,.15);color:#1e40af}
:root[data-theme="dark"] .badge-pending{color:#fbbf24}
:root[data-theme="dark"] .badge-warn{color:#fb923c}
:root[data-theme="dark"] .badge-danger{color:#f87171}
:root[data-theme="dark"] .badge-new{color:#93c5fd}
.empty-state{padding:28px 20px;text-align:center;color:var(--muted);font-size:.9rem;border:1px dashed var(--line-strong);border-radius:12px;background:var(--bg-soft)}
.chat{display:flex;flex-direction:column;gap:10px;max-height:460px;overflow-y:auto;padding:14px;background:var(--bg-soft);border:1px solid var(--line);border-radius:12px;margin-bottom:12px}
.chat:empty{display:none}
.msg{max-width:80%;padding:10px 14px;border-radius:12px;font-size:.9rem;line-height:1.4;word-wrap:break-word}
.msg.them{background:var(--card);border:1px solid var(--line);border-bottom-left-radius:4px;align-self:flex-start}
.msg.me{background:var(--grad);color:#fff;border-bottom-right-radius:4px;align-self:flex-end}
:root[data-theme="dark"] .msg.me{color:#0a0f1c;font-weight:600}
.msg-meta{display:block;font-size:.68rem;opacity:.7;margin-top:4px}
.chat-input{display:flex;gap:8px}.chat-input input{flex:1;min-width:0;padding:12px 16px;border-radius:10px;border:1px solid var(--line-strong);background:var(--card);color:var(--text);outline:none}
.chat-input input:focus{border-color:var(--primary);box-shadow:0 0 0 4px rgba(29,78,216,.1)}
.announcement{padding:14px 16px;background:rgba(59,130,246,.08);border:1px solid rgba(59,130,246,.25);border-radius:12px;margin-bottom:10px}
.announcement.unread{background:linear-gradient(135deg,rgba(59,130,246,.1),rgba(245,158,11,.08));border-color:rgba(251,191,36,.5)}
.announcement h4{font-size:.95rem;font-weight:800;margin-bottom:4px;display:flex;align-items:center;gap:8px}
.announcement p{font-size:.86rem;color:var(--text-soft);line-height:1.5;white-space:pre-wrap}
.announcement .when{font-size:.72rem;color:var(--muted);margin-top:6px}
.req-row{display:flex;gap:10px;align-items:flex-start;padding:12px 14px;border:1px solid var(--line);border-radius:10px;background:var(--card);margin-bottom:8px;flex-wrap:wrap}
.req-row b{font-size:.9rem;color:var(--text)}.req-row small{font-size:.76rem;color:var(--muted);display:block;margin-top:2px;word-break:break-word}
.req-row.pending{border-left:3px solid #f59e0b}.req-row.resolved{border-left:3px solid #059669;background:rgba(16,185,129,.04)}
.conv-row{display:flex;align-items:center;gap:10px;padding:10px 12px;border:1px solid var(--line);border-radius:10px;background:var(--card);margin-bottom:6px;cursor:pointer;transition:.15s}
.conv-row:hover{background:var(--bg-soft);border-color:var(--line-strong)}
.conv-row.selected{background:rgba(59,130,246,.1);border-color:var(--primary)}
.conv-row .name{font-weight:700;font-size:.9rem;flex:0 0 110px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.conv-row .preview{flex:1;min-width:0;color:var(--muted);font-size:.82rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.conv-row .unread{background:var(--red);color:#fff;font-size:.68rem;font-weight:800;padding:2px 7px;border-radius:9px;flex:none}
.banner-form{display:grid;grid-template-columns:2fr 2fr 1fr;gap:10px;margin-top:14px}
.banner-form input{padding:11px 14px;border-radius:9px;border:1px solid var(--line-strong);background:var(--card);color:var(--text);outline:none;font-size:.9rem}
.banner-form input:focus{border-color:var(--primary);box-shadow:0 0 0 4px rgba(29,78,216,.1)}
.banner-form .btn{grid-column:1/-1;justify-self:start}
@media (max-width:640px){.banner-form{grid-template-columns:1fr}}
.banner-card{display:flex;gap:12px;align-items:center;padding:12px;border:1px solid var(--line);border-radius:10px;background:var(--card);margin-bottom:8px;flex-wrap:wrap}
.banner-card.inactive{opacity:.65}
.banner-card .bc-thumb{flex:none;width:140px;height:50px;border-radius:6px;overflow:hidden;background:var(--bg-soft);border:1px solid var(--line)}
.banner-card .bc-thumb img{width:100%;height:100%;object-fit:cover}
.banner-card .bc-meta{flex:1;min-width:180px}
.banner-card .bc-meta b{display:block;font-size:.86rem;color:var(--text)}
.banner-card .bc-meta small{display:block;font-size:.72rem;color:var(--muted);margin-top:2px;word-break:break-all}
.banner-card .bc-actions{display:flex;gap:6px;flex-wrap:wrap}

/* Leaderboard + challenges */
.lb-row{display:flex;align-items:center;gap:12px;padding:10px 14px;border:1px solid var(--line);border-radius:10px;background:var(--card);margin-bottom:6px}
.lb-row.me{background:rgba(59,130,246,.08);border-color:rgba(59,130,246,.35)}
.lb-rank{flex:0 0 46px;font-weight:800;font-size:.92rem;color:var(--muted);text-align:center}
.lb-name{flex:1;min-width:0;font-weight:700;font-size:.9rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.lb-amt{flex:none;font-family:var(--mono);font-weight:800;color:var(--accent);font-size:.86rem}
.challenge-card{border:1px solid var(--line);border-radius:14px;padding:14px 16px;background:var(--card);margin-bottom:10px}
.challenge-card .ch-head{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}
.challenge-card .ch-head b{font-size:.95rem}
.challenge-card p{font-size:.84rem;color:var(--muted);margin:6px 0 10px}
.ch-progress{height:8px;border-radius:999px;background:var(--line);overflow:hidden;margin-bottom:10px}
.ch-progress i{display:block;height:100%;border-radius:999px;background:var(--grad);transition:width .4s}
.ch-foot{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}
.ch-foot small{font-size:.78rem;color:var(--muted);font-weight:700}
.ch-form-row{display:grid;grid-template-columns:1.2fr .8fr .8fr auto;gap:10px;align-items:end}
.toggle-row{display:flex;align-items:center;gap:14px;cursor:pointer;margin-top:14px;padding:14px 16px;border:1px solid var(--line);border-radius:12px;background:var(--bg-soft)}
.toggle-row input{position:absolute;opacity:0;pointer-events:none}
.toggle-track{flex:none;width:52px;height:30px;border-radius:999px;background:var(--line-strong);position:relative;transition:.2s}
.toggle-thumb{position:absolute;top:3px;left:3px;width:24px;height:24px;border-radius:50%;background:#fff;box-shadow:0 1px 4px rgba(15,23,42,.3);transition:.2s}
.toggle-row input:checked + .toggle-track{background:var(--accent)}
.toggle-row input:checked + .toggle-track .toggle-thumb{left:25px}
.toggle-row .tg-txt{flex:1;min-width:0}
.toggle-row .tg-txt b{display:block;font-size:.9rem}
.toggle-row .tg-txt small{display:block;font-size:.78rem;color:var(--muted);margin-top:2px}
.mon-list{display:flex;flex-direction:column;gap:6px;max-height:300px;overflow-y:auto}
.mon-row{display:flex;align-items:center;gap:10px;padding:9px 12px;border:1px solid var(--line);border-radius:9px;background:var(--card);font-size:.82rem}
.mon-row .mon-main{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.mon-row .mon-time{flex:none;font-size:.7rem;color:var(--muted);font-family:var(--mono)}
.mon-row b{font-weight:800}

/* Footer */
footer{border-top:1px solid var(--line);padding:52px 0 30px;background:var(--bg-soft)}
.foot-grid{display:grid;grid-template-columns:1.6fr repeat(3,1fr);gap:36px}
.foot-brand p{color:var(--muted);font-size:.88rem;margin-top:14px;max-width:280px}
.foot-col h4{font-size:.78rem;text-transform:uppercase;letter-spacing:.12em;margin-bottom:16px;font-weight:700}
.foot-col a{display:flex;align-items:center;gap:7px;color:var(--muted);font-size:.88rem;padding:6px 0}.foot-col a:hover{color:var(--primary)}
.foot-bottom{margin-top:40px;padding-top:22px;border-top:1px solid var(--line);display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;font-size:.8rem;color:var(--muted)}

/* Responsive */
@media (max-width:980px){
  .hero-v2-inner{grid-template-columns:1fr;gap:40px}
  .hero-v2-visual{order:-1}
  .foot-grid{grid-template-columns:1fr 1fr;gap:32px}
  .foot-brand{grid-column:1/-1}
}
@media (max-width:820px){
  .nav-links,.nav-cta .btn-ghost{display:none}
  .burger{display:grid}
  .video-publish-form{grid-template-columns:1fr}
}
@media (max-width:640px){
  .container{padding-inline:18px}
  .hero-phone{max-width:280px;transform:none}
  .hero-v2 h1{font-size:2.1rem}
  .hero-v2-actions .btn{flex:1;justify-content:center;padding:14px 18px;font-size:.92rem}
  .hero-v2-trust{gap:10px 18px;font-size:.8rem}
  .stats-grid{grid-template-columns:1fr 1fr;gap:20px}
  .ch-form-row{grid-template-columns:1fr}
  .lb-rank{flex-basis:36px}.lb-amt{font-size:.8rem}
  .dash-container{padding-inline:14px}
  .dash-topbar{top:72px;margin-bottom:12px}
  .dash-head{flex-direction:column;align-items:stretch;gap:10px;padding-bottom:14px}
  .dash-head h1{font-size:1.5rem;margin:4px 0}
  .dash-head p{font-size:.86rem}
  .dash-balance-card{border-radius:18px;padding:20px}
  .dash-balance{font-size:1.9rem}
  .dash-live{font-size:.6rem;padding:4px 10px}
  .dash-balance-card small{margin-top:12px}
  .dash-panel{border-radius:16px;padding:16px;scroll-margin-top:150px}
  .dash-panel h3{font-size:.98rem}
  .dash-panel .sub{font-size:.8rem;margin-bottom:12px}
  .video-head{flex-direction:column;align-items:stretch;gap:8px}
  .video-reward{align-self:flex-start;font-size:.76rem}
  .video-card{flex-direction:column;align-items:stretch;padding:10px}
  .video-card .thumb-wrap{width:100%;aspect-ratio:16/9;border-radius:8px}
  .video-card .meta b{white-space:normal;line-height:1.3;font-size:.88rem;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
  .video-card .actions{width:100%}
  .watch-btn{width:100%;padding:9px 14px;font-size:.8rem}
  .video-status{font-size:.8rem}
  .video-guard{font-size:.74rem}
  .withdraw-info{padding:10px 12px}
  .withdraw-info .wi-val{font-size:.9rem}
  .withdraw-form input, .withdraw-form button{width:100%;flex-basis:100%}
  .ref-code-value{font-size:1.2rem;letter-spacing:.14em}
  .ref-stats{grid-template-columns:1fr}
  .pw-section{grid-template-columns:1fr}
  .chat-input{flex-direction:column}
  .chat-input button{width:100%}
  .conv-row .name{flex-basis:76px;font-size:.85rem}
  .conv-row .preview{font-size:.76rem}
  .req-row{padding:10px 12px}
  .admin-header{flex-direction:column;align-items:stretch}
  .admin-header > div{width:100%}
  .admin-kpis{grid-template-columns:repeat(2,1fr);gap:8px}
  .admin-kpi{padding:11px 12px}
  .admin-kpi .v{font-size:1.15rem}
  .admin-kpi .s{font-size:.68rem}
  .notif-banner{padding:10px 12px}
  .banner-ad{height:50px}
  .banner-card .bc-thumb{width:100%;height:60px}
  .foot-grid{grid-template-columns:1fr}
  .foot-bottom{flex-direction:column;align-items:flex-start}
}
</style>
</head>
<body>

<svg xmlns="http://www.w3.org/2000/svg" style="position:absolute;width:0;height:0;overflow:hidden" aria-hidden="true">
<symbol id="i-play" viewBox="0 0 24 24"><path d="M8 5v14l11-7z" fill="currentColor"/></symbol>
<symbol id="i-menu" viewBox="0 0 24 24"><path d="M3 12h18M3 6h18M3 18h18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></symbol>
<symbol id="i-close" viewBox="0 0 24 24"><path d="M18 6 6 18M6 6l12 12" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></symbol>
<symbol id="i-check" viewBox="0 0 24 24"><path d="M20 6 9 17l-5-5" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/></symbol>
<symbol id="i-arrow-right" viewBox="0 0 24 24"><path d="M5 12h14M13 6l6 6-6 6" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"/></symbol>
<symbol id="i-zap" viewBox="0 0 24 24"><path d="M13 2 3 14h9l-1 8 10-12h-9l1-8z" fill="none" stroke="currentColor" stroke-width="2.2"/></symbol>
<symbol id="i-wallet" viewBox="0 0 24 24"><path d="M20 12V8H6a2 2 0 0 1 0-4h12v4M4 6v12a2 2 0 0 0 2 2h14v-4M18 12a2 2 0 0 0 0 4h4v-4z" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
<symbol id="i-video" viewBox="0 0 24 24"><rect x="2" y="6" width="14" height="12" rx="2" fill="none" stroke="currentColor" stroke-width="2"/><path d="m16 10 6-4v12l-6-4" fill="none" stroke="currentColor" stroke-width="2"/></symbol>
<symbol id="i-user-plus" viewBox="0 0 24 24"><circle cx="9" cy="8" r="4" fill="none" stroke="currentColor" stroke-width="2"/><path d="M2 21v-1a7 7 0 0 1 7-7a7 7 0 0 1 7 7v1M19 8v6M22 11h-6" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></symbol>
<symbol id="i-users" viewBox="0 0 24 24"><circle cx="9" cy="8" r="3.5" fill="none" stroke="currentColor" stroke-width="2"/><path d="M2.5 20v-1a6.5 6.5 0 0 1 13 0v1" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><circle cx="17" cy="8.5" r="3" fill="none" stroke="currentColor" stroke-width="2"/><path d="M17 14a5.5 5.5 0 0 1 5 5v1" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></symbol>
<symbol id="i-log-in" viewBox="0 0 24 24"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4M10 17l5-5-5-5M15 12H3" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></symbol>
<symbol id="i-log-out" viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></symbol>
<symbol id="i-layout" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2" fill="none" stroke="currentColor" stroke-width="2"/><path d="M3 9h18M9 21V9" fill="none" stroke="currentColor" stroke-width="2"/></symbol>
<symbol id="i-info" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" stroke-width="2"/><path d="M12 16v-4M12 8h.01" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"/></symbol>
<symbol id="i-mail" viewBox="0 0 24 24"><rect x="2" y="4" width="20" height="16" rx="2" fill="none" stroke="currentColor" stroke-width="2"/><path d="m2 7 10 6 10-6" fill="none" stroke="currentColor" stroke-width="2"/></symbol>
<symbol id="i-lock" viewBox="0 0 24 24"><rect x="4" y="11" width="16" height="10" rx="2" fill="none" stroke="currentColor" stroke-width="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4" fill="none" stroke="currentColor" stroke-width="2"/></symbol>
<symbol id="i-shield-check" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill="none" stroke="currentColor" stroke-width="2"/><path d="m9 12 2 2 4-4" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></symbol>
<symbol id="i-copy" viewBox="0 0 24 24"><rect x="9" y="9" width="12" height="12" rx="2" fill="none" stroke="currentColor" stroke-width="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" fill="none" stroke="currentColor" stroke-width="2"/></symbol>
<symbol id="i-trending" viewBox="0 0 24 24"><path d="m3 17 6-6 4 4 8-8M21 7v6h-6" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></symbol>
<symbol id="i-dollar" viewBox="0 0 24 24"><path d="M12 2v20M17 6H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H7" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></symbol>
<symbol id="i-whatsapp" viewBox="0 0 24 24"><path d="M17.5 14.4c-.3-.1-1.7-.8-2-.9-.3-.1-.5-.1-.7.1-.2.3-.7.9-.9 1.1-.2.2-.3.2-.6.1-.3-.1-1.3-.5-2.4-1.5-.9-.8-1.5-1.8-1.7-2.1-.2-.3 0-.4.1-.6.1-.1.3-.3.4-.5.1-.1.2-.3.3-.4.1-.2.1-.3 0-.5-.1-.1-.7-1.6-.9-2.2-.2-.6-.5-.5-.7-.5h-.6c-.2 0-.5.1-.8.4-.3.3-1 1-1 2.5s1.1 2.9 1.2 3.1c.1.2 2.1 3.2 5.1 4.4 3 1.2 3 1 3.5.9.5-.1 1.6-.7 1.9-1.3.2-.6.2-1.1.2-1.2-.1-.1-.3-.2-.4-.2M12 2C6.5 2 2 6.5 2 12c0 1.8.5 3.5 1.3 4.9L2 22l5.2-1.3c1.4.8 3 1.2 4.8 1.2 5.5 0 10-4.5 10-10S17.5 2 12 2z" fill="currentColor"/></symbol>
<symbol id="i-inbox" viewBox="0 0 24 24"><path d="M22 12h-6l-2 3h-4l-2-3H2" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/></symbol>
<symbol id="i-megaphone" viewBox="0 0 24 24"><path d="M3 11v2a2 2 0 0 0 2 2h2l4 4V5L7 9H5a2 2 0 0 0-2 2zM14 7s2 1 2 5-2 5-2 5M18 4s4 2 4 8-4 8-4 8" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
<symbol id="i-send" viewBox="0 0 24 24"><path d="M22 2 11 13M22 2l-7 20-4-9-9-4z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/></symbol>
<symbol id="i-gift" viewBox="0 0 24 24"><rect x="3" y="8" width="18" height="4" fill="none" stroke="currentColor" stroke-width="2"/><path d="M12 8v13M20 12v7a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-7M7.5 8a2.5 2.5 0 0 1 0-5C11 3 12 8 12 8s1-5 4.5-5a2.5 2.5 0 0 1 0 5" fill="none" stroke="currentColor" stroke-width="2"/></symbol>
<symbol id="i-alert" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" stroke-width="2"/><path d="M12 8v4M12 16h.01" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"/></symbol>
<symbol id="i-bell" viewBox="0 0 24 24"><path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9M10.3 21a1.94 1.94 0 0 0 3.4 0" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
<symbol id="i-image" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2" fill="none" stroke="currentColor" stroke-width="2"/><circle cx="8.5" cy="8.5" r="1.5" fill="currentColor"/><path d="m21 15-5-5L5 21" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
<symbol id="i-sun" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4" fill="none" stroke="currentColor" stroke-width="2"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></symbol>
<symbol id="i-moon" viewBox="0 0 24 24"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></symbol>
</svg>

<header class="nav" id="nav">
  <div class="container">
    <div class="nav-inner">
      <a href="#/home" class="logo"><span class="logo-mark"><svg class="icon" viewBox="0 0 24 24"><path d="M3 17l5-6 4 3 5-7 4 4"/></svg></span>Mobilearn</a>
      <nav class="nav-links">
        <a href="#/home" data-nav>Home</a>
        <a href="#/how" data-nav>How it works</a>
        <a href="#/dashboard" data-nav id="navDashboard" style="display:none">Dashboard</a>
        <a href="#/inbox" data-nav id="navInbox" style="display:none">Inbox <span class="nav-badge" id="inboxBadge"></span></a>
        <a href="#/about" data-nav>About</a>
        <a href="#/contact" data-nav>Contact</a>
      </nav>
      <div class="nav-cta">
        <button type="button" class="theme-toggle" id="themeToggle" aria-label="Toggle dark mode" title="Toggle dark/light mode">
          <svg class="icon icon-moon" viewBox="0 0 24 24"><use href="#i-moon"/></svg>
          <svg class="icon icon-sun" viewBox="0 0 24 24"><use href="#i-sun"/></svg>
        </button>
        <a href="#/login" class="btn btn-ghost"><svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-log-in"/></svg>Log in</a>
        <a href="#/signup" class="btn btn-primary"><svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-user-plus"/></svg>Get started</a>
        <button class="burger" id="burger" aria-label="Open menu" aria-expanded="false"><svg class="icon icon-menu" viewBox="0 0 24 24"><use href="#i-menu"/></svg><svg class="icon icon-close" viewBox="0 0 24 24"><use href="#i-close"/></svg></button>
      </div>
    </div>
  </div>
  <div class="mobile-menu" id="mobileMenu">
    <a href="#/home" data-nav>Home</a>
    <a href="#/how" data-nav>How it works</a>
    <a href="#/dashboard" data-nav id="mobileDashboard" style="display:none">Dashboard</a>
    <a href="#/inbox" data-nav id="mobileInbox" style="display:none">Inbox <span class="nav-badge" id="mobileInboxBadge"></span></a>
    <a href="#/about" data-nav>About</a>
    <a href="#/contact" data-nav>Contact</a>
    <a href="#/signup" class="btn btn-primary btn-block">Get started</a>
  </div>
</header>

<main>
  <!-- ═══════════ HOME / LANDING ═══════════ -->
  <section class="page" data-page="home">
    <div class="hero-v2">
      <div class="hero-bg"></div>
      <div class="container">
        <div class="hero-v2-inner">
          <div class="hero-v2-copy">
            <span class="hero-badge">
              <span class="live-dot"><svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-zap"/></svg></span>
              <span><b>1,284 payouts</b> in the last 24 hours</span>
            </span>
            <h1>Watch YouTube.<br><span class="grad-text">Get paid</span> for real.</h1>
            <p class="hero-v2-sub">Earn <b>UGX 1,900</b> per completed sponsored video. Withdraw to Airtel Money from UGX 20,000. Refer friends → earn <b>UGX 450</b> per approved signup. Real money, tracked end to end.</p>
            <div class="hero-v2-actions">
              <a href="#/signup" class="btn btn-primary btn-lg">Start earning <svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-arrow-right"/></svg></a>
              <a href="#/how" class="btn btn-ghost btn-lg"><svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-info"/></svg>See how it works</a>
            </div>
            <div class="hero-v2-trust">
              <span><i class="check"><svg class="icon" viewBox="0 0 24 24"><use href="#i-check"/></svg></i> Airtel Uganda only</span>
              <span><i class="check"><svg class="icon" viewBox="0 0 24 24"><use href="#i-check"/></svg></i> Paid in ~2 hours</span>
              <span><i class="check"><svg class="icon" viewBox="0 0 24 24"><use href="#i-check"/></svg></i> 2,400+ active members</span>
            </div>
          </div>
          <div class="hero-v2-visual">
            <div class="hero-phone">
              <div class="hero-phone-notch"></div>
              <div class="hero-phone-body">
                <div class="hp-balance">
                  <small>Available balance</small>
                  <div>UGX 947,300</div>
                  <span>+UGX 23,750 this week</span>
                </div>
                <div class="hp-row"><span>Today's videos</span><span>3 available</span></div>
                <div class="hp-row"><span>Videos today</span><span>UGX 5,700 earned</span></div>
                <div class="hp-card">
                  <div class="hp-card-title">Live payout feed</div>
                  <div class="hp-feed">
                    <div class="hp-feed-row">Amara K. · UGX 12,500 <span>2m ago</span></div>
                    <div class="hp-feed-row">Ronald M. · UGX 24,000 <span>14m ago</span></div>
                    <div class="hp-feed-row">Sara A. · UGX 20,000 <span>1h ago</span></div>
                    <div class="hp-feed-row">Brian O. · UGX 45,000 <span>2h ago</span></div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="stats-strip">
      <div class="container">
        <div class="stats-grid">
          <div class="stat"><b>UGX 47M+</b><span>Paid out to members</span></div>
          <div class="stat"><b>2,400+</b><span>Active earners</span></div>
          <div class="stat"><b>UGX 450</b><span>Per approved referral</span></div>
          <div class="stat"><b>~2 hrs</b><span>Average payout time</span></div>
        </div>
      </div>
    </div>

    <section class="section landing-how">
      <div class="container">
        <div class="section-head">
          <span class="eyebrow">Simple by design</span>
          <h2>Three steps. First payout fast.</h2>
          <p>No interviews. No capital. Just your phone and YouTube.</p>
        </div>
        <div class="how-grid">
          <div class="how-step">
            <div class="how-num">01</div>
            <div class="how-ic"><svg class="icon" viewBox="0 0 24 24"><use href="#i-user-plus"/></svg></div>
            <h3>Create your account</h3>
            <p>Username, Airtel number, password. Takes about a minute. Activate once for UGX 19,500.</p>
          </div>
          <div class="how-step">
            <div class="how-num">02</div>
            <div class="how-ic"><svg class="icon" viewBox="0 0 24 24"><use href="#i-play"/></svg></div>
            <h3>Watch sponsored videos</h3>
            <p>Finish the video to the end. Earn UGX 1,900 per video — auto-tracked and locked after earning.</p>
          </div>
          <div class="how-step">
            <div class="how-num">03</div>
            <div class="how-ic"><svg class="icon" viewBox="0 0 24 24"><use href="#i-wallet"/></svg></div>
            <h3>Withdraw to Airtel</h3>
            <p>Request from UGX 20,000 → admin approves in ~2 hrs → money lands on your Airtel merchant ID.</p>
          </div>
        </div>
      </div>
    </section>

    <section class="section landing-why" style="background:var(--bg-soft)">
      <div class="container">
        <div class="section-head">
          <span class="eyebrow">Why Mobilearn</span>
          <h2>Built for everyday earners</h2>
          <p>Real money. Real people. Real payouts — track every shilling end to end.</p>
        </div>
        <div class="why-grid">
          <div class="why-card">
            <div class="why-ic"><svg class="icon" viewBox="0 0 24 24"><use href="#i-zap"/></svg></div>
            <h3>Fast Airtel payouts</h3>
            <p>Withdraw from UGX 20,000. Admin confirms within ~2 hours. Paid straight to your saved merchant ID.</p>
          </div>
          <div class="why-card">
            <div class="why-ic"><svg class="icon" viewBox="0 0 24 24"><use href="#i-shield-check"/></svg></div>
            <h3>Safe &amp; tracked</h3>
            <p>Every video, bonus and payout is recorded server-side. Anti-skip protection stops fraud on both sides.</p>
          </div>
          <div class="why-card">
            <div class="why-ic"><svg class="icon" viewBox="0 0 24 24"><use href="#i-gift"/></svg></div>
            <h3>Refer &amp; earn</h3>
            <p>Share your link. When a friend signs up <b>and</b> gets approved, UGX 450 lands in your balance.</p>
          </div>
          <div class="why-card">
            <div class="why-ic"><svg class="icon" viewBox="0 0 24 24"><use href="#i-inbox"/></svg></div>
            <h3>Direct admin chat</h3>
            <p>No WhatsApp, no email tag. Message admin inside the app. Get replies, notifications and updates.</p>
          </div>
        </div>
      </div>
    </section>

    <section class="section landing-testimonials">
      <div class="container">
        <div class="section-head">
          <span class="eyebrow">Payout proof</span>
          <h2>Real members. Real withdrawals.</h2>
          <p>Every payout below was approved by admin and paid on Airtel Money.</p>
        </div>
        <div class="testi-grid">
          <div class="testi-card">
            <div class="testi-quote">Got my first UGX 25,000 in under 3 hours. Now I do 5 videos a day and pick up extra every week.</div>
            <div class="testi-who">
              <div class="testi-av">A</div>
              <div><b>Amara K.</b><small>Kampala · Active member</small></div>
            </div>
          </div>
          <div class="testi-card">
            <div class="testi-quote">Referred 6 friends — every one got approved and I earned UGX 2,700 in bonuses. It adds up fast.</div>
            <div class="testi-who">
              <div class="testi-av">R</div>
              <div><b>Ronald M.</b><small>Entebbe · Referral earner</small></div>
            </div>
          </div>
          <div class="testi-card">
            <div class="testi-quote">Withdrew UGX 45,000 last Friday. The admin replied in my Inbox in 20 minutes. Clean experience.</div>
            <div class="testi-who">
              <div class="testi-av">S</div>
              <div><b>Sara A.</b><small>Jinja · Active member</small></div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <section class="section landing-faq" style="background:var(--bg-soft)">
      <div class="container">
        <div class="section-head">
          <span class="eyebrow">FAQ</span>
          <h2>Questions? Answered.</h2>
        </div>
        <div class="faq-list">
          <details class="faq-item">
            <summary>How much can I earn per video?</summary>
            <p>UGX 1,900 per completed sponsored video by default. Admin can raise the reward per video when publishing. Every video can only be earned once per account.</p>
          </details>
          <details class="faq-item">
            <summary>How does the anti-skip protection work?</summary>
            <p>The player detects skipping and fast-forwarding. If you skip, the video restarts from the beginning and you lose that progress. Watch all the way through to earn.</p>
          </details>
          <details class="faq-item">
            <summary>When do I get paid?</summary>
            <p>Request a withdrawal from your dashboard (minimum UGX 20,000). Admin approves in about 2 hours on average and sends the money to your saved Airtel merchant ID. You can only have one pending withdrawal at a time.</p>
          </details>
          <details class="faq-item">
            <summary>How does the referral bonus work?</summary>
            <p>Share your unique link. When your friend signs up <b>and is approved by admin</b>, UGX 450 lands in your balance instantly and is added to your total earned for the leaderboard.</p>
          </details>
          <details class="faq-item">
            <summary>Do I have to pay to join?</summary>
            <p>One-time activation of UGX 19,500 via *185*9# → merchant code <b>7285061</b> (MOBILE LABS). After that, all your earnings are free and clear. Nothing is deducted from your balance.</p>
          </details>
          <details class="faq-item">
            <summary>Is my password safe?</summary>
            <p>Yes. Passwords are hashed with PBKDF2-SHA256 and a per-user salt. We never store or log your plain password. Sessions expire in 30 days and can be revoked at any time.</p>
          </details>
        </div>
      </div>
    </section>

    <section class="cta-band">
      <div class="container">
        <div class="cta-inner">
          <h2>Ready to start earning?</h2>
          <p>Sign up in under a minute. Get approved. Start watching sponsored videos for real money.</p>
          <a href="#/signup" class="btn btn-lg">Create free account <svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-arrow-right"/></svg></a>
        </div>
      </div>
    </section>
  </section>

  <!-- ═══════════ HOW IT WORKS ═══════════ -->
  <section class="page" data-page="how"><div class="container">
    <div class="page-head"><span class="eyebrow">How it works</span><h1>From signup to payout</h1><p>Account, activation, YouTube videos, withdrawals and referrals.</p></div>
    <div class="section"><div class="panel panel-accent">
      <h3><svg class="icon" viewBox="0 0 24 24" style="color:var(--primary)"><use href="#i-lock"/></svg>Activate — UGX 19,500</h3>
      <p>One-time activation via Airtel Money. Then submit an activation request in your Inbox.</p>
      <div class="merchant-box"><span class="mb-label">Merchant<br>Code</span><span class="mb-value">7285061</span><button type="button" class="mb-copy" data-copy="7285061"><svg class="icon" viewBox="0 0 24 24"><use href="#i-copy"/></svg>Copy</button></div>
      <div class="pay-steps">
        <div class="pay-step"><span class="pay-step-num">1</span><div><b>Dial <code>*185*9#</code></b><span class="desc">Opens Airtel Money</span></div></div>
        <div class="pay-step"><span class="pay-step-num">2</span><div><b>Enter merchant code <code>7285061</code></b></div></div>
        <div class="pay-step"><span class="pay-step-num">3</span><div><b>Confirm <code>MOBILE LABS</code> · pay <code>UGX 19,500</code></b></div></div>
        <div class="pay-step"><span class="pay-step-num">4</span><div><b>Enter PIN to approve</b></div></div>
      </div>
    </div></div>
    <div class="section" style="padding-top:0"><div class="grid-2">
      <div class="panel"><h3><svg class="icon" viewBox="0 0 24 24"><use href="#i-wallet"/></svg>Withdrawals</h3><p style="margin-top:8px;color:var(--muted);font-size:.93rem">Request from UGX 20,000. Admin approves in about 2 hours. Paid straight to your saved Airtel merchant ID. Only one pending withdrawal at a time.</p></div>
      <div class="panel"><h3><svg class="icon" viewBox="0 0 24 24"><use href="#i-gift"/></svg>Referrals</h3><p style="margin-top:8px;color:var(--muted);font-size:.93rem">Share your link. When a friend signs up and gets approved by admin, <b>UGX 450</b> lands in your balance instantly — real money, not just a link.</p></div>
    </div></div>
  </div></section>

  <!-- ═══════════ SIGNUP ═══════════ -->
  <section class="page" data-page="signup"><div class="section"><div class="container"><div class="auth-wrap"><div class="auth-card">
    <span class="eyebrow"><svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-user-plus"/></svg>Get started</span>
    <h1 style="margin-top:10px">Create your account</h1>
    <p class="sub">Join Mobilearn in under a minute. Airtel Uganda numbers only.</p>
    <div id="refBanner" style="display:none;margin-bottom:14px;padding:10px 14px;background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.3);border-radius:10px;font-size:.86rem;color:#047857">
      <b>🎁 You were referred!</b> After admin approves you, your friend earns UGX 450.
    </div>
    <form class="form-stack" id="signup" novalidate>
      <input type="text" id="username" placeholder="Username" autocomplete="username" required />
      <input type="tel" id="phone" placeholder="Airtel number (e.g. 0701234567)" inputmode="tel" autocomplete="tel" required />
      <input type="password" id="password" placeholder="Password (min 6 chars)" autocomplete="new-password" required />
      <input type="password" id="confirmPassword" placeholder="Confirm password" autocomplete="new-password" required />
      <button type="submit" class="btn btn-primary btn-block"><svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-user-plus"/></svg>Create account</button>
    </form>
    <div class="auth-msg" id="formMsg" role="status" aria-live="polite"></div>
    <div class="auth-alt">Already have an account? <a href="#/login">Log in</a></div>
  </div></div></div></div></section>

  <!-- ═══════════ LOGIN ═══════════ -->
  <section class="page" data-page="login"><div class="section"><div class="container"><div class="auth-wrap"><div class="auth-card">
    <h1>Welcome back</h1>
    <p class="sub">Log in with your username or Airtel number. Data syncs across all devices.</p>
    <form class="form-stack" id="login" novalidate>
      <input type="text" id="loginId" placeholder="Username or Airtel number" autocomplete="username" required />
      <input type="password" id="loginPass" placeholder="Password" autocomplete="current-password" required />
      <button type="submit" class="btn btn-primary btn-block"><svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-log-in"/></svg>Log in</button>
    </form>
    <div class="auth-msg" id="loginMsg" role="status" aria-live="polite"></div>
    <div class="auth-alt"><a href="#/forgot">Forgot password?</a></div>
    <div class="auth-alt">New here? <a href="#/signup">Create an account</a></div>
  </div></div></div></div></section>

  <!-- ═══════════ FORGOT ═══════════ -->
  <section class="page" data-page="forgot"><div class="section"><div class="container"><div class="auth-wrap"><div class="auth-card">
    <h1>Reset your password</h1>
    <p class="sub">Enter your username, the Airtel number on the account and a new password.</p>
    <form class="form-stack" id="forgotForm" novalidate>
      <input type="text" id="fpUser" placeholder="Username" autocomplete="username" required />
      <input type="tel" id="fpPhone" placeholder="Airtel number on account" inputmode="tel" required />
      <input type="password" id="fpNew" placeholder="New password (min 6 chars)" autocomplete="new-password" required />
      <input type="password" id="fpConfirm" placeholder="Confirm new password" autocomplete="new-password" required />
      <button type="submit" class="btn btn-primary btn-block"><svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-lock"/></svg>Reset password</button>
    </form>
    <div class="auth-msg" id="forgotMsg" role="status" aria-live="polite"></div>
    <div class="auth-alt"><a href="#/login">← Back to login</a></div>
  </div></div></div></div></section>

  <!-- ═══════════ DASHBOARD ═══════════ -->
  <section class="page" data-page="dashboard">
    <div class="dash-drawer-overlay" id="dashDrawerOverlay"></div>
    <aside class="dash-drawer" id="dashDrawer" aria-hidden="true">
      <div class="dash-drawer-head">
        <div class="dash-avatar" id="drawerAvatar">U</div>
        <div style="min-width:0">
          <b id="drawerUser">User</b>
          <small id="drawerBalance">UGX 0</small>
        </div>
      </div>
      <nav class="dash-drawer-nav">
        <a href="#sec-videos" data-dash-link>
          <span class="dn-ic" style="background:linear-gradient(135deg,#1e40af,#0f766e)"><svg class="icon" viewBox="0 0 24 24"><use href="#i-play"/></svg></span>
          Watch &amp; Earn
        </a>
        <a href="#sec-challenges" data-dash-link>
          <span class="dn-ic" style="background:linear-gradient(135deg,#dc2626,#b91c1c)"><svg class="icon" viewBox="0 0 24 24"><use href="#i-zap"/></svg></span>
          Challenges
        </a>
        <a href="#sec-leaderboard" data-dash-link>
          <span class="dn-ic" style="background:linear-gradient(135deg,#ca8a04,#a16207)"><svg class="icon" viewBox="0 0 24 24"><use href="#i-trending"/></svg></span>
          Leaderboard
        </a>
        <a href="#sec-withdraw" data-dash-link>
          <span class="dn-ic" style="background:linear-gradient(135deg,#059669,#047857)"><svg class="icon" viewBox="0 0 24 24"><use href="#i-wallet"/></svg></span>
          Withdraw
        </a>
        <a href="#/inbox">
          <span class="dn-ic" style="background:linear-gradient(135deg,#0891b2,#0e7490)"><svg class="icon" viewBox="0 0 24 24"><use href="#i-bell"/></svg></span>
          Inbox
          <span class="dn-badge" id="drawerInboxBadge"></span>
        </a>
        <a href="#sec-referrals" data-dash-link>
          <span class="dn-ic" style="background:linear-gradient(135deg,#b45309,#92400e)"><svg class="icon" viewBox="0 0 24 24"><use href="#i-gift"/></svg></span>
          Referrals
        </a>
        <a href="#sec-payout" data-dash-link>
          <span class="dn-ic" style="background:linear-gradient(135deg,#7c3aed,#6d28d9)"><svg class="icon" viewBox="0 0 24 24"><use href="#i-dollar"/></svg></span>
          Payout Details
        </a>
        <a href="#sec-password" data-dash-link>
          <span class="dn-ic" style="background:linear-gradient(135deg,#475569,#334155)"><svg class="icon" viewBox="0 0 24 24"><use href="#i-lock"/></svg></span>
          Change Password
        </a>
      </nav>
      <div class="dash-drawer-foot">
        <button type="button" class="btn btn-ghost btn-block" id="drawerLogout">
          <svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-log-out"/></svg>Log out
        </button>
      </div>
    </aside>

    <div class="container dash-container">
      <div class="dash-topbar">
        <button type="button" class="dash-burger" id="dashBurger" aria-label="Open menu" aria-expanded="false">
          <svg class="icon icon-menu" viewBox="0 0 24 24"><use href="#i-menu"/></svg>
        </button>
        <div class="dash-ttl">Dashboard</div>
        <button type="button" class="dash-bell" id="dashBell" aria-label="Open inbox">
          <svg class="icon" viewBox="0 0 24 24"><use href="#i-bell"/></svg>
          <span class="dash-bell-badge" id="dashBellBadge">0</span>
        </button>
      </div>

      <div class="dash-head">
        <div>
          <span class="eyebrow">Dashboard</span>
          <h1>Welcome back, <span id="dashUser">User</span></h1>
          <p>
            <span class="status-active" id="verifyStatus">Account active</span>
            <span class="status-online" title="You are online">Online</span>
            <span id="verifyText">Watch a full video to earn UGX 1,900</span>
          </p>
        </div>
      </div>

      <div class="notif-banner" id="notifBanner">
        <svg class="icon nb-ic" viewBox="0 0 24 24"><use href="#i-bell"/></svg>
        <div class="nb-tx"><b>Enable alerts</b><span id="notifBannerText">Hear a chime and see popups on your phone when admin sends you a message or announcement.</span></div>
        <button type="button" class="nb-btn" id="notifEnableBtn"><svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-bell"/></svg>Enable</button>
      </div>

      <a class="banner-ad" id="bannerAd" href="#" target="_blank" rel="noopener" style="display:none">
        <img id="bannerImg" src="" alt="" />
        <span class="bn-label">Sponsored</span>
      </a>

      <div class="dash-quicknav">
        <a href="#sec-videos" data-dash-link class="qn-item">
          <div class="qn-icon" style="background:linear-gradient(135deg,#1e40af,#0f766e)"><svg class="icon" viewBox="0 0 24 24"><use href="#i-play"/></svg></div>
          <span>Watch</span>
        </a>
        <a href="#sec-withdraw" data-dash-link class="qn-item">
          <div class="qn-icon" style="background:linear-gradient(135deg,#059669,#047857)"><svg class="icon" viewBox="0 0 24 24"><use href="#i-wallet"/></svg></div>
          <span>Withdraw</span>
        </a>
        <a href="#/inbox" class="qn-item">
          <div class="qn-icon" style="background:linear-gradient(135deg,#0891b2,#0e7490)">
            <svg class="icon" viewBox="0 0 24 24"><use href="#i-bell"/></svg>
            <span class="qn-badge" id="qnInboxBadge"></span>
          </div>
          <span>Inbox</span>
        </a>
        <a href="#sec-referrals" data-dash-link class="qn-item">
          <div class="qn-icon" style="background:linear-gradient(135deg,#b45309,#92400e)"><svg class="icon" viewBox="0 0 24 24"><use href="#i-gift"/></svg></div>
          <span>Referrals</span>
        </a>
        <a href="#sec-payout" data-dash-link class="qn-item">
          <div class="qn-icon" style="background:linear-gradient(135deg,#7c3aed,#6d28d9)"><svg class="icon" viewBox="0 0 24 24"><use href="#i-dollar"/></svg></div>
          <span>Payout</span>
        </a>
        <a href="#sec-password" data-dash-link class="qn-item">
          <div class="qn-icon" style="background:linear-gradient(135deg,#475569,#334155)"><svg class="icon" viewBox="0 0 24 24"><use href="#i-lock"/></svg></div>
          <span>Security</span>
        </a>
      </div>

      <div class="dash-balance-card">
        <span class="dash-live"><i></i>Verified balance</span>
        <small>Available balance</small>
        <div class="dash-balance" id="dashBalance">UGX 0</div>
      </div>

      <div class="dash-panel" id="sec-videos" style="margin-top:22px">
        <div class="video-head">
          <div><h3><svg class="icon" viewBox="0 0 24 24"><use href="#i-play"/></svg>Watch &amp; Earn</h3><p class="sub">Watch once. Earn once. Earned videos are locked — they can never replay.</p></div>
          <span class="video-reward" id="videoRewardBadge"><svg class="icon" viewBox="0 0 24 24"><use href="#i-dollar"/></svg>+UGX 1,900</span>
        </div>
        <div class="video-frame" id="videoFrame"><div id="ytPlayer"></div><div class="placeholder" id="videoPlaceholder">Choose a video below to start earning.</div></div>
        <div class="video-status" id="videoStatus"><svg class="icon" viewBox="0 0 24 24"><use href="#i-play"/></svg>Select a video to begin.</div>
        <div class="video-progress" id="videoProgress"><i></i></div>
        <p class="video-guard"><svg class="icon" viewBox="0 0 24 24"><use href="#i-shield-check"/></svg>Anti-skip protection is on. Skipping restarts the video. Once earned, a video is locked forever for your account.</p>
        <div class="video-list" id="videoListMember" style="margin-top:16px"></div>
        <div style="margin-top:16px;padding:14px;border-radius:14px;background:rgba(59,130,246,.08);border:1px solid rgba(59,130,246,.25);display:flex;align-items:center;gap:14px;flex-wrap:wrap">
          <svg class="icon" style="width:32px;height:32px;color:var(--primary);fill:none;stroke:currentColor;stroke-width:2.2;flex:none" viewBox="0 0 24 24"><use href="#i-inbox"/></svg>
          <div style="flex:1;min-width:0"><b style="display:block;font-size:.92rem">Verify in the Inbox</b><small style="color:var(--muted);font-size:.82rem">Finished a video? Send a verification request to admin — no WhatsApp needed.</small></div>
          <a href="#/inbox" class="btn btn-primary" style="padding:10px 20px;font-size:.85rem">Open Inbox</a>
        </div>
      </div>

      <div class="dash-panel" id="sec-challenges" style="margin-top:22px">
        <div class="video-head">
          <div><h3><svg class="icon" viewBox="0 0 24 24"><use href="#i-zap"/></svg>Challenges</h3><p class="sub">Hit a goal, claim the bonus. Progress updates live.</p></div>
        </div>
        <div id="challengeList"></div>
        <div class="auth-msg" id="challengeClaimMsg" role="status" aria-live="polite"></div>
      </div>

      <div class="dash-panel" id="sec-leaderboard" style="margin-top:22px">
        <div class="video-head">
          <div><h3><svg class="icon" viewBox="0 0 24 24"><use href="#i-trending"/></svg>Leaderboard</h3><p class="sub">Top earners on Mobilearn. Earn more to climb.</p></div>
          <span class="ref-pill"><svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-trending"/></svg>Top 10</span>
        </div>
        <div id="leaderboardList"></div>
        <div class="ref-msg" id="leaderboardMe" style="margin-top:10px">Loading…</div>
      </div>

      <div class="dash-panel" id="sec-withdraw" style="margin-top:22px">
        <div class="video-head">
          <div><h3><svg class="icon" viewBox="0 0 24 24"><use href="#i-wallet"/></svg>Withdraw earnings</h3><p class="sub">Request a payout to your Airtel merchant ID. Admin approves in ~2 hrs.</p></div>
          <span class="badge badge-pending">Min 20,000</span>
        </div>
        <div class="withdraw-info" id="withdrawInfo">
          <div>
            <div class="wi-lbl">Available</div>
            <div class="wi-val" id="wdAvailable">UGX 0</div>
          </div>
          <div style="text-align:right">
            <div class="wi-lbl">Merchant ID</div>
            <div class="wi-val" id="wdMerchant">—</div>
          </div>
          <div class="wi-min" id="wdMinNote">Minimum UGX 20,000</div>
        </div>
        <form id="withdrawForm" class="withdraw-form" novalidate>
          <input type="number" id="withdrawAmount" placeholder="Amount (UGX, min 20,000)" min="20000" step="100" />
          <button type="submit" class="btn btn-primary"><svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-wallet"/></svg>Request withdrawal</button>
        </form>
        <div class="withdraw-note">
          <svg class="icon" viewBox="0 0 24 24"><use href="#i-alert"/></svg>
          <div>Requests are manually approved. Please allow <b>up to 2 hours</b> for admin to confirm your payment — be patient. Only one pending request at a time.</div>
        </div>
        <div class="auth-msg" id="withdrawMsg" role="status" aria-live="polite"></div>
        <div class="withdraw-history" id="withdrawHistory"></div>
      </div>

      <div class="dash-panel" id="sec-referrals" style="margin-top:22px">
        <div class="video-head">
          <div><h3><svg class="icon" viewBox="0 0 24 24"><use href="#i-gift"/></svg>Refer &amp; earn UGX 450</h3><p class="sub">Try your luck — don't retreat, signup now!!! Share your code and earn each approved signup.</p></div>
          <span class="ref-pill"><svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-gift"/></svg>UGX 450 / approved</span>
        </div>
        <div class="ref-display">
          <div>
            <div class="ref-code-label">Your referral code</div>
            <div class="ref-code-value" id="refLinkText">—</div>
          </div>
          <button type="button" id="refCopyBtn" class="btn btn-primary">
            <svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-copy"/></svg>Copy referral link
          </button>
        </div>
        <div class="ref-stats">
          <div class="ref-stat"><div class="v" id="refTotal">0</div><div class="l">Referred</div></div>
          <div class="ref-stat"><div class="v" id="refCredited">0</div><div class="l">Approved</div></div>
          <div class="ref-stat"><div class="v" id="refEarned">UGX 0</div><div class="l">Earned</div></div>
        </div>
        <div class="ref-msg" id="refMsg">Share your link. When your friend signs up <b>and gets approved by admin</b>, you get UGX 450 into your balance — real money, instantly.</div>
      </div>

      <div class="dash-panel" id="sec-payout" style="margin-top:22px">
        <div class="video-head">
          <div><h3><svg class="icon" viewBox="0 0 24 24"><use href="#i-wallet"/></svg>Payout details</h3><p class="sub">Save your Airtel merchant ID for admin payouts. Required before withdrawing.</p></div>
          <span class="badge badge-pending">Required</span>
        </div>
        <form id="merchantForm" novalidate style="display:flex;flex-direction:column;gap:10px;max-width:440px">
          <input type="text" id="merchantInput" placeholder="Airtel merchant ID (e.g. 0701234567)" style="padding:13px 16px;border-radius:10px;border:1px solid var(--line-strong);background:var(--card);color:var(--text);outline:none;width:100%" />
          <button type="submit" class="btn btn-primary"><svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-check"/></svg>Save merchant ID</button>
        </form>
        <div class="auth-msg" id="merchantMsg" role="status" aria-live="polite"></div>
        <div id="merchantSaved" style="font-size:.86rem;color:var(--muted);margin-top:8px"></div>
      </div>

      <div class="dash-panel" id="sec-password" style="margin-top:22px">
        <div class="video-head"><div><h3><svg class="icon" viewBox="0 0 24 24"><use href="#i-lock"/></svg>Change password</h3><p class="sub">New password stored hashed. Other devices signed out.</p></div></div>
        <form id="changePwForm" novalidate>
          <div class="pw-section">
            <input type="password" id="curPw" placeholder="Current password" required />
            <input type="password" id="newPw" placeholder="New password (min 6 chars)" required />
          </div>
          <button type="submit" class="btn btn-primary" style="margin-top:12px"><svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-lock"/></svg>Update password</button>
        </form>
        <div class="auth-msg" id="changePwMsg" role="status" aria-live="polite"></div>
      </div>
      <div style="height:40px"></div>
    </div>
  </section>

  <!-- ═══════════ INBOX ═══════════ -->
  <section class="page" data-page="inbox"><div class="container dash-container">
    <div class="dash-head">
      <div>
        <span class="eyebrow">Inbox</span>
        <h1>Messages, requests &amp; announcements</h1>
        <p>Talk directly to admin. Send verification, activation or payout requests here.</p>
      </div>
      <button type="button" class="btn btn-ghost" id="inboxMarkRead"><svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-check"/></svg>Mark all read</button>
    </div>
    <div class="dash-panel">
      <div class="video-head"><div><h3><svg class="icon" viewBox="0 0 24 24"><use href="#i-megaphone"/></svg>Announcements</h3><p class="sub">Broadcasts from Mobilearn admin.</p></div></div>
      <div id="memberAnnouncements"></div>
    </div>
    <div class="dash-panel" style="margin-top:22px">
      <div class="video-head"><div><h3><svg class="icon" viewBox="0 0 24 24"><use href="#i-send"/></svg>Send a request to admin</h3><p class="sub">Verification, activation, payout issue or something else — admin replies here.</p></div></div>
      <form id="dealRequestForm" novalidate>
        <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px">
          <select id="drKind" style="flex:1;min-width:180px;padding:12px 16px;border-radius:10px;border:1px solid var(--line-strong);background:var(--card);color:var(--text);outline:none;font-weight:600">
            <option value="verification">Video verification</option>
            <option value="activation">Account activation</option>
            <option value="payout">Payout / withdrawal</option>
            <option value="other">Other</option>
          </select>
          <input type="text" id="drVideo" placeholder="Video title or ID (optional)" style="flex:2;min-width:180px;padding:12px 16px;border-radius:10px;border:1px solid var(--line-strong);background:var(--card);color:var(--text);outline:none" />
        </div>
        <textarea id="drMessage" placeholder="Describe your request (5+ characters)" style="width:100%;min-height:90px;padding:12px 16px;border-radius:10px;border:1px solid var(--line-strong);background:var(--card);color:var(--text);outline:none;resize:vertical"></textarea>
        <button type="submit" class="btn btn-primary" style="margin-top:10px"><svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-send"/></svg>Send request</button>
      </form>
      <div class="auth-msg" id="dealRequestMsg" role="status" aria-live="polite"></div>
      <div id="myDealRequests" style="margin-top:14px"></div>
    </div>
    <div class="dash-panel" style="margin-top:22px">
      <div class="video-head"><div><h3><svg class="icon" viewBox="0 0 24 24"><use href="#i-inbox"/></svg>Chat with admin</h3><p class="sub">Simple direct messages — admin replies here.</p></div></div>
      <div class="chat" id="memberChat"></div>
      <form id="memberChatForm" class="chat-input">
        <input type="text" id="memberChatInput" placeholder="Type a message…" maxlength="4000" />
        <button type="submit" class="btn btn-primary" style="padding:10px 18px"><svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-send"/></svg>Send</button>
      </form>
      <div class="auth-msg" id="memberChatMsg" role="status" aria-live="polite"></div>
    </div>
    <div style="height:40px"></div>
  </div></section>

  <!-- ═══════════ ADMIN LOGIN ═══════════ -->
  <section class="page" data-page="admin"><div class="section"><div class="container"><div class="auth-wrap"><div class="auth-card">
    <h1>Admin console</h1>
    <p class="sub">Sign in to manage members, approve withdrawals, publish videos, reply to members, send broadcasts.</p>
    <form class="form-stack" id="adminLoginForm" novalidate>
      <input type="text" id="adminUser" placeholder="Admin username" autocomplete="username" required />
      <input type="password" id="adminPass" placeholder="Admin password" autocomplete="current-password" required />
      <button type="submit" class="btn btn-primary btn-block"><svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-lock"/></svg>Sign in</button>
    </form>
    <div class="auth-msg" id="adminMsg" role="status" aria-live="polite"></div>
    <div class="auth-alt"><a href="#/home">← Back to site</a></div>
  </div></div></div></div></section>

  <!-- ═══════════ ADMIN DASHBOARD ═══════════ -->
  <section class="page" data-page="adminDashboard"><div class="container admin-shell">
    <div class="admin-header">
      <div>
        <span class="eyebrow">Admin</span>
        <h1>Members &amp; payouts</h1>
        <p>All changes persist to the database. Approve signups, approve withdrawals, resolve requests, send broadcasts.</p>
      </div>
      <div style="display:flex;gap:10px;flex-wrap:wrap">
        <button type="button" class="btn btn-ghost" id="adminRefresh"><svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-trending"/></svg>Refresh</button>
        <a href="/api/admin/backup" class="btn btn-ghost" download><svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-wallet"/></svg>Backup DB</a>
        <button type="button" class="btn btn-ghost" id="adminLogout"><svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-log-out"/></svg>Log out</button>
      </div>
    </div>
    <div class="admin-kpis" id="adminKpis"></div>

    <div class="panel admin-section">
      <h3><svg class="icon" viewBox="0 0 24 24" style="color:var(--primary);fill:none;stroke:currentColor;stroke-width:2.2"><use href="#i-shield-check"/></svg>Access control</h3>
      <p>Turn admin authorization on or off. When OFF, new members skip approval and pending members are activated automatically — they can log in and reach the dashboard immediately.</p>
      <label class="toggle-row" for="autoApproveToggle">
        <input type="checkbox" id="autoApproveToggle" />
        <span class="toggle-track"><span class="toggle-thumb"></span></span>
        <span class="tg-txt"><b>Auto-approve signups</b><small id="autoApproveState">OFF — admin approval required</small></span>
      </label>
      <div class="auth-msg" id="settingsMsg" role="status" aria-live="polite"></div>
    </div>

    <div class="panel admin-section">
      <h3><svg class="icon" viewBox="0 0 24 24" style="color:var(--primary);fill:none;stroke:currentColor;stroke-width:2.2"><use href="#i-trending"/></svg>Live monitor</h3>
      <p>Who's online right now and the latest activity across the app (refreshes every 30 seconds).</p>
      <div class="grid-2" style="margin-top:14px">
        <div>
          <div class="ref-code-label" style="margin-bottom:8px">Online now</div>
          <div class="mon-list" id="adminOnlineList"></div>
        </div>
        <div>
          <div class="ref-code-label" style="margin-bottom:8px">Recent activity</div>
          <div class="mon-list" id="adminAuditList"></div>
        </div>
      </div>
    </div>

    <div class="panel admin-section">
      <h3><svg class="icon" viewBox="0 0 24 24" style="color:var(--primary);fill:none;stroke:currentColor;stroke-width:2.2"><use href="#i-image"/></svg>Banner ads</h3>
      <p>Paste an image URL (direct .jpg/.png or hosted image). It goes live on every member's dashboard as a ~1 cm tall clickable banner.</p>
      <form class="banner-form" id="bannerForm" novalidate>
        <input type="text" id="bnImage" placeholder="Image URL (https://… .jpg/.png)" required />
        <input type="text" id="bnLink" placeholder="Link when clicked (optional https://…)" />
        <input type="text" id="bnTitle" placeholder="Label (optional, e.g. 'Weekend promo')" />
        <button type="submit" class="btn btn-primary"><svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-image"/></svg>Publish banner</button>
      </form>
      <div class="auth-msg" id="bannerMsg" role="status" aria-live="polite"></div>
      <div id="adminBannerList" style="margin-top:14px"></div>
    </div>

    <div class="panel admin-section">
      <h3><svg class="icon" viewBox="0 0 24 24" style="color:var(--primary);fill:none;stroke:currentColor;stroke-width:2.2"><use href="#i-wallet"/></svg>Withdrawal requests</h3>
      <p>Approve to deduct balance and pay. Reject with a reason — the member is notified either way.</p>
      <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap">
        <select id="wdFilter" class="user-select">
          <option value="pending">Pending only</option>
          <option value="all">All withdrawals</option>
          <option value="approved">Approved</option>
          <option value="rejected">Rejected</option>
        </select>
      </div>
      <div id="adminWithdrawals" style="margin-top:12px"></div>
    </div>

    <div class="panel admin-section">
      <h3><svg class="icon" viewBox="0 0 24 24" style="color:var(--primary);fill:none;stroke:currentColor;stroke-width:2.2"><use href="#i-inbox"/></svg>Member conversations</h3>
      <p>Click a member to open their chat and reply.</p>
      <div id="adminConversations" style="margin-top:12px"></div>
      <div id="adminChatWrap" style="display:none;margin-top:16px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;flex-wrap:wrap;gap:8px">
          <b id="adminChatWith">Conversation</b>
          <button type="button" class="mini-btn" id="adminChatBack">Close conversation</button>
        </div>
        <div class="chat" id="adminChat"></div>
        <form id="adminChatForm" class="chat-input">
          <input type="text" id="adminChatInput" placeholder="Reply to member…" maxlength="4000" />
          <button type="submit" class="btn btn-primary" style="padding:10px 18px"><svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-send"/></svg>Send</button>
        </form>
        <div class="auth-msg" id="adminChatMsg" role="status" aria-live="polite"></div>
      </div>
    </div>

    <div class="panel admin-section">
      <h3><svg class="icon" viewBox="0 0 24 24" style="color:var(--primary);fill:none;stroke:currentColor;stroke-width:2.2"><use href="#i-send"/></svg>Deal requests</h3>
      <p>Verification, activation, payout issues. Mark as resolved when handled.</p>
      <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap">
        <select id="drFilter" class="user-select">
          <option value="pending">Pending only</option>
          <option value="all">All requests</option>
          <option value="resolved">Resolved only</option>
        </select>
      </div>
      <div id="adminDealRequests" style="margin-top:12px"></div>
    </div>

    <div class="panel admin-section">
      <h3><svg class="icon" viewBox="0 0 24 24" style="color:var(--primary);fill:none;stroke:currentColor;stroke-width:2.2"><use href="#i-zap"/></svg>Challenges</h3>
      <p>Create goals. Members see progress on their dashboard and claim the reward when complete.</p>
      <form id="challengeForm" novalidate style="margin-top:14px">
        <div class="grid-2" style="gap:10px;margin-bottom:10px">
          <input id="chTitle" placeholder="Title (e.g. Watch 5 videos)" style="padding:12px 16px;border-radius:10px;border:1px solid var(--line-strong);background:var(--card);color:var(--text);outline:none" required />
          <input id="chDesc" placeholder="Short description (optional)" style="padding:12px 16px;border-radius:10px;border:1px solid var(--line-strong);background:var(--card);color:var(--text);outline:none" />
        </div>
        <div class="ch-form-row">
          <select id="chType" class="user-select"><option value="videos">Videos watched</option><option value="referrals">Approved referrals</option></select>
          <input id="chGoal" type="number" min="1" value="5" placeholder="Goal" style="padding:12px 16px;border-radius:10px;border:1px solid var(--line-strong);background:var(--card);color:var(--text);outline:none" />
          <input id="chReward" type="number" min="1" step="100" value="1000" placeholder="Reward UGX" style="padding:12px 16px;border-radius:10px;border:1px solid var(--line-strong);background:var(--card);color:var(--text);outline:none" />
          <button type="submit" class="btn btn-primary"><svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-zap"/></svg>Create</button>
        </div>
      </form>
      <div class="auth-msg" id="challengeMsg" role="status" aria-live="polite"></div>
      <div id="adminChallengeList" style="margin-top:14px"></div>
    </div>

    <div class="panel admin-section">
      <h3><svg class="icon" viewBox="0 0 24 24" style="color:var(--primary);fill:none;stroke:currentColor;stroke-width:2.2"><use href="#i-megaphone"/></svg>Broadcast announcement</h3>
      <p>Sends to every member's Inbox — triggers a popup &amp; sound on their phone.</p>
      <form id="adminAnnounceForm" novalidate style="margin-top:14px">
        <input type="text" id="annTitle" placeholder="Title (e.g. Payout schedule update)" style="width:100%;padding:12px 16px;border-radius:10px;border:1px solid var(--line-strong);background:var(--card);color:var(--text);outline:none;margin-bottom:8px" required />
        <textarea id="annBody" placeholder="Announcement body…" style="width:100%;min-height:80px;padding:12px 16px;border-radius:10px;border:1px solid var(--line-strong);background:var(--card);color:var(--text);outline:none;resize:vertical" required></textarea>
        <button type="submit" class="btn btn-primary" style="margin-top:10px"><svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-megaphone"/></svg>Broadcast</button>
      </form>
      <div class="auth-msg" id="adminAnnounceMsg" role="status" aria-live="polite"></div>
      <div id="adminAnnouncementsList" style="margin-top:16px"></div>
    </div>

    <div class="panel admin-section">
      <h3><svg class="icon" viewBox="0 0 24 24" style="color:var(--primary);fill:none;stroke:currentColor;stroke-width:2.2"><use href="#i-users"/></svg>Members &amp; balances</h3>
      <p>Approve, suspend, block, reset password or delete. Green dot = online in the last 90 seconds.</p>
      <div class="user-toolbar">
        <input type="text" id="userSearch" placeholder="Search username or phone…" style="max-width:300px;padding:12px 16px;border-radius:10px;border:1px solid var(--line-strong);background:var(--card);color:var(--text);outline:none" />
        <select id="userFilter" class="user-select">
          <option value="all">All statuses</option>
          <option value="pending">Pending</option>
          <option value="active">Active</option>
          <option value="suspended">Suspended</option>
          <option value="blocked">Blocked</option>
          <option value="online">Online now</option>
        </select>
      </div>
      <div id="userListAdmin"></div>
    </div>

    <div class="panel admin-section">
      <h3><svg class="icon" viewBox="0 0 24 24" style="color:var(--primary);fill:none;stroke:currentColor;stroke-width:2.2"><use href="#i-video"/></svg>Publish a new video</h3>
      <p>Paste a YouTube link, set title and reward, publish.</p>
      <form class="video-publish-form" id="videoForm" novalidate>
        <div class="field"><label for="vUrl">YouTube URL</label><input type="text" id="vUrl" placeholder="https://youtu.be/AWOXpzQzkp8" required /></div>
        <div class="field"><label for="vTitle">Title</label><input type="text" id="vTitle" placeholder="Sponsored video" required /></div>
        <div class="field"><label for="vReward">Reward (UGX)</label><input type="number" id="vReward" min="0" step="100" value="1900" required /></div>
        <button type="submit" class="btn btn-primary"><svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-play"/></svg>Publish</button>
      </form>
      <div class="auth-msg" id="videoMsg" role="status" aria-live="polite"></div>
      <div id="videoListAdmin" style="margin-top:14px"></div>
    </div>

    <div class="panel admin-section">
      <h3><svg class="icon" viewBox="0 0 24 24" style="color:var(--primary);fill:none;stroke:currentColor;stroke-width:2.2"><use href="#i-wallet"/></svg>Merchant IDs</h3>
      <div id="merchantListAdmin"></div>
    </div>

    <div class="panel admin-section">
      <h3><svg class="icon" viewBox="0 0 24 24" style="color:var(--primary);fill:none;stroke:currentColor;stroke-width:2.2"><use href="#i-lock"/></svg>Change admin password</h3>
      <p>Stored hashed. Other admin sessions signed out.</p>
      <form id="adminChangePwForm" novalidate style="max-width:520px;margin-top:14px">
        <div class="pw-section">
          <input type="password" id="adminCurPw" placeholder="Current admin password" required />
          <input type="password" id="adminNewPw" placeholder="New password (min 8 chars)" required />
        </div>
        <button type="submit" class="btn btn-primary" style="margin-top:12px"><svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-lock"/></svg>Update admin password</button>
      </form>
      <div class="auth-msg" id="adminChangePwMsg" role="status" aria-live="polite"></div>
    </div>
    <div style="height:40px"></div>
  </div></section>

  <!-- ═══════════ ABOUT ═══════════ -->
  <section class="page" data-page="about"><div class="container">
    <div class="page-head"><span class="eyebrow">About us</span><h1>Built for everyday earners</h1><p>Mobilearn is operated by Mobilelabs UG.</p></div>
    <div class="section"><div class="grid-2">
      <div class="panel"><h3><svg class="icon" viewBox="0 0 24 24"><use href="#i-zap"/></svg>Our mission</h3><p>Give anyone with an Airtel phone a fair way to earn. No CVs, no interviews, no capital — just sponsored YouTube videos that pay.</p></div>
      <div class="panel"><h3><svg class="icon" viewBox="0 0 24 24"><use href="#i-shield-check"/></svg>How we work</h3><p>We partner with verified brands and pay members directly. Every reward is tracked in your dashboard; verification, withdrawals and support happen inside the app.</p></div>
    </div></div>
  </div></section>

  <!-- ═══════════ CONTACT ═══════════ -->
  <section class="page" data-page="contact"><div class="container">
    <div class="page-head"><span class="eyebrow">Contact</span><h1>We're here to help</h1></div>
    <div class="section"><div class="panel" style="max-width:600px;margin:0 auto">
      <h3><svg class="icon" viewBox="0 0 24 24"><use href="#i-mail"/></svg>Support</h3>
      <p style="margin-top:12px"><b>Email:</b> support@mobilelabs.ug</p>
      <p style="margin-top:8px"><b>WhatsApp:</b> <a href="https://wa.me/256747943247" style="color:var(--whatsapp-deep);font-weight:800;font-family:var(--mono)">+256 747 943 247</a></p>
      <p style="margin-top:8px"><b>In-app:</b> log in and open your <a href="#/inbox" style="color:var(--primary);font-weight:700">Inbox</a> to message admin.</p>
      <p style="margin-top:8px"><b>Hours:</b> Mon–Sat, 8:00am – 8:00pm EAT</p>
    </div></div>
  </div></section>

  <!-- ═══════════ LEGAL ═══════════ -->
  <section class="page" data-page="legal"><div class="container">
    <div class="page-head"><span class="eyebrow">Legal</span><h1>Terms, privacy &amp; payouts</h1></div>
    <div class="section" style="max-width:800px;margin-inline:auto"><div class="panel">
      <div style="padding:20px 0;border-bottom:1px solid var(--line)"><h2 style="font-size:1.15rem;font-weight:800;margin-bottom:8px">Terms</h2><p style="color:var(--muted);font-size:.93rem">Airtel Uganda only. Activation UGX 19,500 via *185*9# merchant <b style="font-family:var(--mono)">7285061</b>. Rewards paid once per video and require full viewing. Withdrawals from UGX 20,000, admin approval required.</p></div>
      <div style="padding:20px 0;border-bottom:1px solid var(--line)"><h2 style="font-size:1.15rem;font-weight:800;margin-bottom:8px">Privacy</h2><p style="color:var(--muted);font-size:.93rem">We collect username, phone and merchant ID. Passwords stored hashed with salt. Messages, requests and withdrawals are stored for admin support only.</p></div>
      <div style="padding:20px 0"><h2 style="font-size:1.15rem;font-weight:800;margin-bottom:8px">Verification</h2><p style="color:var(--muted);font-size:.93rem">Rewards are auto-tracked server-side. Submit a verification request in the Inbox to flag them for admin approval.</p></div>
    </div></div>
  </div></section>
</main>

<footer><div class="container">
  <div class="foot-grid">
    <div class="foot-brand"><a href="#/home" class="logo"><span class="logo-mark"><svg class="icon" viewBox="0 0 24 24"><path d="M3 17l5-6 4 3 5-7 4 4"/></svg></span>Mobilearn</a><p>Watch YouTube. Get paid. Powered by Mobilelabs UG.</p></div>
    <div class="foot-col"><h4>Platform</h4><a href="#/home">Home</a><a href="#/how">How it works</a><a href="#/signup">Create account</a><a href="#/login">Log in</a></div>
    <div class="foot-col"><h4>Company</h4><a href="#/about">About</a><a href="#/contact">Contact</a><a href="#/admin">Admin console</a></div>
    <div class="foot-col"><h4>Legal</h4><a href="#/legal">Terms</a><a href="#/legal">Privacy</a></div>
  </div>
  <div class="foot-bottom"><span>© <span id="year">2025</span> Mobilearn. All rights reserved.</span><span style="color:var(--muted)">Powered by <b style="color:var(--primary)">Mobilelabs UG</b></span></div>
</div></footer>

<script>
(function () {
  "use strict";
  const PHONE_RE = /^(\+?256|0)(70|74|75|76)\d{7}$/;
  const DEFAULT_REWARD = 1900;
  const POLL_MS = 500, SEEK_TOLERANCE = 5, DRIFT_LIMIT = 10;
  const UNREAD_POLL_MS = 15000;
  const ADMIN_POLL_MS = 30000;
  const REF_STORAGE_KEY = "ml_ref";

  let authToken  = localStorage.getItem("ml_member_token") || null;
  let adminToken = localStorage.getItem("ml_admin_token")    || null;
  let currentUser = null, authorized = false, displayName = "User";
  let adminConvUser = null;
  let referralLink = "";

  const seenMsgIds = new Set();
  const seenAnnIds = new Set();
  let inboxInitialized = false;
  let audioCtx = null;

  // ─── THEME TOGGLE ─────────────────────────────────
  (function setupTheme() {
    const btn = document.getElementById("themeToggle");
    if (!btn) return;
    btn.addEventListener("click", () => {
      const cur = document.documentElement.getAttribute("data-theme") || "light";
      const next = cur === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      try { localStorage.setItem("ml_theme", next); } catch(e) {}
    });
  })();

  const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const fmt = n => "UGX " + Math.round(Number(n) || 0).toLocaleString("en-US");
  const fmt2 = n => "UGX " + Number(n || 0).toLocaleString("en-US");
  const tfmt = ts => ts ? new Date(ts * 1000).toLocaleString() : "";

  async function api(path, options = {}, token = null) {
    const headers = { "Content-Type": "application/json" };
    if (token) headers["Authorization"] = "Bearer " + token;
    const res = await fetch(path, { ...options, headers });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw Object.assign({ status: res.status }, data);
    return data;
  }
  async function memberFetch(p, o = {}) {
    try { return await api(p, o, authToken); }
    catch (e) { if (e.status === 401) { clearMemberAuth(); location.hash = "#/login"; } throw e; }
  }
  async function adminFetch(p, o = {}) {
    try { return await api(p, o, adminToken); }
    catch (e) { if (e.status === 401) { clearAdminAuth(); location.hash = "#/admin"; } throw e; }
  }
  function clearMemberAuth() {
    authToken = null; currentUser = null; authorized = false;
    localStorage.removeItem("ml_member_token");
    setAuthorizedUI(false); setUnreadBadge(0);
    seenMsgIds.clear(); seenAnnIds.clear(); inboxInitialized = false;
  }
  function clearAdminAuth() { adminToken = null; localStorage.removeItem("ml_admin_token"); }

  function setBtnLoading(btn, loading, text) {
    if (!btn) return;
    if (loading) {
      if (!btn.dataset.origHtml) btn.dataset.origHtml = btn.innerHTML;
      btn.disabled = true;
      btn.classList.add("loading");
      btn.innerHTML = '<span class="spinner"></span><span>' + (text || "Please wait…") + '</span>';
    } else {
      btn.disabled = false;
      btn.classList.remove("loading");
      if (btn.dataset.origHtml) { btn.innerHTML = btn.dataset.origHtml; delete btn.dataset.origHtml; }
    }
  }

  function unlockAudio() {
    if (!audioCtx) { try { audioCtx = new (window.AudioContext || window.webkitAudioContext)(); } catch {} }
    if (audioCtx && audioCtx.state === "suspended") { try { audioCtx.resume(); } catch {} }
  }
  document.addEventListener("click", unlockAudio, { once: true });
  document.addEventListener("touchstart", unlockAudio, { once: true });

  function playChime() {
    try {
      if (!audioCtx) unlockAudio();
      if (!audioCtx) return;
      const now = audioCtx.currentTime;
      [880, 1174].forEach((freq, i) => {
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.type = "sine"; osc.frequency.value = freq;
        const t = now + i * 0.13;
        gain.gain.setValueAtTime(0, t);
        gain.gain.linearRampToValueAtTime(0.18, t + 0.02);
        gain.gain.exponentialRampToValueAtTime(0.001, t + 0.30);
        osc.connect(gain); gain.connect(audioCtx.destination);
        osc.start(t); osc.stop(t + 0.32);
      });
    } catch {}
  }

  function canNotify() { return ("Notification" in window) && Notification.permission === "granted"; }
  async function ensureNotifyPermission() {
    if (!("Notification" in window)) return false;
    if (Notification.permission === "granted") return true;
    if (Notification.permission === "denied") return false;
    try { return (await Notification.requestPermission()) === "granted"; } catch { return false; }
  }
  function showNativeNotification(title, body, tag) {
    if (!canNotify()) return;
    try {
      const n = new Notification(title, {
        body: body || "", tag: tag || ("ml-" + Date.now()),
        icon: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='14' fill='%231e40af'/%3E%3Cpath d='M12 46l14-16 10 8 14-20 10 10' fill='none' stroke='%23fff' stroke-width='6' stroke-linecap='round'/%3E%3C/svg%3E",
        requireInteraction: false, silent: false,
      });
      n.onclick = () => { try { window.focus(); location.hash = "#/inbox"; n.close(); } catch {} };
      setTimeout(() => { try { n.close(); } catch {} }, 8000);
    } catch {}
  }

  function updateNotifBanner() {
    const banner = document.getElementById("notifBanner");
    const txt = document.getElementById("notifBannerText");
    const btn = document.getElementById("notifEnableBtn");
    if (!banner) return;
    if (!("Notification" in window)) {
      banner.classList.add("show", "denied");
      if (txt) txt.textContent = "Your browser doesn't support notifications. In-app alerts still work.";
      if (btn) btn.style.display = "none";
      return;
    }
    if (Notification.permission === "granted") {
      banner.classList.add("show", "active");
      banner.classList.remove("denied");
      if (txt) txt.textContent = "Alerts on — you'll hear a chime and see popups when admin messages you.";
      if (btn) btn.style.display = "none";
      setTimeout(() => banner.classList.remove("show"), 4000);
    } else if (Notification.permission === "denied") {
      banner.classList.add("show", "denied");
      banner.classList.remove("active");
      if (txt) txt.textContent = "Alerts are blocked. Enable notifications for this site in your phone settings to hear alerts.";
      if (btn) { btn.style.display = ""; btn.textContent = "How?"; }
    } else {
      banner.classList.add("show");
      banner.classList.remove("active", "denied");
      if (txt) txt.textContent = "Hear a chime and see popups on your phone when admin sends you a message or announcement.";
      if (btn) btn.style.display = "";
    }
  }
  document.addEventListener("click", (e) => {
    if (e.target && e.target.id === "notifEnableBtn") {
      ensureNotifyPermission().then(updateNotifBanner);
      unlockAudio();
    }
  });

  async function pollInbox() {
    if (!authorized || !authToken) return;
    try {
      const data = await api("/api/inbox", {}, authToken);
      setUnreadBadge(data.unread || 0);
      if (!inboxInitialized) {
        (data.messages || []).forEach(m => seenMsgIds.add(m.id));
        (data.announcements || []).forEach(a => seenAnnIds.add(a.id));
        inboxInitialized = true;
        return;
      }
      let newly = 0;
      (data.messages || []).forEach(m => {
        if (!seenMsgIds.has(m.id)) {
          seenMsgIds.add(m.id);
          if (m.from_username === "admin") {
            newly++; playChime();
            showNativeNotification("Mobilearn — new message from admin", m.body.slice(0, 140), "msg-" + m.id);
          }
        }
      });
      (data.announcements || []).forEach(a => {
        if (!seenAnnIds.has(a.id)) {
          seenAnnIds.add(a.id); newly++; playChime();
          showNativeNotification("Mobilearn — " + (a.title || "Announcement"), (a.body || "").slice(0, 140), "ann-" + a.id);
        }
      });
      if (newly > 0 && currentRoute() === "inbox") loadInbox();
    } catch {}
  }

  // ─── ROUTING ──────────────────────────────────────
  document.getElementById("year").textContent = new Date().getFullYear();
  const nav = document.getElementById("nav");
  window.addEventListener("scroll", () => nav.classList.toggle("scrolled", window.scrollY > 8), { passive: true });
  const burger = document.getElementById("burger"), menu = document.getElementById("mobileMenu");
  burger.addEventListener("click", () => {
    const open = burger.getAttribute("aria-expanded") === "true";
    burger.setAttribute("aria-expanded", String(!open));
    menu.classList.toggle("open", !open);
  });
  menu.querySelectorAll("a").forEach(a => a.addEventListener("click", () => { menu.classList.remove("open"); burger.setAttribute("aria-expanded", "false"); }));

  const navDashboard = document.getElementById("navDashboard");
  const mobileDashboard = document.getElementById("mobileDashboard");
  const navInbox = document.getElementById("navInbox");
  const mobileInbox = document.getElementById("mobileInbox");
  const inboxBadge = document.getElementById("inboxBadge");
  const mobileInboxBadge = document.getElementById("mobileInboxBadge");

  function setAuthorizedUI(on) {
    navDashboard.style.display = on ? "" : "none";
    mobileDashboard.style.display = on ? "" : "none";
    navInbox.style.display = on ? "" : "none";
    mobileInbox.style.display = on ? "" : "none";
    const el = document.getElementById("dashUser");
    if (el) el.textContent = displayName;
    const dv = document.getElementById("drawerUser");
    if (dv) dv.textContent = displayName;
    const av = document.getElementById("drawerAvatar");
    if (av) av.textContent = (displayName || "U").charAt(0).toUpperCase();
  }
  function setUnreadBadge(n) {
    [inboxBadge, mobileInboxBadge].forEach(b => {
      if (!b) return;
      if (n > 0) { b.textContent = n > 99 ? "99+" : String(n); b.classList.add("on"); }
      else b.classList.remove("on");
    });
    const bell = document.getElementById("dashBellBadge");
    if (bell) {
      if (n > 0) { bell.textContent = n > 99 ? "99+" : String(n); bell.classList.add("on"); }
      else bell.classList.remove("on");
    }
    const qn = document.getElementById("qnInboxBadge");
    if (qn) {
      if (n > 0) { qn.textContent = n > 99 ? "99+" : String(n); qn.classList.add("on"); }
      else qn.classList.remove("on");
    }
    const dn = document.getElementById("drawerInboxBadge");
    if (dn) {
      if (n > 0) { dn.textContent = n > 99 ? "99+" : String(n); dn.classList.add("on"); }
      else dn.classList.remove("on");
    }
  }

  // ─── DRAWER ────────────────────────────────────────
  const dashDrawer = document.getElementById("dashDrawer");
  const dashDrawerOverlay = document.getElementById("dashDrawerOverlay");
  const dashBurger = document.getElementById("dashBurger");
  function openDrawer() {
    if (!dashDrawer) return;
    dashDrawer.classList.add("open");
    dashDrawerOverlay.classList.add("open");
    dashDrawer.setAttribute("aria-hidden", "false");
    dashBurger.setAttribute("aria-expanded", "true");
    document.body.style.overflow = "hidden";
  }
  function closeDrawer() {
    if (!dashDrawer) return;
    dashDrawer.classList.remove("open");
    dashDrawerOverlay.classList.remove("open");
    dashDrawer.setAttribute("aria-hidden", "true");
    dashBurger.setAttribute("aria-expanded", "false");
    document.body.style.overflow = "";
  }
  dashBurger?.addEventListener("click", () => {
    dashDrawer.classList.contains("open") ? closeDrawer() : openDrawer();
  });
  dashDrawerOverlay?.addEventListener("click", closeDrawer);
  dashDrawer?.querySelectorAll("a").forEach(a => a.addEventListener("click", () => closeDrawer()));
  document.getElementById("drawerLogout")?.addEventListener("click", async () => {
    closeDrawer();
    try { await memberFetch("/api/logout", { method: "POST" }); } catch {}
    clearMemberAuth(); location.hash = "#/home";
  });
  document.getElementById("dashBell")?.addEventListener("click", () => { location.hash = "#/inbox"; });

  document.addEventListener("click", (e) => {
    const link = e.target.closest("[data-dash-link]");
    if (!link) return;
    const hash = link.getAttribute("href");
    if (!hash || !hash.startsWith("#sec-")) return;
    e.preventDefault();
    closeDrawer();
    const target = document.querySelector(hash);
    if (target) target.scrollIntoView({ behavior: "smooth", block: "start" });
    history.replaceState(null, "", "#/dashboard");
  });

  function captureReferral() {
    try {
      const hashQ = (location.hash.split("?")[1] || "");
      const urlQ  = location.search.replace(/^\?/, "");
      const parse = qs => new URLSearchParams(qs).get("ref");
      const ref = (parse(hashQ) || parse(urlQ) || "").toUpperCase();
      if (ref) {
        localStorage.setItem(REF_STORAGE_KEY, ref);
        const banner = document.getElementById("refBanner");
        if (banner) banner.style.display = "block";
      } else if (localStorage.getItem(REF_STORAGE_KEY)) {
        const banner = document.getElementById("refBanner");
        if (banner) banner.style.display = "block";
      }
    } catch {}
  }
  function getStoredRef() { try { return (localStorage.getItem(REF_STORAGE_KEY) || "").toUpperCase(); } catch { return ""; } }
  function clearStoredRef() { try { localStorage.removeItem(REF_STORAGE_KEY); } catch {} }

  const pages = document.querySelectorAll(".page");
  const routes = ["home","how","signup","login","forgot","dashboard","inbox","about","contact","legal","admin","adminDashboard"];
  const titles = { home:"Watch YouTube. Get Paid.", how:"How it works", signup:"Create account",
    login:"Log in", forgot:"Reset password", dashboard:"Dashboard", inbox:"Inbox", about:"About", contact:"Contact",
    legal:"Terms", admin:"Admin login", adminDashboard:"Admin console" };
  if (!location.hash) history.replaceState(null, "", "#/home");
  function currentRoute() {
    const raw = location.hash.replace(/^#\/?/, "").split("?")[0];
    if (raw === "admin/dashboard") return "adminDashboard";
    return routes.includes(raw) ? raw : "home";
  }
  function render() {
    const route = currentRoute();
    if ((route === "dashboard" || route === "inbox") && !(authorized && currentUser)) { location.hash = "#/login"; return; }
    if (route === "adminDashboard" && !adminToken) { location.hash = "#/admin"; return; }
    if (route === "admin" && adminToken) { location.hash = "#/admin/dashboard"; return; }

    pages.forEach(p => p.classList.toggle("active", p.dataset.page === route));
    document.querySelectorAll("[data-nav]").forEach(link => {
      const isActive = link.getAttribute("href") === "#/" + route;
      link.classList.toggle("active", isActive);
    });
    document.title = titles[route] + " — Mobilearn";
    window.scrollTo(0, 0);
    menu.classList.remove("open");
    burger.setAttribute("aria-expanded", "false");
    if (dashDrawer && dashDrawer.classList.contains("open")) closeDrawer();

    if (route === "signup") captureReferral();
    if (route === "dashboard") {
      paintDash(); loadMemberVideos(); loadMerchant(); loadWithdrawals(); loadReferrals();
      loadBanners(); loadChallenges(); loadLeaderboard(); updateNotifBanner();
    }
    if (route === "inbox") loadInbox();
    if (route === "adminDashboard") {
      renderAdminKpis(); renderAdminSettings(); renderAdminMonitor();
      renderAdminUsers(); renderAdminVideos(); renderAdminMerchants();
      renderAdminConversations(); renderAdminAnnouncements(); renderAdminDealRequests();
      renderAdminWithdrawals(); renderAdminBanners(); renderAdminChallenges();
    }
  }
  window.addEventListener("hashchange", render);

  document.querySelectorAll("[data-copy]").forEach(btn => {
    btn.addEventListener("click", async (e) => {
      e.preventDefault();
      const code = btn.getAttribute("data-copy"), orig = btn.innerHTML;
      try {
        if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(code);
        else { const t = document.createElement("textarea"); t.value = code; document.body.appendChild(t); t.select(); document.execCommand("copy"); document.body.removeChild(t); }
        btn.innerHTML = '<svg class="icon" viewBox="0 0 24 24"><use href="#i-check"/></svg>Copied!';
        setTimeout(() => { btn.innerHTML = orig; }, 1500);
      } catch {}
    });
  });

  async function paintDash() {
    try {
      const me = await memberFetch("/api/me");
      currentUser = me;
      document.getElementById("dashBalance").textContent = fmt(me.balance);
      updateVerifyChip(!!me.verified, Number(me.balance) || 0);
      displayName = me.username;
      setAuthorizedUI(true);
      setUnreadBadge(me.unread || 0);
      const dr = document.getElementById("drawerBalance");
      if (dr) dr.textContent = fmt(me.balance);
    } catch {}
  }
  function updateVerifyChip(verified, balance) {
    const chip = document.getElementById("verifyStatus"), txt = document.getElementById("verifyText");
    if (verified) { chip.textContent = "Verified"; chip.className = "status-active"; txt.textContent = "Your earnings are verified"; }
    else if (balance > 0) { chip.textContent = "Pending verification"; chip.className = "status-active status-pending"; txt.textContent = "Submit a verification request in your Inbox"; }
    else { chip.textContent = "Account active"; chip.className = "status-active"; txt.textContent = "Watch a full video to earn " + fmt(DEFAULT_REWARD); }
  }

  // ─── BANNERS ────────────────────────────────────────
  async function loadBanners() {
    try {
      const banners = await memberFetch("/api/banners");
      const ad = document.getElementById("bannerAd");
      const img = document.getElementById("bannerImg");
      if (!ad || !img) return;
      if (!banners || !banners.length) { ad.style.display = "none"; return; }
      const b = banners[0];
      img.src = b.image_url;
      img.alt = b.title || "Sponsored";
      ad.href = b.link_url || "#/home";
      ad.style.display = "block";
      ad.onclick = b.link_url ? null : (e => e.preventDefault());
    } catch {}
  }

  // ─── LEADERBOARD ─────────────────────────────────
  async function loadLeaderboard() {
    const el = document.getElementById("leaderboardList");
    const meEl = document.getElementById("leaderboardMe");
    if (!el) return;
    try {
      const data = await memberFetch("/api/leaderboard");
      const list = data.leaderboard || [];
      if (!list.length) {
        el.innerHTML = '<div class="empty-state">No earners yet — be the first on the board!</div>';
      } else {
        el.innerHTML = list.map(e => {
          const isMe = currentUser && e.username === currentUser.username;
          const medal = e.rank === 1 ? "🥇" : e.rank === 2 ? "🥈" : e.rank === 3 ? "🥉" : "#" + e.rank;
          return '<div class="lb-row ' + (isMe ? 'me' : '') + '">' +
            '<span class="lb-rank">' + medal + '</span>' +
            '<span class="lb-name">' + esc(e.username) + (isMe ? ' <span class="badge badge-new">You</span>' : '') + '</span>' +
            '<span class="lb-amt">' + fmt(e.earned) + '</span></div>';
        }).join("");
      }
      if (meEl && data.me) {
        meEl.innerHTML = 'Your rank: <b>#' + data.me.rank + '</b> · Total earned: <b>' + fmt(data.me.earned) + '</b>';
      }
    } catch {
      el.innerHTML = '<div class="empty-state">Could not load leaderboard.</div>';
    }
  }

  // ─── CHALLENGES ──────────────────────────────────
  async function loadChallenges() {
    const el = document.getElementById("challengeList");
    if (!el) return;
    try {
      const list = await memberFetch("/api/challenges");
      if (!list.length) {
        el.innerHTML = '<div class="empty-state">No challenges right now — check back soon.</div>';
        return;
      }
      el.innerHTML = list.map(c => {
        const pct = Math.min(100, Math.round((c.progress / c.goal_value) * 100));
        let action;
        if (c.claimed) action = '<button class="watch-btn earned" disabled><svg class="icon" viewBox="0 0 24 24"><use href="#i-check"/></svg>Claimed</button>';
        else if (c.complete) action = '<button class="watch-btn" data-claim="' + esc(c.id) + '">Claim ' + fmt(c.reward) + '</button>';
        else action = '<span class="badge badge-pending">' + c.progress + ' / ' + c.goal_value + '</span>';
        return '<div class="challenge-card">' +
          '<div class="ch-head"><b>' + esc(c.title) + '</b><span class="video-reward">' + fmt(c.reward) + '</span></div>' +
          (c.description ? '<p>' + esc(c.description) + '</p>' : '') +
          '<div class="ch-progress"><i style="width:' + pct + '%"></i></div>' +
          '<div class="ch-foot"><small>' + (c.goal_type === 'referrals' ? 'Approved referrals' : 'Videos watched') + ': ' + c.progress + '/' + c.goal_value + '</small>' + action + '</div>' +
        '</div>';
      }).join("");
      el.querySelectorAll("[data-claim]").forEach(b => b.addEventListener("click", async () => {
        const msg = document.getElementById("challengeClaimMsg");
        if (msg) { msg.textContent = ""; msg.classList.remove("err"); }
        try {
          const r = await memberFetch("/api/challenges/" + b.getAttribute("data-claim") + "/claim", { method: "POST" });
          document.getElementById("dashBalance").textContent = fmt(r.balance);
          if (currentUser) currentUser.balance = r.balance;
          if (msg) msg.textContent = "✅ +" + fmt(r.reward) + " added to your balance!";
          loadChallenges(); loadLeaderboard(); loadWithdrawals();
        } catch (e) {
          if (msg) { msg.textContent = e.error || "Could not claim."; msg.classList.add("err"); }
        }
      }));
    } catch {
      el.innerHTML = '<div class="empty-state">Could not load challenges.</div>';
    }
  }

  // ─── YOUTUBE PLAYER ──────────────────────────────
  let ytPlayer = null, ytApiReady = false, ytPending = null;
  let currentVideo = null, watchMonitor = null, lastTick = null, watchedSeconds = 0, drift = 0;
  let memberVideos = [];
  const locallyLockedIds = new Set();

  function loadYouTubeAPI(cb) {
    if (ytApiReady) { cb(); return; }
    ytPending = cb;
    if (window.YT && window.YT.Player) { ytApiReady = true; cb(); return; }
    if (!document.getElementById("ytApiScript")) {
      const s = document.createElement("script"); s.id = "ytApiScript"; s.src = "https://www.youtube.com/iframe_api"; document.head.appendChild(s);
      window.onYouTubeIframeAPIReady = function () { ytApiReady = true; if (ytPending) { const fn = ytPending; ytPending = null; fn(); } };
    }
  }
  function setVideoStatus(html, cls) { const el = document.getElementById("videoStatus"); el.innerHTML = html; el.className = "video-status" + (cls ? " " + cls : ""); }
  function updateRewardBadge() {
    const b = document.getElementById("videoRewardBadge"); if (!b) return;
    if (currentVideo) {
      if (currentVideo.credited) { b.innerHTML = '<svg class="icon" viewBox="0 0 24 24"><use href="#i-check"/></svg>Earned'; b.classList.add("earned"); }
      else { b.innerHTML = '<svg class="icon" viewBox="0 0 24 24"><use href="#i-dollar"/></svg>+' + fmt(currentVideo.reward); b.classList.remove("earned"); }
    } else {
      b.innerHTML = '<svg class="icon" viewBox="0 0 24 24"><use href="#i-dollar"/></svg>+' + fmt(DEFAULT_REWARD); b.classList.remove("earned");
    }
  }
  function paintWatchProgress(r) { const w = document.getElementById("videoProgress"); if (!w) return; w.classList.toggle("on", !!currentVideo && !currentVideo.credited); const bar = w.querySelector("i"); if (bar) bar.style.width = Math.max(0, Math.min(100, r * 100)).toFixed(1) + "%"; }
  function stopWatchMonitor() { if (watchMonitor) { clearInterval(watchMonitor); watchMonitor = null; } }
  function resetWatchTracking() { stopWatchMonitor(); lastTick = null; watchedSeconds = 0; drift = 0; paintWatchProgress(0); }
  function startWatchMonitor() { if (watchMonitor || !ytPlayer) return; lastTick = { time: ytPlayer.getCurrentTime(), wall: Date.now() }; watchMonitor = setInterval(tickWatch, POLL_MS); }
  function tickWatch() {
    if (!ytPlayer || !currentVideo) return;
    if (typeof ytPlayer.getCurrentTime !== "function") return;
    let t, dur;
    try { t = ytPlayer.getCurrentTime(); dur = ytPlayer.getDuration() || 0; } catch { return; }
    const now = Date.now();
    if (!lastTick) { lastTick = { time: t, wall: now }; return; }
    const elapsed = (now - lastTick.wall) / 1000, delta = t - lastTick.time;
    if (delta > elapsed + SEEK_TOLERANCE) { handleSkip("Skipping detected"); return; }
    if (delta > 0) { drift += delta - elapsed; watchedSeconds += Math.min(delta, elapsed + 0.2); if (drift > DRIFT_LIMIT) { handleSkip("Fast-forwarding detected"); return; } }
    else if (delta < -1) drift = 0;
    lastTick = { time: t, wall: now };
    paintWatchProgress(dur ? watchedSeconds / dur : 0);
  }
  function handleSkip(reason) {
    stopWatchMonitor(); lastTick = null; watchedSeconds = 0; drift = 0; paintWatchProgress(0);
    try { ytPlayer.pauseVideo(); ytPlayer.seekTo(0, true); } catch {}
    setVideoStatus('<svg class="icon" viewBox="0 0 24 24"><use href="#i-shield-check"/></svg>' + reason + ' — video restarted. Watch to the end to earn.', "paused");
  }
  function handleVideoState(e) {
    if (!currentVideo || !window.YT) return;
    const S = YT.PlayerState;
    if (e.data === S.PLAYING) {
      if (currentVideo.credited || locallyLockedIds.has(currentVideo.id)) {
        try { ytPlayer.pauseVideo(); } catch {}
        setVideoStatus('<svg class="icon" viewBox="0 0 24 24"><use href="#i-check"/></svg>This video is already earned. Pick another.', "earned");
        return;
      }
      startWatchMonitor();
      setVideoStatus('<svg class="icon" viewBox="0 0 24 24"><use href="#i-play"/></svg>Playing… finish the video to earn ' + fmt(currentVideo.reward), "playing");
    }
    else if (e.data === S.PAUSED) { stopWatchMonitor(); lastTick = null; setVideoStatus('<svg class="icon" viewBox="0 0 24 24"><use href="#i-play"/></svg>Paused — keep watching to earn.', "paused"); }
    else if (e.data === S.ENDED) { stopWatchMonitor(); lastTick = null; creditCurrentVideo(); }
    else { stopWatchMonitor(); lastTick = null; }
  }
  async function creditCurrentVideo() {
    const vid = currentVideo;
    if (!vid) return;
    if (vid.credited || locallyLockedIds.has(vid.id)) { setVideoStatus('<svg class="icon" viewBox="0 0 24 24"><use href="#i-check"/></svg>You already earned from this video.', "earned"); return; }
    locallyLockedIds.add(vid.id);
    setVideoStatus('<svg class="icon" viewBox="0 0 24 24"><use href="#i-shield-check"/></svg>Verifying reward…', "playing");
    try {
      const result = await memberFetch("/api/credit", { method: "POST", body: JSON.stringify({ video_id: vid.id }) });
      vid.credited = true;
      if (currentUser) currentUser.balance = result.balance;
      document.getElementById("dashBalance").textContent = fmt(result.balance);
      updateVerifyChip(false, result.balance);
      setVideoStatus('<svg class="icon" viewBox="0 0 24 24"><use href="#i-check"/></svg>+' + fmt(result.reward) + " earned! This video is now locked.", "earned");
      updateRewardBadge();
      disposePlayer();
      renderMemberVideos();
      loadWithdrawals(); loadLeaderboard(); loadChallenges();
      setTimeout(() => loadMemberVideos(), 300);
    } catch (e) {
      if (e.status === 409) {
        vid.credited = true;
        setVideoStatus('<svg class="icon" viewBox="0 0 24 24"><use href="#i-check"/></svg>Already earned from this video.', "earned");
        updateRewardBadge(); disposePlayer(); renderMemberVideos();
      } else {
        locallyLockedIds.delete(vid.id);
        setVideoStatus('<svg class="icon" viewBox="0 0 24 24"><use href="#i-info"/></svg>' + (e.error || "Could not credit reward."), "paused");
      }
    }
  }
  function disposePlayer() {
    try { if (ytPlayer && typeof ytPlayer.destroy === "function") ytPlayer.destroy(); } catch {}
    ytPlayer = null;
    const frame = document.getElementById("videoFrame") || document.querySelector(".video-frame");
    if (frame) frame.innerHTML = '<div id="ytPlayer"></div><div class="placeholder" id="videoPlaceholder">Choose a video below to start earning.</div>';
    paintWatchProgress(0);
  }
  function ensurePlayer(video) {
    if (!video || video.credited || locallyLockedIds.has(video.id)) {
      setVideoStatus('<svg class="icon" viewBox="0 0 24 24"><use href="#i-check"/></svg>You already earned from this video. Pick another.', "earned");
      return;
    }
    currentVideo = video; updateRewardBadge(); resetWatchTracking();
    loadYouTubeAPI(() => {
      if (ytPlayer && typeof ytPlayer.loadVideoById === "function") { try { ytPlayer.loadVideoById(video.video_id); } catch {} return; }
      const ph = document.getElementById("videoPlaceholder"); if (ph) ph.style.display = "none";
      try { ytPlayer = new YT.Player("ytPlayer", { videoId: video.video_id, playerVars: { rel: 0, modestbranding: 1, playsinline: 1 }, events: { onStateChange: handleVideoState } }); } catch {}
    });
  }
  async function loadMemberVideo(video) {
    if (!video || video.credited || locallyLockedIds.has(video.id)) {
      currentVideo = video || null;
      setVideoStatus('<svg class="icon" viewBox="0 0 24 24"><use href="#i-check"/></svg>You already earned from this video. Pick another.', "earned");
      updateRewardBadge(); return;
    }
    try {
      const credits = await memberFetch("/api/credits");
      if (Array.isArray(credits) && credits.includes(video.id)) {
        video.credited = true; locallyLockedIds.add(video.id); renderMemberVideos();
        currentVideo = video;
        setVideoStatus('<svg class="icon" viewBox="0 0 24 24"><use href="#i-check"/></svg>You already earned from this video. Pick another.', "earned");
        updateRewardBadge(); return;
      }
    } catch {}
    setVideoStatus('<svg class="icon" viewBox="0 0 24 24"><use href="#i-play"/></svg>Press play — finish the video to earn ' + fmt(video.reward), "");
    ensurePlayer(video); renderMemberVideos();
    document.querySelector(".video-frame")?.scrollIntoView({ behavior: "smooth", block: "center" });
  }
  async function loadMemberVideos() {
    try {
      const videos = await memberFetch("/api/videos");
      const credits = await memberFetch("/api/credits");
      credits.forEach(id => locallyLockedIds.add(id));
      memberVideos = videos.map(v => ({ ...v, credited: credits.includes(v.id) || locallyLockedIds.has(v.id) }));
      renderMemberVideos();
    } catch {}
  }
  function renderMemberVideos() {
    const c = document.getElementById("videoListMember"); if (!c) return;
    if (!memberVideos.length) { c.innerHTML = '<div class="empty-state">No videos available right now.</div>'; return; }
    c.innerHTML = memberVideos.map(v => {
      const credited = !!v.credited, watching = !!currentVideo && currentVideo.id === v.id && !credited;
      const cls = (credited ? "earned " : "") + (watching ? "watching" : "");
      let btn;
      if (credited) btn = '<button class="watch-btn earned" data-watch="' + esc(v.id) + '" disabled><svg class="icon" viewBox="0 0 24 24"><use href="#i-check"/></svg>Earned</button>';
      else if (watching) btn = '<button class="watch-btn playing" data-watch="' + esc(v.id) + '"><svg class="icon" viewBox="0 0 24 24"><use href="#i-play"/></svg>Watching</button>';
      else btn = '<button class="watch-btn" data-watch="' + esc(v.id) + '"><svg class="icon" viewBox="0 0 24 24"><use href="#i-play"/></svg>Watch</button>';
      return '<div class="video-card ' + cls + '"><div class="thumb-wrap"><img class="thumb" src="https://i.ytimg.com/vi/' + esc(v.video_id) + '/mqdefault.jpg" alt="" loading="lazy" /></div><div class="meta"><b>' + esc(v.title) + '</b><small>' + (credited ? "Reward earned · Locked" : "Reward") + ' <span class="reward">+' + fmt(v.reward) + '</span></small></div><div class="actions">' + btn + '</div></div>';
    }).join("");
    c.querySelectorAll("[data-watch]:not([disabled])").forEach(btn => {
      btn.addEventListener("click", () => {
        const video = memberVideos.find(v => v.id === btn.getAttribute("data-watch"));
        if (!video || video.credited || locallyLockedIds.has(video.id)) return;
        if (currentVideo && currentVideo.id === video.id) { document.querySelector(".video-frame")?.scrollIntoView({ behavior: "smooth" }); return; }
        loadMemberVideo(video);
      });
    });
  }

  async function loadMerchant() {
    try {
      const data = await memberFetch("/api/merchant");
      const s = document.getElementById("merchantSaved");
      if (s) s.textContent = data.merchant_id ? "✅ Current merchant ID: " + data.merchant_id : "";
      const i = document.getElementById("merchantInput");
      if (i && !i.value && data.merchant_id) i.value = data.merchant_id;
      const wd = document.getElementById("wdMerchant");
      if (wd) wd.textContent = data.merchant_id || "Not saved";
    } catch {}
  }
  document.getElementById("merchantForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = e.target.querySelector('button[type="submit"]');
    const msg = document.getElementById("merchantMsg"), input = document.getElementById("merchantInput");
    msg.textContent = ""; msg.classList.remove("err");
    const clean = input.value.replace(/[\s\-()]/g, "");
    if (!clean) { msg.textContent = "Enter your Airtel merchant ID."; msg.classList.add("err"); return; }
    if (!PHONE_RE.test(clean)) { msg.textContent = "Invalid Airtel number."; msg.classList.add("err"); return; }
    setBtnLoading(btn, true, "Saving…");
    try { await memberFetch("/api/merchant", { method: "POST", body: JSON.stringify({ merchant_id: clean }) }); msg.textContent = "✅ Merchant ID saved: " + clean; loadMerchant(); loadWithdrawals(); }
    catch (err) { msg.textContent = err.error || "Could not save."; msg.classList.add("err"); }
    finally { setBtnLoading(btn, false); }
  });

  async function loadWithdrawals() {
    try {
      const data = await memberFetch("/api/withdrawals");
      const avail = document.getElementById("wdAvailable"); if (avail) avail.textContent = fmt(data.balance);
      const merchantEl = document.getElementById("wdMerchant"); if (merchantEl) merchantEl.textContent = data.merchant_id || "Not saved";
      const minEl = document.getElementById("wdMinNote"); if (minEl) minEl.textContent = "Minimum UGX " + (data.min || 20000).toLocaleString();
      const hist = document.getElementById("withdrawHistory");
      if (hist) {
        const list = data.withdrawals || [];
        if (!list.length) hist.innerHTML = "";
        else hist.innerHTML = '<div style="font-size:.72rem;font-weight:800;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin-bottom:6px">Recent requests</div>' +
          list.map(w => {
            const stBadge = w.status === 'pending' ? 'badge badge-pending' : w.status === 'approved' ? 'badge badge-live' : 'badge badge-danger';
            return '<div class="wd-row ' + esc(w.status) + '"><div style="min-width:0"><span class="wd-amt">' + fmt2(w.amount) + '</span><small>To ' + esc(w.merchant_id) + ' · ' + tfmt(w.created_at) + '</small>' + (w.admin_note ? '<small style="color:var(--primary)">Admin: ' + esc(w.admin_note) + '</small>' : '') + '</div><span class="' + stBadge + '">' + esc(w.status) + '</span></div>';
          }).join("");
      }
      const amt = document.getElementById("withdrawAmount");
      if (amt && !amt.value && data.balance >= (data.min || 20000)) amt.value = Math.floor(data.balance / 100) * 100;
    } catch {}
  }
  document.getElementById("withdrawForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = e.target.querySelector('button[type="submit"]');
    const msg = document.getElementById("withdrawMsg");
    const amt = parseFloat(document.getElementById("withdrawAmount").value);
    msg.textContent = ""; msg.classList.remove("err", "warn");
    if (!amt || amt < 20000) { msg.textContent = "Minimum withdrawal is UGX 20,000."; msg.classList.add("err"); return; }
    setBtnLoading(btn, true, "Submitting…");
    try {
      const r = await memberFetch("/api/withdraw", { method: "POST", body: JSON.stringify({ amount: amt }) });
      msg.textContent = "✅ " + (r.message || "Request submitted."); msg.classList.add("warn");
      document.getElementById("withdrawAmount").value = "";
      loadWithdrawals(); paintDash(); loadInbox?.();
    } catch (err) { msg.textContent = err.error || "Could not submit."; msg.classList.add("err"); }
    finally { setBtnLoading(btn, false); }
  });

  async function loadReferrals() {
    try {
      const data = await memberFetch("/api/referrals");
      const base = location.origin + "/";
      referralLink = base + "#/signup?ref=" + (data.code || "");
      document.getElementById("refLinkText").textContent = data.code || "—";
      document.getElementById("refTotal").textContent = data.referred_total || 0;
      document.getElementById("refCredited").textContent = data.credited_total || 0;
      document.getElementById("refEarned").textContent = fmt(data.earned || 0);
      const m = document.getElementById("refMsg");
      if (m) m.innerHTML = data.prefix ? ("<b>" + esc(data.prefix) + "</b> Share your code. When they sign up <b>and get approved by admin</b>, you earn UGX " + (data.bonus || 450) + " into your balance — real money, instantly.") : "Share your code to earn.";
    } catch {}
  }
  document.getElementById("refCopyBtn")?.addEventListener("click", async () => {
    if (!referralLink) return;
    const btn = document.getElementById("refCopyBtn"), orig = btn.innerHTML;
    try {
      if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(referralLink);
      else { const t = document.createElement("textarea"); t.value = referralLink; document.body.appendChild(t); t.select(); document.execCommand("copy"); document.body.removeChild(t); }
      btn.innerHTML = '<svg class="icon" viewBox="0 0 24 24"><use href="#i-check"/></svg>Link copied!';
      setTimeout(() => { btn.innerHTML = orig; }, 1600);
    } catch { window.prompt("Copy your referral link:", referralLink); btn.innerHTML = orig; }
  });

  document.getElementById("changePwForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = e.target.querySelector('button[type="submit"]');
    const msg = document.getElementById("changePwMsg"), cur = document.getElementById("curPw").value, nw = document.getElementById("newPw").value;
    msg.textContent = ""; msg.classList.remove("err");
    if (nw.length < 6) { msg.textContent = "New password must be at least 6 characters."; msg.classList.add("err"); return; }
    setBtnLoading(btn, true, "Updating…");
    try { await memberFetch("/api/change-password", { method: "POST", body: JSON.stringify({ current_password: cur, new_password: nw }) }); msg.textContent = "✅ Password updated."; e.target.reset(); }
    catch (err) { msg.textContent = err.error || "Could not update password."; msg.classList.add("err"); }
    finally { setBtnLoading(btn, false); }
  });

  function renderChat(container, msgs, myName) {
    if (!container) return;
    if (!msgs.length) { container.innerHTML = ''; return; }
    container.innerHTML = msgs.map(m => {
      const mine = m.from_username === myName;
      return '<div class="msg ' + (mine ? "me" : "them") + '">' + esc(m.body) + '<span class="msg-meta">' + (mine ? "You" : esc(m.from_username)) + ' · ' + tfmt(m.created_at) + '</span></div>';
    }).join("");
    container.scrollTop = container.scrollHeight;
  }
  async function loadInbox() {
    if (!authorized) return;
    try {
      const data = await memberFetch("/api/inbox");
      setUnreadBadge(data.unread || 0);
      const annEl = document.getElementById("memberAnnouncements");
      if (data.announcements && data.announcements.length) {
        annEl.innerHTML = data.announcements.map(a => '<div class="announcement ' + (a.is_read ? '' : 'unread') + '"><h4><svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-megaphone"/></svg>' + esc(a.title) + '</h4><p>' + esc(a.body) + '</p><div class="when">' + tfmt(a.created_at) + (a.is_read ? '' : ' · NEW') + '</div></div>').join("");
      } else { annEl.innerHTML = '<div class="empty-state">No announcements yet.</div>'; }
      renderChat(document.getElementById("memberChat"), data.messages || [], currentUser?.username || '');
      const reqEl = document.getElementById("myDealRequests");
      const reqs = data.deal_requests || [];
      if (!reqs.length) reqEl.innerHTML = '';
      else reqEl.innerHTML = '<div style="font-size:.78rem;font-weight:800;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin-bottom:8px">Your recent requests</div>' + reqs.map(r => {
        const st = r.status === 'pending' ? 'badge badge-pending' : 'badge badge-live';
        return '<div class="req-row ' + r.status + '"><div style="flex:1;min-width:200px"><b>' + esc(r.kind.charAt(0).toUpperCase() + r.kind.slice(1)) + '</b><small>' + esc(r.message) + '</small>' + (r.admin_note ? '<small style="color:var(--primary)"><b>Admin:</b> ' + esc(r.admin_note) + '</small>' : '') + '</div><span class="' + st + '">' + esc(r.status) + '</span></div>';
      }).join("");
    } catch {}
  }
  document.getElementById("inboxMarkRead")?.addEventListener("click", async () => {
    try { await memberFetch("/api/inbox/mark-read", { method: "POST" }); setUnreadBadge(0); loadInbox(); } catch {}
  });
  document.getElementById("memberChatForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const input = document.getElementById("memberChatInput"), msg = document.getElementById("memberChatMsg");
    const body = input.value.trim(); if (!body) return;
    msg.textContent = ""; msg.classList.remove("err");
    try { await memberFetch("/api/inbox/message", { method: "POST", body: JSON.stringify({ body }) }); input.value = ""; loadInbox(); }
    catch (err) { msg.textContent = err.error || "Could not send."; msg.classList.add("err"); }
  });
  document.getElementById("dealRequestForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = e.target.querySelector('button[type="submit"]');
    const kind = document.getElementById("drKind").value;
    const message = document.getElementById("drMessage").value.trim();
    const video = document.getElementById("drVideo").value.trim();
    const msg = document.getElementById("dealRequestMsg");
    msg.textContent = ""; msg.classList.remove("err");
    if (message.length < 5) { msg.textContent = "Describe your request (5+ characters)."; msg.classList.add("err"); return; }
    setBtnLoading(btn, true, "Sending…");
    try { await memberFetch("/api/deal-request", { method: "POST", body: JSON.stringify({ kind, message, video_id: video || null }) }); msg.textContent = "✅ Request sent to admin. You'll see a reply here."; e.target.reset(); loadInbox(); }
    catch (err) { msg.textContent = err.error || "Could not send request."; msg.classList.add("err"); }
    finally { setBtnLoading(btn, false); }
  });

  document.getElementById("signup").addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = e.target.querySelector('button[type="submit"]');
    const msg = document.getElementById("formMsg");
    msg.textContent = ""; msg.classList.remove("err");
    const userVal = document.getElementById("username").value.trim();
    const phoneVal = document.getElementById("phone").value.replace(/[\s\-()]/g, "");
    const passVal = document.getElementById("password").value;
    const confirmVal = document.getElementById("confirmPassword").value;
    if (userVal.length < 3) { msg.textContent = "Username must be at least 3 characters."; msg.classList.add("err"); return; }
    if (!PHONE_RE.test(phoneVal)) { msg.textContent = "Airtel Uganda numbers only."; msg.classList.add("err"); return; }
    if (passVal.length < 6) { msg.textContent = "Password must be at least 6 characters."; msg.classList.add("err"); return; }
    if (passVal !== confirmVal) { msg.textContent = "Passwords do not match."; msg.classList.add("err"); return; }
    setBtnLoading(btn, true, "Creating account…");
    try {
      const r = await api("/api/signup", { method: "POST", body: JSON.stringify({ username: userVal, phone: phoneVal, password: passVal, ref: getStoredRef() }) });
      msg.textContent = "✅ " + r.message;
      e.target.reset(); clearStoredRef();
      const banner = document.getElementById("refBanner"); if (banner) banner.style.display = "none";
      if (r.auto_approved) setTimeout(() => { location.hash = "#/login"; }, 1800);
    } catch (err) { msg.textContent = err.error || "Signup failed."; msg.classList.add("err"); }
    finally { setBtnLoading(btn, false); }
  });

  document.getElementById("login").addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = e.target.querySelector('button[type="submit"]');
    const msg = document.getElementById("loginMsg");
    msg.textContent = ""; msg.classList.remove("err", "warn");
    const idf = document.getElementById("loginId").value.trim(), pw = document.getElementById("loginPass").value;
    if (!idf || !pw) { msg.textContent = "Enter username/number and password."; msg.classList.add("err"); return; }
    setBtnLoading(btn, true, "Signing in…");
    try {
      const r = await api("/api/login", { method: "POST", body: JSON.stringify({ identifier: idf, password: pw }) });
      authToken = r.token; localStorage.setItem("ml_member_token", authToken);
      currentUser = r.user; displayName = r.user.username; authorized = true;
      seenMsgIds.clear(); seenAnnIds.clear(); inboxInitialized = false;
      setUnreadBadge(r.unread || 0);
      msg.textContent = "✅ Authorized. Opening dashboard…"; e.target.reset();
      ensureNotifyPermission().then(() => updateNotifBanner());
      setTimeout(() => {
        setAuthorizedUI(true);
        document.getElementById("dashBalance").textContent = fmt(r.user.balance);
        const dr = document.getElementById("drawerBalance"); if (dr) dr.textContent = fmt(r.user.balance);
        updateVerifyChip(!!r.user.verified, r.user.balance);
        location.hash = "#/dashboard";
      }, 400);
    } catch (err) { msg.textContent = err.error || "Login failed."; msg.classList.add(err.status === 403 ? "warn" : "err"); }
    finally { setBtnLoading(btn, false); }
  });

  document.getElementById("forgotForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = e.target.querySelector('button[type="submit"]');
    const msg = document.getElementById("forgotMsg");
    msg.textContent = ""; msg.classList.remove("err");
    const username = document.getElementById("fpUser").value.trim();
    const phone = document.getElementById("fpPhone").value.replace(/[\s\-()]/g, "");
    const nw = document.getElementById("fpNew").value;
    const cf = document.getElementById("fpConfirm").value;
    if (!username) { msg.textContent = "Enter your username."; msg.classList.add("err"); return; }
    if (!PHONE_RE.test(phone)) { msg.textContent = "Enter the Airtel number on the account."; msg.classList.add("err"); return; }
    if (nw.length < 6) { msg.textContent = "New password must be at least 6 characters."; msg.classList.add("err"); return; }
    if (nw !== cf) { msg.textContent = "Passwords do not match."; msg.classList.add("err"); return; }
    setBtnLoading(btn, true, "Resetting…");
    try {
      await api("/api/forgot-password", { method: "POST", body: JSON.stringify({ username, phone, new_password: nw }) });
      msg.textContent = "✅ Password reset! Redirecting to login…";
      e.target.reset();
      setTimeout(() => { location.hash = "#/login"; }, 1600);
    } catch (err) { msg.textContent = err.error || "Could not reset password."; msg.classList.add("err"); }
    finally { setBtnLoading(btn, false); }
  });

  document.getElementById("adminLoginForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = e.target.querySelector('button[type="submit"]');
    const msg = document.getElementById("adminMsg");
    msg.textContent = ""; msg.classList.remove("err");
    const u = document.getElementById("adminUser").value.trim(), p = document.getElementById("adminPass").value;
    if (!u || !p) { msg.textContent = "Enter username and password."; msg.classList.add("err"); return; }
    setBtnLoading(btn, true, "Signing in…");
    try {
      const r = await api("/api/admin/login", { method: "POST", body: JSON.stringify({ username: u, password: p }) });
      adminToken = r.token; localStorage.setItem("ml_admin_token", adminToken);
      msg.textContent = "✅ Access granted…";
      setTimeout(() => { location.hash = "#/admin/dashboard"; }, 400);
    } catch (err) { msg.textContent = err.error || "Invalid credentials."; msg.classList.add("err"); }
    finally { setBtnLoading(btn, false); }
  });

  document.getElementById("adminRefresh")?.addEventListener("click", () => {
    renderAdminKpis(); renderAdminSettings(); renderAdminMonitor();
    renderAdminUsers(); renderAdminVideos(); renderAdminMerchants();
    renderAdminConversations(); renderAdminAnnouncements(); renderAdminDealRequests();
    renderAdminWithdrawals(); renderAdminBanners(); renderAdminChallenges();
  });
  document.getElementById("adminLogout")?.addEventListener("click", async () => {
    try { await adminFetch("/api/logout", { method: "POST" }); } catch {}
    clearAdminAuth(); location.hash = "#/admin";
  });
  document.getElementById("adminChangePwForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = e.target.querySelector('button[type="submit"]');
    const msg = document.getElementById("adminChangePwMsg");
    const cur = document.getElementById("adminCurPw").value, nw = document.getElementById("adminNewPw").value;
    msg.textContent = ""; msg.classList.remove("err");
    if (nw.length < 8) { msg.textContent = "New admin password must be at least 8 characters."; msg.classList.add("err"); return; }
    setBtnLoading(btn, true, "Updating…");
    try { await adminFetch("/api/admin/change-password", { method: "POST", body: JSON.stringify({ current_password: cur, new_password: nw }) }); msg.textContent = "✅ Admin password updated."; e.target.reset(); }
    catch (err) { msg.textContent = err.error || "Could not update."; msg.classList.add("err"); }
    finally { setBtnLoading(btn, false); }
  });

  // ─── ADMIN SETTINGS ──────────────────────────
  function updateAutoApproveLabel() {
    const t = document.getElementById("autoApproveToggle");
    const lbl = document.getElementById("autoApproveState");
    if (lbl && t) lbl.textContent = t.checked ? "ON — new members log in immediately" : "OFF — admin approval required";
  }
  async function renderAdminSettings() {
    const t = document.getElementById("autoApproveToggle");
    if (!t) return;
    try {
      const s = await adminFetch("/api/admin/settings");
      t.checked = !!s.auto_approve;
      updateAutoApproveLabel();
    } catch {}
  }
  document.getElementById("autoApproveToggle")?.addEventListener("change", async (e) => {
    const msg = document.getElementById("settingsMsg");
    msg.textContent = ""; msg.classList.remove("err");
    try {
      const r = await adminFetch("/api/admin/settings", { method: "POST", body: JSON.stringify({ auto_approve: e.target.checked }) });
      msg.textContent = r.auto_approve
        ? "✅ Auto-approve is ON. Pending members were activated."
        : "✅ Auto-approve is OFF. New signups now need approval.";
      updateAutoApproveLabel();
      renderAdminUsers(); renderAdminKpis();
    } catch (err) {
      msg.textContent = err.error || "Could not update."; msg.classList.add("err");
      e.target.checked = !e.target.checked; updateAutoApproveLabel();
    }
  });

  // ─── ADMIN MONITOR ─────────────────────────
  async function renderAdminMonitor() {
    const onlineEl = document.getElementById("adminOnlineList");
    const auditEl = document.getElementById("adminAuditList");
    try {
      const online = await adminFetch("/api/admin/online");
      if (onlineEl) {
        onlineEl.innerHTML = online.length ? online.map(u =>
          '<div class="mon-row"><span class="online-dot"></span><span class="mon-main"><b>' + esc(u.username) + '</b> · ' + esc(u.phone) + '</span><span class="mon-time">' + fmt(u.balance) + '</span></div>'
        ).join("") : '<div class="empty-state">Nobody online right now.</div>';
      }
    } catch {}
    try {
      const log = await adminFetch("/api/admin/audit");
      if (auditEl) {
        auditEl.innerHTML = log.length ? log.slice(0, 30).map(a =>
          '<div class="mon-row"><span class="mon-main"><b>' + esc(a.actor) + '</b> ' + esc(a.action) +
          (a.target ? ' → ' + esc(a.target) : '') +
          (a.payload ? ' <span style="color:var(--muted)">(' + esc(String(a.payload).slice(0, 60)) + ')</span>' : '') +
          '</span><span class="mon-time">' + tfmt(a.created_at) + '</span></div>'
        ).join("") : '<div class="empty-state">No activity yet.</div>';
      }
    } catch {}
  }

  // ─── ADMIN BANNERS ─────────────────────────
  document.getElementById("bannerForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = e.target.querySelector('button[type="submit"]');
    const msg = document.getElementById("bannerMsg");
    msg.textContent = ""; msg.classList.remove("err");
    const image_url = document.getElementById("bnImage").value.trim();
    const link_url  = document.getElementById("bnLink").value.trim();
    const title     = document.getElementById("bnTitle").value.trim();
    if (!image_url) { msg.textContent = "Image URL is required."; msg.classList.add("err"); return; }
    setBtnLoading(btn, true, "Publishing…");
    try {
      await adminFetch("/api/admin/banners", { method: "POST", body: JSON.stringify({ image_url, link_url, title }) });
      msg.textContent = "✅ Banner published — live on all dashboards.";
      e.target.reset();
      renderAdminBanners(); renderAdminKpis();
    } catch (err) { msg.textContent = err.error || "Could not publish."; msg.classList.add("err"); }
    finally { setBtnLoading(btn, false); }
  });
  async function renderAdminBanners() {
    const el = document.getElementById("adminBannerList"); if (!el) return;
    try {
      const list = await adminFetch("/api/admin/banners");
      if (!list.length) { el.innerHTML = '<div class="empty-state">No banners yet. Publish one above — every member sees it instantly.</div>'; return; }
      el.innerHTML = list.map(b =>
        '<div class="banner-card ' + (b.active ? '' : 'inactive') + '">' +
          '<div class="bc-thumb"><img src="' + esc(b.image_url) + '" alt="" onerror="this.parentNode.innerHTML=\'<div style=&quot;display:grid;place-items:center;height:100%;color:#94a3b8;font-size:.7rem&quot;>no image</div>\'" /></div>' +
          '<div class="bc-meta">' +
            '<b>' + esc(b.title || 'Banner') + (b.active ? ' <span class="badge badge-live" style="margin-left:6px">Live</span>' : ' <span class="badge">Hidden</span>') + '</b>' +
            '<small>img: ' + esc(b.image_url.slice(0, 80)) + '</small>' +
            (b.link_url ? '<small>link: ' + esc(b.link_url.slice(0, 80)) + '</small>' : '') +
          '</div>' +
          '<div class="bc-actions">' +
            '<button type="button" class="mini-btn ' + (b.active ? 'warn' : 'good') + '" data-banner-toggle="' + esc(b.id) + '">' + (b.active ? 'Hide' : 'Show') + '</button>' +
            '<button type="button" class="mini-btn bad" data-banner-delete="' + esc(b.id) + '">Delete</button>' +
          '</div>' +
        '</div>'
      ).join("");
      el.querySelectorAll("[data-banner-toggle]").forEach(btn => btn.addEventListener("click", async () => {
        try { await adminFetch("/api/admin/banners/" + btn.getAttribute("data-banner-toggle") + "/toggle", { method: "POST" }); renderAdminBanners(); renderAdminKpis(); }
        catch (e) { alert(e.error || "Failed."); }
      }));
      el.querySelectorAll("[data-banner-delete]").forEach(btn => btn.addEventListener("click", async () => {
        if (!confirm("Delete this banner?")) return;
        try { await adminFetch("/api/admin/banners/" + btn.getAttribute("data-banner-delete"), { method: "DELETE" }); renderAdminBanners(); renderAdminKpis(); }
        catch (e) { alert(e.error || "Failed."); }
      }));
    } catch { el.innerHTML = '<div class="empty-state">Failed to load banners.</div>'; }
  }

  // ─── ADMIN CHALLENGES ──────────────────────
  document.getElementById("challengeForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = e.target.querySelector('button[type="submit"]');
    const msg = document.getElementById("challengeMsg");
    msg.textContent = ""; msg.classList.remove("err");
    const title = document.getElementById("chTitle").value.trim();
    const description = document.getElementById("chDesc").value.trim();
    const goal_type = document.getElementById("chType").value;
    const goal_value = parseInt(document.getElementById("chGoal").value, 10);
    const reward = parseFloat(document.getElementById("chReward").value);
    if (!title) { msg.textContent = "Title required."; msg.classList.add("err"); return; }
    if (!goal_value || goal_value < 1) { msg.textContent = "Goal must be at least 1."; msg.classList.add("err"); return; }
    if (!reward || reward <= 0) { msg.textContent = "Reward must be above 0."; msg.classList.add("err"); return; }
    setBtnLoading(btn, true, "Creating…");
    try {
      await adminFetch("/api/admin/challenges", { method: "POST", body: JSON.stringify({ title, description, goal_type, goal_value, reward }) });
      msg.textContent = "✅ Challenge created — members see it on their dashboard.";
      e.target.reset();
      document.getElementById("chGoal").value = 5;
      document.getElementById("chReward").value = 1000;
      renderAdminChallenges(); renderAdminKpis();
    } catch (err) { msg.textContent = err.error || "Could not create."; msg.classList.add("err"); }
    finally { setBtnLoading(btn, false); }
  });
  async function renderAdminChallenges() {
    const el = document.getElementById("adminChallengeList"); if (!el) return;
    try {
      const list = await adminFetch("/api/admin/challenges");
      if (!list.length) { el.innerHTML = '<div class="empty-state">No challenges yet.</div>'; return; }
      el.innerHTML = list.map(c =>
        '<div class="req-row">' +
          '<div style="flex:1;min-width:200px"><b>' + esc(c.title) + '</b>' +
            (c.description ? '<small>' + esc(c.description) + '</small>' : '') +
            '<small>' + (c.goal_type === 'referrals' ? 'Approved referrals' : 'Videos watched') + ' goal: ' + c.goal_value + ' · reward ' + fmt(c.reward) + '</small>' +
          '</div>' +
          '<button type="button" class="mini-btn bad" data-del-ch="' + esc(c.id) + '">Delete</button>' +
        '</div>'
      ).join("");
      el.querySelectorAll("[data-del-ch]").forEach(b => b.addEventListener("click", async () => {
        if (!confirm("Delete this challenge?")) return;
        try { await adminFetch("/api/admin/challenges/" + b.getAttribute("data-del-ch"), { method: "DELETE" }); renderAdminChallenges(); renderAdminKpis(); }
        catch (e) { alert(e.error || "Failed."); }
      }));
    } catch { el.innerHTML = '<div class="empty-state">Failed to load.</div>'; }
  }

  // ─── ADMIN USERS ───────────────────────────
  function statusBadge(status) {
    switch (status) {
      case "active": return '<span class="badge badge-live">Active</span>';
      case "pending": return '<span class="badge badge-pending">Pending</span>';
      case "suspended": return '<span class="badge badge-warn">Suspended</span>';
      case "blocked": return '<span class="badge badge-danger">Blocked</span>';
      default: return '<span class="badge">' + esc(status) + '</span>';
    }
  }
  function userActionButtons(u) {
    const btns = [];
    if (u.status === "pending") { btns.push('<button class="mini-btn good" data-user-action="approve" data-uid="' + esc(u.id) + '">Approve</button>'); btns.push('<button class="mini-btn bad" data-user-action="block" data-uid="' + esc(u.id) + '">Block</button>'); }
    else if (u.status === "active") { btns.push('<button class="mini-btn warn" data-user-action="suspend" data-uid="' + esc(u.id) + '">Suspend</button>'); btns.push('<button class="mini-btn bad" data-user-action="block" data-uid="' + esc(u.id) + '">Block</button>'); }
    else { btns.push('<button class="mini-btn good" data-user-action="approve" data-uid="' + esc(u.id) + '">Reactivate</button>'); }
    btns.push('<button class="mini-btn" data-user-action="resetpw" data-uid="' + esc(u.id) + '">Reset pw</button>');
    btns.push('<button class="mini-btn bad" data-user-action="delete" data-uid="' + esc(u.id) + '">Delete</button>');
    return '<div class="user-actions">' + btns.join("") + '</div>';
  }
  async function renderAdminUsers() {
    const el = document.getElementById("userListAdmin"); if (!el) return;
    try {
      const users = await adminFetch("/api/admin/users");
      const q = (document.getElementById("userSearch").value || "").trim().toLowerCase();
      const filter = document.getElementById("userFilter").value;
      let rows = users.slice().sort((a, b) => (b.created_at || 0) - (a.created_at || 0));
      if (q) rows = rows.filter(u => (u.username || "").toLowerCase().includes(q) || (u.phone || "").includes(q));
      if (filter === "online") rows = rows.filter(u => u.is_online);
      else if (filter !== "all") rows = rows.filter(u => u.status === filter);
      if (!users.length) { el.innerHTML = '<div class="empty-state">No members yet.</div>'; return; }
      if (!rows.length) { el.innerHTML = '<div class="empty-state">No members match.</div>'; return; }
      el.innerHTML = '<div class="admin-table-wrap"><table class="admin-table"><thead><tr><th>Member</th><th>Phone</th><th>Status</th><th>Balance</th><th>Earned</th><th>Referral</th><th>Presence</th><th>Joined</th><th>Actions</th></tr></thead><tbody>' +
        rows.map(u => {
          const refTag = u.referred_by
            ? '<div style="font-size:.76rem;color:var(--muted)">via <b>' + esc(u.referred_by) + '</b>' + (u.referral_credited ? ' <span style="color:var(--accent)">✓ paid</span>' : ' <span style="color:var(--amber)">pending</span>') + '</div>'
            : '<span style="color:var(--muted);font-size:.76rem">—</span>';
          const onlineTag = u.is_online
            ? '<span style="display:inline-flex;align-items:center;gap:6px;font-size:.74rem;color:#047857;font-weight:800"><span class="online-dot"></span>Online</span>'
            : '<span style="display:inline-flex;align-items:center;gap:6px;font-size:.74rem;color:var(--muted);font-weight:600"><span class="offline-dot"></span>Offline</span>';
          return '<tr><td><b>' + esc(u.username) + '</b>' + (u.note ? '<span style="display:block;font-size:.72rem;color:var(--muted)">"' + esc(u.note) + '"</span>' : '') + '</td>' +
            '<td class="mono">' + esc(u.phone) + '</td>' +
            '<td>' + statusBadge(u.status) + '</td>' +
            '<td class="mono">' + fmt2(u.balance || 0) + '</td>' +
            '<td class="mono">' + fmt2(u.total_earned || 0) + '</td>' +
            '<td>' + refTag + '</td>' +
            '<td>' + onlineTag + '</td>' +
            '<td>' + (u.created_at ? new Date(u.created_at * 1000).toLocaleDateString() : "—") + '</td>' +
            '<td>' + userActionButtons(u) + '</td></tr>';
        }).join("") + '</tbody></table></div>';
      el.querySelectorAll("[data-user-action]").forEach(btn => btn.addEventListener("click", () => handleUserAction(btn.getAttribute("data-uid"), btn.getAttribute("data-user-action"))));
    } catch { el.innerHTML = '<div class="empty-state">Failed to load.</div>'; }
  }
  async function handleUserAction(uid, action) {
    try {
      if (action === "delete") {
        if (!confirm("Delete this member permanently?")) return;
        await adminFetch("/api/admin/users/" + uid, { method: "DELETE" });
      } else if (action === "resetpw") {
        const np = prompt("Enter new password for this member (min 6 chars):");
        if (!np) return;
        if (np.length < 6) { alert("Password must be at least 6 characters."); return; }
        await adminFetch("/api/admin/users/" + uid + "/reset-password", { method: "POST", body: JSON.stringify({ new_password: np }) });
        alert("Password reset. The member was notified in their Inbox.");
        return;
      } else {
        const status = action === "approve" ? "active" : action === "suspend" ? "suspended" : "blocked";
        let note = "";
        if (action === "suspend" || action === "block") { const r = prompt("Reason? (optional)"); if (r === null) return; note = r.trim(); }
        await adminFetch("/api/admin/users/" + uid + "/status", { method: "POST", body: JSON.stringify({ status, note }) });
      }
      renderAdminUsers(); renderAdminKpis();
    } catch (e) { alert(e.error || "Action failed."); }
  }
  document.getElementById("userSearch")?.addEventListener("input", renderAdminUsers);
  document.getElementById("userFilter")?.addEventListener("change", renderAdminUsers);

  async function renderAdminKpis() {
    const el = document.getElementById("adminKpis"); if (!el) return;
    try {
      const k = await adminFetch("/api/admin/kpis");
      el.innerHTML = [
        { k: "Members", v: k.users, s: k.active + " active · " + k.pending + " pending" },
        { k: "Online now", v: k.online_now || 0, s: "active in last 90s", cls: "online" },
        { k: "Total balance", v: fmt(k.total_balance || 0), s: "across all members" },
        { k: "Pending withdrawals", v: k.pending_withdrawals || 0, s: "awaiting approval" },
        { k: "Total withdrawn", v: fmt(k.total_withdrawn || 0), s: "approved payouts" },
        { k: "Referrals paid", v: k.referrals_credited || 0, s: "bonuses credited" },
        { k: "Challenges", v: k.active_challenges || 0, s: (k.challenge_claims || 0) + " claimed" },
        { k: "Active banners", v: k.active_banners || 0, s: "live on dashboards" },
        { k: "Live videos", v: k.live_videos, s: k.total_videos + " total" },
      ].map(i => '<div class="admin-kpi ' + (i.cls || '') + '"><div class="k">' + i.k + '</div><div class="v">' + i.v + '</div><div class="s">' + i.s + '</div></div>').join("");
    } catch {}
  }

  document.getElementById("wdFilter")?.addEventListener("change", renderAdminWithdrawals);
  async function renderAdminWithdrawals() {
    const el = document.getElementById("adminWithdrawals"); if (!el) return;
    try {
      const rows = await adminFetch("/api/admin/withdrawals");
      const filter = document.getElementById("wdFilter").value;
      let list = rows;
      if (filter !== "all") list = rows.filter(r => r.status === filter);
      if (!list.length) { el.innerHTML = '<div class="empty-state">No ' + (filter === "all" ? "" : filter) + ' withdrawals.</div>'; return; }
      el.innerHTML = list.map(w => {
        const st = w.status === 'pending' ? 'badge badge-pending' : w.status === 'approved' ? 'badge badge-live' : 'badge badge-danger';
        const actions = w.status === 'pending' ? '<button class="mini-btn good" data-wd-approve="' + esc(w.id) + '">Approve</button> <button class="mini-btn bad" data-wd-reject="' + esc(w.id) + '">Reject</button>' : '';
        return '<div class="req-row ' + (w.status === 'approved' ? 'resolved' : w.status === 'rejected' ? 'rejected' : 'pending') + '">' +
          '<div style="flex:1;min-width:220px"><b>' + esc(w.username) + ' · ' + fmt2(w.amount) + '</b><small>To <b>' + esc(w.merchant_id) + '</b> · ' + tfmt(w.created_at) + '</small><small>User balance now: <b>' + fmt2(w.user_balance || 0) + '</b></small>' + (w.admin_note ? '<small style="color:var(--primary)">Note: ' + esc(w.admin_note) + '</small>' : '') + '</div>' +
          '<div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap"><span class="' + st + '">' + esc(w.status) + '</span>' + actions + '</div></div>';
      }).join("");
      el.querySelectorAll("[data-wd-approve]").forEach(b => b.addEventListener("click", async () => {
        if (!confirm("Approve this withdrawal?")) return;
        try { await adminFetch("/api/admin/withdrawals/" + b.getAttribute("data-wd-approve") + "/approve", { method: "POST" }); renderAdminWithdrawals(); renderAdminKpis(); renderAdminUsers(); }
        catch (e) { alert(e.error || "Failed."); }
      }));
      el.querySelectorAll("[data-wd-reject]").forEach(b => b.addEventListener("click", async () => {
        const note = prompt("Reason for rejection:") || "";
        try { await adminFetch("/api/admin/withdrawals/" + b.getAttribute("data-wd-reject") + "/reject", { method: "POST", body: JSON.stringify({ admin_note: note }) }); renderAdminWithdrawals(); renderAdminKpis(); }
        catch (e) { alert(e.error || "Failed."); }
      }));
    } catch { el.innerHTML = '<div class="empty-state">Failed to load.</div>'; }
  }

  async function renderAdminConversations() {
    const el = document.getElementById("adminConversations"); if (!el) return;
    try {
      const rows = await adminFetch("/api/admin/conversations");
      if (!rows.length) { el.innerHTML = '<div class="empty-state">No conversations yet.</div>'; return; }
      el.innerHTML = rows.map(r => '<div class="conv-row ' + (r.username === adminConvUser ? 'selected' : '') + '" data-conv="' + esc(r.username) + '"><span class="name">' + esc(r.username) + '</span><span class="preview">' + esc((r.last_body || "No messages yet").slice(0, 80)) + '</span>' + (r.unread > 0 ? '<span class="unread">' + r.unread + '</span>' : '') + '</div>').join("");
      el.querySelectorAll("[data-conv]").forEach(row => row.addEventListener("click", () => openConversation(row.getAttribute("data-conv"))));
    } catch { el.innerHTML = '<div class="empty-state">Failed to load.</div>'; }
  }
  async function openConversation(username) {
    adminConvUser = username;
    document.getElementById("adminChatWrap").style.display = "block";
    document.getElementById("adminChatWith").textContent = "Conversation with " + username;
    renderAdminConversations();
    await refreshAdminChat();
  }
  async function refreshAdminChat() {
    if (!adminConvUser) return;
    try {
      const msgs = await adminFetch("/api/admin/messages/" + encodeURIComponent(adminConvUser));
      renderChat(document.getElementById("adminChat"), msgs, 'admin');
    } catch (e) { document.getElementById("adminChatMsg").textContent = e.error || "Load failed."; }
  }
  document.getElementById("adminChatBack")?.addEventListener("click", () => { adminConvUser = null; document.getElementById("adminChatWrap").style.display = "none"; renderAdminConversations(); });
  document.getElementById("adminChatForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!adminConvUser) return;
    const input = document.getElementById("adminChatInput"), msg = document.getElementById("adminChatMsg");
    const body = input.value.trim(); if (!body) return;
    msg.textContent = ""; msg.classList.remove("err");
    try { await adminFetch("/api/admin/messages/" + encodeURIComponent(adminConvUser) + "/reply", { method: "POST", body: JSON.stringify({ body }) }); input.value = ""; await refreshAdminChat(); renderAdminConversations(); }
    catch (err) { msg.textContent = err.error || "Could not send."; msg.classList.add("err"); }
  });

  document.getElementById("adminAnnounceForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = e.target.querySelector('button[type="submit"]');
    const msg = document.getElementById("adminAnnounceMsg");
    msg.textContent = ""; msg.classList.remove("err");
    const title = document.getElementById("annTitle").value.trim(), body = document.getElementById("annBody").value.trim();
    if (!title || !body) { msg.textContent = "Title and body are required."; msg.classList.add("err"); return; }
    setBtnLoading(btn, true, "Broadcasting…");
    try { await adminFetch("/api/admin/announcements", { method: "POST", body: JSON.stringify({ title, body }) }); msg.textContent = "✅ Broadcast sent. Members will hear a chime."; e.target.reset(); renderAdminAnnouncements(); renderAdminKpis(); }
    catch (err) { msg.textContent = err.error || "Could not send."; msg.classList.add("err"); }
    finally { setBtnLoading(btn, false); }
  });
  async function renderAdminAnnouncements() {
    const el = document.getElementById("adminAnnouncementsList"); if (!el) return;
    try {
      const rows = await adminFetch("/api/admin/announcements");
      if (!rows.length) { el.innerHTML = '<div class="empty-state">No announcements yet.</div>'; return; }
      el.innerHTML = rows.map(a => '<div class="announcement"><h4><svg class="icon icon-sm" viewBox="0 0 24 24"><use href="#i-megaphone"/></svg>' + esc(a.title) + '</h4><p>' + esc(a.body) + '</p><div class="when">' + tfmt(a.created_at) + ' · read by ' + a.read_count + '/' + a.total_users + ' <button type="button" class="mini-btn bad" data-del-ann="' + esc(a.id) + '" style="margin-left:8px">Delete</button></div></div>').join("");
      el.querySelectorAll("[data-del-ann]").forEach(b => b.addEventListener("click", async () => {
        if (!confirm("Delete this announcement for everyone?")) return;
        try { await adminFetch("/api/admin/announcements/" + b.getAttribute("data-del-ann"), { method: "DELETE" }); renderAdminAnnouncements(); }
        catch (e) { alert(e.error || "Failed."); }
      }));
    } catch { el.innerHTML = '<div class="empty-state">Failed to load.</div>'; }
  }

  document.getElementById("drFilter")?.addEventListener("change", renderAdminDealRequests);
  async function renderAdminDealRequests() {
    const el = document.getElementById("adminDealRequests"); if (!el) return;
    try {
      const rows = await adminFetch("/api/admin/deal-requests");
      const filter = document.getElementById("drFilter").value;
      let list = rows;
      if (filter !== "all") list = rows.filter(r => r.status === filter);
      if (!list.length) { el.innerHTML = '<div class="empty-state">No ' + (filter === "all" ? "" : filter) + ' requests.</div>'; return; }
      el.innerHTML = list.map(r => {
        const st = r.status === 'pending' ? 'badge badge-pending' : 'badge badge-live';
        const actions = r.status === 'pending' ? '<button type="button" class="mini-btn good" data-resolve="' + esc(r.id) + '">Resolve</button>' : '';
        return '<div class="req-row ' + r.status + '"><div style="flex:1;min-width:220px"><b>' + esc(r.username) + ' · ' + esc(r.kind) + (r.video_id ? ' · ' + esc(r.video_id) : '') + '</b><small>' + esc(r.message) + '</small>' + (r.admin_note ? '<small style="color:var(--primary)"><b>Note:</b> ' + esc(r.admin_note) + '</small>' : '') + '<small style="color:var(--muted)">' + tfmt(r.created_at) + '</small></div><div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap"><span class="' + st + '">' + esc(r.status) + '</span>' + actions + '</div></div>';
      }).join("");
      el.querySelectorAll("[data-resolve]").forEach(btn => btn.addEventListener("click", async () => {
        const note = prompt("Resolution note for the member (optional):") || "";
        try { await adminFetch("/api/admin/deal-requests/" + btn.getAttribute("data-resolve") + "/resolve", { method: "POST", body: JSON.stringify({ admin_note: note }) }); renderAdminDealRequests(); renderAdminKpis(); }
        catch (e) { alert(e.error || "Failed."); }
      }));
    } catch { el.innerHTML = '<div class="empty-state">Failed to load.</div>'; }
  }

  document.getElementById("videoForm")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = e.target.querySelector('button[type="submit"]');
    const msg = document.getElementById("videoMsg");
    msg.textContent = ""; msg.classList.remove("err");
    const url = document.getElementById("vUrl").value.trim();
    const title = document.getElementById("vTitle").value.trim();
    const reward = parseFloat(document.getElementById("vReward").value);
    if (!url) { msg.textContent = "Paste a YouTube URL."; msg.classList.add("err"); return; }
    if (!title) { msg.textContent = "Add a title."; msg.classList.add("err"); return; }
    if (!reward || reward <= 0) { msg.textContent = "Set a reward above 0."; msg.classList.add("err"); return; }
    setBtnLoading(btn, true, "Publishing…");
    try { await adminFetch("/api/admin/videos", { method: "POST", body: JSON.stringify({ url, title, reward }) }); msg.textContent = "✅ Published!"; e.target.reset(); document.getElementById("vReward").value = 1900; renderAdminVideos(); renderAdminKpis(); }
    catch (err) { msg.textContent = err.error || "Failed to publish."; msg.classList.add("err"); }
    finally { setBtnLoading(btn, false); }
  });
  async function renderAdminVideos() {
    const el = document.getElementById("videoListAdmin"); if (!el) return;
    try {
      const videos = await adminFetch("/api/admin/videos");
      if (!videos.length) { el.innerHTML = '<div class="empty-state">No videos yet.</div>'; return; }
      el.innerHTML = '<div class="admin-table-wrap"><table class="admin-table"><thead><tr><th>Thumb</th><th>Title</th><th>Reward</th><th>Video ID</th><th>Status</th><th></th></tr></thead><tbody>' +
        videos.map(v => '<tr><td><img class="thumb-sm" src="https://i.ytimg.com/vi/' + esc(v.video_id) + '/mqdefault.jpg" alt="" /></td><td><b>' + esc(v.title) + '</b></td><td class="mono">' + fmt2(v.reward) + '</td><td class="mono">' + esc(v.video_id) + '</td><td>' + (v.published ? '<span class="badge badge-live">Live</span>' : '<span class="badge">Hidden</span>') + '</td><td><button class="mini-btn bad" data-delete="' + esc(v.id) + '">Delete</button></td></tr>').join("") +
        '</tbody></table></div>';
      el.querySelectorAll("[data-delete]").forEach(btn => btn.addEventListener("click", async () => {
        if (!confirm("Delete this video?")) return;
        try { await adminFetch("/api/admin/videos/" + btn.getAttribute("data-delete"), { method: "DELETE" }); renderAdminVideos(); renderAdminKpis(); }
        catch (e) { alert(e.error || "Delete failed."); }
      }));
    } catch { el.innerHTML = '<div class="empty-state">Failed to load.</div>'; }
  }
  async function renderAdminMerchants() {
    const el = document.getElementById("merchantListAdmin"); if (!el) return;
    try {
      const list = await adminFetch("/api/admin/merchants");
      if (!list.length) { el.innerHTML = '<div class="empty-state">No merchant IDs yet.</div>'; return; }
      el.innerHTML = '<div class="admin-table-wrap"><table class="admin-table"><thead><tr><th>Member</th><th>Merchant ID</th><th>Submitted</th><th>Updated</th></tr></thead><tbody>' +
        list.map(m => '<tr><td><b>' + esc(m.username) + '</b></td><td class="mono">' + esc(m.merchant_id) + '</td><td>' + tfmt(m.submitted_at) + '</td><td>' + (m.updated_at ? tfmt(m.updated_at) : "—") + '</td></tr>').join("") +
        '</tbody></table></div>';
    } catch { el.innerHTML = '<div class="empty-state">Failed to load.</div>'; }
  }

  setInterval(() => { if (authorized && authToken) pollInbox(); }, UNREAD_POLL_MS);
  setInterval(() => {
    if (currentRoute() === "adminDashboard" && adminToken) {
      renderAdminKpis(); renderAdminUsers(); renderAdminMonitor();
    }
  }, ADMIN_POLL_MS);

  (async function boot() {
    if (authToken) {
      try {
        const me = await api("/api/me", {}, authToken);
        if (!me.is_admin) {
          currentUser = me; displayName = me.username; authorized = true;
          setAuthorizedUI(true); setUnreadBadge(me.unread || 0);
          const dr = document.getElementById("drawerBalance"); if (dr) dr.textContent = fmt(me.balance);
        } else clearMemberAuth();
      } catch { clearMemberAuth(); }
    }
    if (adminToken) { try { await api("/api/admin/kpis", {}, adminToken); } catch { clearAdminAuth(); } }
    render();
    if (currentRoute() === "signup") captureReferral();
    if (authorized) setTimeout(pollInbox, 1500);
  })();
})();
</script>
</body>
</html>
HTMLEOF

# ---------------------------------------------------------------------
# 3) Kill stale instances, then launch on 0.0.0.0
# ---------------------------------------------------------------------
pkill -f "python3.*server\.py" 2>/dev/null || true
pkill -f "python3 server\.py" 2>/dev/null || true
sleep 1
cd "$APP_DIR"
echo ""
echo "=================================================="
echo "  Installation complete."
echo "  Database : $DB_FILE"
echo "  Bind     : 0.0.0.0 (all interfaces)"
echo "  Port     : $PORT"
echo "             (env PORT / MOBILEARN_PORT override)"
echo "  Starting Mobilearn..."
echo "=================================================="
echo ""
exec python3 server.py
