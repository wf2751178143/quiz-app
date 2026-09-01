#!/usr/bin/env python3
"""Quiz server with user accounts and progress sync."""
import os, sys, json, hashlib, secrets, sqlite3, time
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timedelta

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Railway uses /data for persistent storage
DATA_DIR = os.environ.get('RAILWAY_VOLUME_MOUNT_PATH', BASE_DIR)
DB_PATH = os.path.join(DATA_DIR, 'quiz.db')
QUESTIONS_PATH = os.path.join(BASE_DIR, 'questions.json')
STATIC_DIR = os.path.join(BASE_DIR, 'static')
HOST = '0.0.0.0'
PORT = int(os.environ.get('PORT', 8080))

# ─── Database ────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS progress (
            user_id INTEGER NOT NULL,
            question_key TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'done',
            updated_at TEXT DEFAULT (datetime('now','localtime')),
            PRIMARY KEY (user_id, question_key),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS bookmarks (
            user_id INTEGER NOT NULL,
            question_key TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now','localtime')),
            PRIMARY KEY (user_id, question_key),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS wrong_answers (
            user_id INTEGER NOT NULL,
            question_key TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now','localtime')),
            PRIMARY KEY (user_id, question_key),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS notes (
            user_id INTEGER NOT NULL,
            question_key TEXT NOT NULL,
            content TEXT NOT NULL DEFAULT '',
            updated_at TEXT DEFAULT (datetime('now','localtime')),
            PRIMARY KEY (user_id, question_key),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    ''')
    conn.close()

# ─── Auth helpers ────────────────────────────────────────────────────────────

def hash_password(password):
    salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return salt + ':' + h

def verify_password(stored, password):
    salt, h = stored.split(':')
    return hashlib.sha256((salt + password).encode()).hexdigest() == h

def create_session(user_id):
    token = secrets.token_hex(32)
    expires = (datetime.now() + timedelta(days=30)).isoformat()
    conn = get_db()
    conn.execute('INSERT OR REPLACE INTO sessions (token, user_id, expires_at) VALUES (?,?,?)',
                 (token, user_id, expires))
    conn.commit()
    conn.close()
    return token

def get_user_from_token(token):
    if not token:
        return None
    conn = get_db()
    row = conn.execute(
        'SELECT u.id, u.username FROM users u JOIN sessions s ON u.id=s.user_id '
        'WHERE s.token=? AND s.expires_at>datetime("now","localtime")',
        (token,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None

# ─── Handler ─────────────────────────────────────────────────────────────────

class QuizHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

    def end_headers(self):
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        super().end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == '/api/questions':
            return self.handle_questions()
        elif path == '/api/progress':
            return self.handle_get_progress()
        elif path == '/api/bookmarks':
            return self.handle_get_bookmarks()
        elif path == '/api/wrong':
            return self.handle_get_wrong()
        elif path == '/api/notes':
            return self.handle_get_notes()
        elif path == '/api/exam':
            return self.handle_generate_exam(parsed)
        else:
            return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        body = self.read_body()

        if path == '/api/register':
            return self.handle_register(body)
        elif path == '/api/login':
            return self.handle_login(body)
        elif path == '/api/progress':
            return self.handle_save_progress(body)
        elif path == '/api/bookmark':
            return self.handle_toggle_bookmark(body)
        elif path == '/api/wrong':
            return self.handle_toggle_wrong(body)
        elif path == '/api/batch-progress':
            return self.handle_batch_progress(body)
        elif path == '/api/note':
            return self.handle_save_note(body)
        else:
            self.send_json(404, {'error': 'not found'})

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path
        body = self.read_body()

        if path == '/api/bookmark':
            return self.handle_remove_bookmark(body)
        elif path == '/api/wrong':
            return self.handle_remove_wrong(body)
        else:
            self.send_json(404, {'error': 'not found'})

    # ── Auth ──────────────────────────────────────────────────────────────

    def handle_register(self, body):
        username = body.get('username', '').strip()
        password = body.get('password', '')
        if not username or not password:
            return self.send_json(400, {'error': '用户名和密码不能为空'})
        if len(username) < 2 or len(username) > 20:
            return self.send_json(400, {'error': '用户名长度2-20个字符'})
        if len(password) < 4:
            return self.send_json(400, {'error': '密码至少4个字符'})

        conn = get_db()
        try:
            conn.execute('INSERT INTO users (username, password_hash) VALUES (?,?)',
                         (username, hash_password(password)))
            conn.commit()
            user = conn.execute('SELECT id FROM users WHERE username=?', (username,)).fetchone()
            token = create_session(user['id'])
            conn.close()
            return self.send_json(200, {'token': token, 'username': username})
        except sqlite3.IntegrityError:
            conn.close()
            return self.send_json(400, {'error': '用户名已存在'})

    def handle_login(self, body):
        username = body.get('username', '').strip()
        password = body.get('password', '')
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        conn.close()
        if not user or not verify_password(user['password_hash'], password):
            return self.send_json(401, {'error': '用户名或密码错误'})
        token = create_session(user['id'])
        return self.send_json(200, {'token': token, 'username': username})

    # ── Questions ─────────────────────────────────────────────────────────

    def handle_questions(self):
        try:
            with open(QUESTIONS_PATH, 'r', encoding='utf-8') as f:
                data = json.load(f)
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            law = params.get('law', [None])[0]
            if law:
                for cat in data:
                    for s in data[cat]:
                        if s['law'] == law:
                            return self.send_json(200, {law: [{'law': s['law'], 'questions': s['questions']}]})
                return self.send_json(404, {'error': '未找到该法律'})
            summary = {}
            for cat in data:
                summary[cat] = [{'law': s['law'], 'count': len(s['questions'])} for s in data[cat]]
            return self.send_json(200, {'summary': summary})
        except FileNotFoundError:
            return self.send_json(500, {'error': '题库文件不存在'})

    # ── Progress ──────────────────────────────────────────────────────────

    def handle_get_progress(self):
        user = self.get_auth_user()
        if not user:
            return self.send_json(401, {'error': '未登录'})
        conn = get_db()
        rows = conn.execute('SELECT question_key, status FROM progress WHERE user_id=?',
                            (user['id'],)).fetchall()
        conn.close()
        return self.send_json(200, {r['question_key']: r['status'] for r in rows})

    def handle_save_progress(self, body):
        user = self.get_auth_user()
        if not user:
            return self.send_json(401, {'error': '未登录'})
        key = body.get('question_key', '')
        status = body.get('status', 'done')
        if not key:
            return self.send_json(400, {'error': '缺少 question_key'})
        conn = get_db()
        if status is None or status == 'null':
            conn.execute('DELETE FROM progress WHERE user_id=? AND question_key=?', (user['id'], key))
        else:
            conn.execute(
                'INSERT OR REPLACE INTO progress (user_id, question_key, status, updated_at) '
                'VALUES (?,?,?,datetime("now","localtime"))',
                (user['id'], key, status)
            )
        conn.commit()
        conn.close()
        return self.send_json(200, {'ok': True})

    def handle_batch_progress(self, body):
        user = self.get_auth_user()
        if not user:
            return self.send_json(401, {'error': '未登录'})
        items = body.get('items', [])
        conn = get_db()
        for item in items:
            conn.execute(
                'INSERT OR REPLACE INTO progress (user_id, question_key, status, updated_at) '
                'VALUES (?,?,?,datetime("now","localtime"))',
                (user['id'], item['key'], item['status'])
            )
        conn.commit()
        conn.close()
        return self.send_json(200, {'ok': True})

    # ── Bookmarks ─────────────────────────────────────────────────────────

    def handle_get_bookmarks(self):
        user = self.get_auth_user()
        if not user:
            return self.send_json(401, {'error': '未登录'})
        conn = get_db()
        rows = conn.execute('SELECT question_key FROM bookmarks WHERE user_id=?',
                            (user['id'],)).fetchall()
        conn.close()
        return self.send_json(200, [r['question_key'] for r in rows])

    def handle_toggle_bookmark(self, body):
        user = self.get_auth_user()
        if not user:
            return self.send_json(401, {'error': '未登录'})
        key = body.get('question_key', '')
        if not key:
            return self.send_json(400, {'error': '缺少 question_key'})
        conn = get_db()
        existing = conn.execute('SELECT 1 FROM bookmarks WHERE user_id=? AND question_key=?',
                                (user['id'], key)).fetchone()
        if existing:
            conn.execute('DELETE FROM bookmarks WHERE user_id=? AND question_key=?',
                         (user['id'], key))
            conn.commit()
            conn.close()
            return self.send_json(200, {'bookmarked': False})
        else:
            conn.execute('INSERT INTO bookmarks (user_id, question_key) VALUES (?,?)',
                         (user['id'], key))
            conn.commit()
            conn.close()
            return self.send_json(200, {'bookmarked': True})

    def handle_remove_bookmark(self, body):
        user = self.get_auth_user()
        if not user:
            return self.send_json(401, {'error': '未登录'})
        key = body.get('question_key', '')
        conn = get_db()
        conn.execute('DELETE FROM bookmarks WHERE user_id=? AND question_key=?',
                     (user['id'], key))
        conn.commit()
        conn.close()
        return self.send_json(200, {'ok': True})

    # ── Wrong answers ─────────────────────────────────────────────────────

    def handle_get_wrong(self):
        user = self.get_auth_user()
        if not user:
            return self.send_json(401, {'error': '未登录'})
        conn = get_db()
        rows = conn.execute('SELECT question_key FROM wrong_answers WHERE user_id=?',
                            (user['id'],)).fetchall()
        conn.close()
        return self.send_json(200, [r['question_key'] for r in rows])

    def handle_toggle_wrong(self, body):
        user = self.get_auth_user()
        if not user:
            return self.send_json(401, {'error': '未登录'})
        key = body.get('question_key', '')
        action = body.get('action', 'add')
        if not key:
            return self.send_json(400, {'error': '缺少 question_key'})
        conn = get_db()
        if action == 'remove':
            conn.execute('DELETE FROM wrong_answers WHERE user_id=? AND question_key=?',
                         (user['id'], key))
        else:
            conn.execute(
                'INSERT OR IGNORE INTO wrong_answers (user_id, question_key) VALUES (?,?)',
                (user['id'], key)
            )
        conn.commit()
        conn.close()
        return self.send_json(200, {'ok': True})

    def handle_remove_wrong(self, body):
        user = self.get_auth_user()
        if not user:
            return self.send_json(401, {'error': '未登录'})
        key = body.get('question_key', '')
        conn = get_db()
        conn.execute('DELETE FROM wrong_answers WHERE user_id=? AND question_key=?',
                     (user['id'], key))
        conn.commit()
        conn.close()
        return self.send_json(200, {'ok': True})

    # ── Notes ────────────────────────────────────────────────────────────

    def handle_get_notes(self):
        user = self.get_auth_user()
        if not user:
            return self.send_json(401, {'error': '未登录'})
        conn = get_db()
        rows = conn.execute('SELECT question_key, content FROM notes WHERE user_id=?',
                            (user['id'],)).fetchall()
        conn.close()
        return self.send_json(200, {r['question_key']: r['content'] for r in rows})

    def handle_save_note(self, body):
        user = self.get_auth_user()
        if not user:
            return self.send_json(401, {'error': '未登录'})
        key = body.get('question_key', '')
        content = body.get('content', '')
        conn = get_db()
        if content.strip():
            conn.execute('''INSERT INTO notes (user_id, question_key, content, updated_at)
                            VALUES (?, ?, ?, datetime('now','localtime'))
                            ON CONFLICT(user_id, question_key)
                            DO UPDATE SET content=excluded.content, updated_at=excluded.updated_at''',
                         (user['id'], key, content))
        else:
            conn.execute('DELETE FROM notes WHERE user_id=? AND question_key=?',
                         (user['id'], key))
        conn.commit()
        conn.close()
        return self.send_json(200, {'ok': True})

    # ── Exam Generation ──────────────────────────────────────────────────

    # Distribution: {law_name: {type: count}}
    PRO_EXAM_DIST = {
        '中华人民共和国烟草专卖法': {'单选': 10, '多选': 4, '判断': 6},
        '中华人民共和国烟草专卖法实施条例': {'单选': 9, '多选': 4, '判断': 5},
        '烟草专卖品准运证管理办法': {'单选': 5, '多选': 2, '判断': 3},
        '烟草专卖许可证管理办法': {'单选': 7, '多选': 3, '判断': 3},
        '烟草专卖行政处罚程序规定': {'单选': 7, '多选': 3, '判断': 3},
        '关于办理非法生产、销售烟草专卖品等刑事案件具体应用法律若干问题的解释': {'单选': 4, '多选': 2, '判断': 2},
        '福建省烟草专卖管理办法': {'单选': 2, '多选': 1, '判断': 1},
        '福建省反走私综合治理条例': {'单选': 1, '多选': 1, '判断': 1},
        '未成年人保护法与\u201c电子烟\u201d两通告': {'单选': 2, '多选': 1, '判断': 1},
        '电子烟管理办法': {'单选': 1, '多选': 2, '判断': 1},
        '关于贯彻法治政府建设实施纲要深入推进法治烟草建设的指导意见／关于全面推进法治烟草建设的指导意见': {'单选': 1, '多选': 1, '判断': 1},
    }
    COM_EXAM_DIST = {
        '行政处罚法': {'单选': 10, '多选': 4, '判断': 8},
        '行政许可法': {'单选': 10, '多选': 4, '判断': 5},
        '行政诉讼法': {'单选': 6, '多选': 2, '判断': 4},
        '行政复议法': {'单选': 6, '多选': 2, '判断': 3},
        '习近平法治思想': {'单选': 3, '多选': 2, '判断': 2},
        '行政强制法': {'单选': 3, '多选': 1, '判断': 1},
        '宪法': {'单选': 3, '多选': 1, '判断': 1},
        '刑法': {'单选': 2, '多选': 1, '判断': 2},
        '行政复议法实施条例': {'单选': 3, '多选': 1, '判断': 1},
        '民法典': {'单选': 2, '多选': 1, '判断': 2},
        '立法法': {'单选': 2, '多选': 1, '判断': 1},
    }

    def handle_generate_exam(self, parsed):
        import random
        qs = parse_qs(parsed.query)
        exam_type = qs.get('type', ['pro'])[0]
        dist = self.PRO_EXAM_DIST if exam_type == 'pro' else self.COM_EXAM_DIST

        with open(QUESTIONS_PATH, 'r', encoding='utf-8') as f:
            all_q = json.load(f)

        # Build lookup: (law, type) -> list of questions
        lookup = {}
        for cat_sections in all_q.values():
            for s in cat_sections:
                for q in s['questions']:
                    key = (s['law'], q['type'])
                    if key not in lookup:
                        lookup[key] = []
                    lookup[key].append({**q, 'law': s['law']})

        exam_questions = []
        for law, types in dist.items():
            for qtype, count in types.items():
                pool = lookup.get((law, qtype), [])
                if len(pool) < count:
                    # Take all available if pool is smaller
                    picked = pool[:]
                else:
                    picked = random.sample(pool, count)
                exam_questions.extend(picked)

        # Group by type: 单选 → 多选 → 判断 (shuffle within each group)
        single = [q for q in exam_questions if q['type'] == '单选']
        multi = [q for q in exam_questions if q['type'] == '多选']
        judge = [q for q in exam_questions if q['type'] == '判断']
        random.shuffle(single)
        random.shuffle(multi)
        random.shuffle(judge)
        exam_questions = single + multi + judge
        return self.send_json(200, {'questions': exam_questions, 'total': len(exam_questions)})

    # ── Helpers ───────────────────────────────────────────────────────────

    def get_auth_user(self):
        token = self.headers.get('Authorization', '').replace('Bearer ', '')
        return get_user_from_token(token)

    def read_body(self):
        length = int(self.headers.get('Content-Length', 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode('utf-8'))
        except:
            return {}

    def send_json(self, code, data):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', len(body))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        self.end_headers()

    def log_message(self, format, *args):
        print(f"[{time.strftime('%H:%M:%S')}] {args[0]}")

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    init_db()
    print(f"DB_PATH: {DB_PATH}")
    print(f"QUESTIONS_PATH: {QUESTIONS_PATH}")
    server = HTTPServer((HOST, PORT), QuizHandler)
    print(f"Quiz server running at http://{HOST}:{PORT}")
    print(f"Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
        server.server_close()

if __name__ == '__main__':
    main()
