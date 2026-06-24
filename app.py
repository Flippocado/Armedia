import os
import uuid
from io import BytesIO

from flask import Flask, request, jsonify, send_from_directory, session
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image

import database


def _exec(conn, sql, params=()):
    cur = conn.cursor()
    cur.execute(sql, params)
    return cur

def _one(conn, sql, params=()):
    cur = _exec(conn, sql, params)
    return cur.fetchone()

def _all(conn, sql, params=()):
    cur = _exec(conn, sql, params)
    return cur.fetchall()

def _run(conn, sql, params=()):
    _exec(conn, sql, params)

def _insert(conn, sql, params=()):
    cur = _exec(conn, sql + " RETURNING id", params)
    return cur.fetchone()["id"]


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")
CORS(app, supports_credentials=True)

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads", "profile_pictures")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
AVATAR_SIZE = 512


def get_db():
    return database.get_connection()


def current_user_id():
    return session.get("user_id")


def require_auth():
    uid = current_user_id()
    if not uid:
        return None, (jsonify({"error": "Not authenticated"}), 401)
    return uid, None


def user_to_dict(row):
    d = dict(row)
    if d.get("profile_picture"):
        d["avatar_url"] = f"/avatar/image/{d['profile_picture']}"
    else:
        d["avatar_url"] = None
    d.pop("password_hash", None)
    return d


def validate_handle(handle):
    import re
    return bool(re.match(r'^[a-zA-Z0-9_]{3,32}$', handle))


def process_avatar(file_bytes, original_filename):
    ext = original_filename.rsplit(".", 1)[-1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return None, "Unsupported file type"
    if len(file_bytes) > MAX_FILE_SIZE:
        return None, "File exceeds 5 MB limit"
    try:
        img = Image.open(BytesIO(file_bytes))
        img.verify()
        img = Image.open(BytesIO(file_bytes))
    except Exception:
        return None, "Invalid or corrupt image file"
    img = img.convert("RGB") if img.mode not in ("RGB", "RGBA") else img
    w, h = img.size
    side = min(w, h)
    left = (w - side) // 2
    top = (h - side) // 2
    img = img.crop((left, top, left + side, top + side))
    if side > AVATAR_SIZE:
        img = img.resize((AVATAR_SIZE, AVATAR_SIZE), Image.LANCZOS)
    save_ext = "png" if ext in ("png", "webp") else "jpeg"
    unique_id = uuid.uuid4().hex[:8]
    filename = f"{unique_id}_avatar.{save_ext}"
    out = BytesIO()
    if save_ext == "jpeg":
        img.save(out, format="JPEG", quality=85, optimize=True)
    else:
        img.save(out, format="PNG", optimize=True)
    return filename, out.getvalue()


# ── Auth ────────────────────────────────────────────────────────────────────

@app.route("/register", methods=["POST"])
def register():
    print("REGISTER HIT")
    data = request.get_json(force=True)
    display_name = (data.get("display_name") or "").strip()
    handle = (data.get("handle") or "").strip().lstrip("@")
    password = data.get("password") or ""
    email = (data.get("email") or "").strip() or None

    if not display_name:
        return jsonify({"error": "Display name is required"}), 400
    if not handle or not validate_handle(handle):
        return jsonify({"error": "Handle must be 3-32 characters (letters, numbers, underscores)"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    pw_hash = generate_password_hash(password)
    conn = get_db()
    try:
        _run(conn,
            "INSERT INTO users (display_name, handle, email, password_hash) VALUES (%s, %s, %s, %s)",
            (display_name, handle, email, pw_hash),
        )
        conn.commit()
        row = _one(conn, "SELECT * FROM users WHERE handle = %s", (handle,))
        session["user_id"] = row["id"]
        return jsonify({"message": "Registered", "user": user_to_dict(row)}), 201
    except Exception as e:
        if "unique" in str(e).lower():
            return jsonify({"error": "Handle already taken"}), 409
        return jsonify({"error": "Registration failed"}), 500
    finally:
        conn.close()


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    handle = (data.get("handle") or "").strip().lstrip("@")
    password = data.get("password") or ""
    conn = get_db()
    try:
        row = _one(conn, "SELECT * FROM users WHERE handle = %s", (handle,))
        if not row or not check_password_hash(row["password_hash"], password):
            return jsonify({"error": "Invalid handle or password"}), 401
        session["user_id"] = row["id"]
        return jsonify({"message": "Logged in", "user": user_to_dict(row)})
    finally:
        conn.close()


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out"})


# ── Account ──────────────────────────────────────────────────────────────────

@app.route("/account", methods=["GET"])
def get_account():
    uid, err = require_auth()
    if err:
        return err
    conn = get_db()
    try:
        row = _one(conn, "SELECT * FROM users WHERE id = %s", (uid,))
        if not row:
            return jsonify({"error": "User not found"}), 404
        return jsonify(user_to_dict(row))
    finally:
        conn.close()


@app.route("/account/update", methods=["POST"])
def update_account():
    uid, err = require_auth()
    if err:
        return err
    data = request.get_json(force=True)
    conn = get_db()
    try:
        current = _one(conn, "SELECT * FROM users WHERE id = %s", (uid,))
        if not current:
            return jsonify({"error": "User not found"}), 404

        display_name = (data.get("display_name") or "").strip() or current["display_name"]
        handle = (data.get("handle") or "").strip().lstrip("@") or current["handle"]
        email = data.get("email")
        if email is not None:
            email = email.strip() or None
        else:
            email = current["email"]

        if not validate_handle(handle):
            return jsonify({"error": "Invalid handle format"}), 400

        if data.get("new_password"):
            if len(data["new_password"]) < 6:
                return jsonify({"error": "Password must be at least 6 characters"}), 400
            pw_hash = generate_password_hash(data["new_password"])
        else:
            pw_hash = current["password_hash"]

        _run(conn,
            "UPDATE users SET display_name=%s, handle=%s, email=%s, password_hash=%s WHERE id=%s",
            (display_name, handle, email, pw_hash, uid),
        )
        conn.commit()
        updated = _one(conn, "SELECT * FROM users WHERE id = %s", (uid,))
        return jsonify({"message": "Updated", "user": user_to_dict(updated)})
    except Exception as e:
        if "unique" in str(e).lower():
            return jsonify({"error": "Handle already taken"}), 409
        return jsonify({"error": "Update failed"}), 500
    finally:
        conn.close()


@app.route("/account/delete", methods=["POST"])
def delete_account():
    uid, err = require_auth()
    if err:
        return err
    data = request.get_json(force=True)
    conn = get_db()
    try:
        row = _one(conn, "SELECT * FROM users WHERE id = %s", (uid,))
        if not row:
            return jsonify({"error": "User not found"}), 404
        if not check_password_hash(row["password_hash"], data.get("password", "")):
            return jsonify({"error": "Incorrect password"}), 403
        if row["profile_picture"]:
            pic_path = os.path.join(UPLOAD_FOLDER, row["profile_picture"])
            if os.path.exists(pic_path):
                os.remove(pic_path)
        _run(conn, "DELETE FROM users WHERE id = %s", (uid,))
        conn.commit()
        session.clear()
        return jsonify({"message": "Account deleted"})
    finally:
        conn.close()


# ── Avatars ───────────────────────────────────────────────────────────────────

@app.route("/avatar/upload", methods=["POST"])
def upload_avatar():
    uid, err = require_auth()
    if err:
        return err
    if "avatar" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    file = request.files["avatar"]
    if not file.filename:
        return jsonify({"error": "Empty filename"}), 400
    raw = file.read()
    filename, result = process_avatar(raw, file.filename)
    if filename is None:
        return jsonify({"error": result}), 400
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    with open(filepath, "wb") as f:
        f.write(result)
    conn = get_db()
    try:
        old = _one(conn, "SELECT profile_picture FROM users WHERE id = %s", (uid,))
        if old and old["profile_picture"]:
            old_path = os.path.join(UPLOAD_FOLDER, old["profile_picture"])
            if os.path.exists(old_path):
                os.remove(old_path)
        _run(conn, "UPDATE users SET profile_picture = %s WHERE id = %s", (filename, uid))
        conn.commit()
        return jsonify({"message": "Avatar uploaded", "filename": filename, "avatar_url": f"/avatar/image/{filename}"})
    finally:
        conn.close()


@app.route("/avatar/remove", methods=["POST"])
def remove_avatar():
    uid, err = require_auth()
    if err:
        return err
    conn = get_db()
    try:
        row = _one(conn, "SELECT profile_picture FROM users WHERE id = %s", (uid,))
        if row and row["profile_picture"]:
            pic_path = os.path.join(UPLOAD_FOLDER, row["profile_picture"])
            if os.path.exists(pic_path):
                os.remove(pic_path)
        _run(conn, "UPDATE users SET profile_picture = NULL WHERE id = %s", (uid,))
        conn.commit()
        return jsonify({"message": "Avatar removed"})
    finally:
        conn.close()


@app.route("/avatar/image/<filename>")
def serve_avatar(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)


# ── Users ─────────────────────────────────────────────────────────────────────

@app.route("/users/search", methods=["GET"])
def search_users():
    uid, err = require_auth()
    if err:
        return err
    query = request.args.get("q", "").strip()
    if not query:
        return jsonify([])
    conn = get_db()
    try:
        pattern = f"%{query}%"
        rows = _all(conn,
            "SELECT * FROM users WHERE (handle LIKE %s OR display_name LIKE %s) AND id != %s LIMIT 20",
            (pattern, pattern, uid),
        )
        return jsonify([user_to_dict(r) for r in rows])
    finally:
        conn.close()


@app.route("/users/<int:target_id>", methods=["GET"])
def get_user(target_id):
    uid, err = require_auth()
    if err:
        return err
    conn = get_db()
    try:
        row = _one(conn, "SELECT * FROM users WHERE id = %s", (target_id,))
        if not row:
            return jsonify({"error": "User not found"}), 404
        return jsonify(user_to_dict(row))
    finally:
        conn.close()


# ── Private Chats ─────────────────────────────────────────────────────────────

@app.route("/chats", methods=["GET"])
def list_chats():
    uid, err = require_auth()
    if err:
        return err
    conn = get_db()
    try:
        rows = _all(conn,
            """
            SELECT DISTINCT
                CASE WHEN sender_id = %s THEN receiver_id ELSE sender_id END AS other_id
            FROM private_messages
            WHERE sender_id = %s OR receiver_id = %s
            """,
            (uid, uid, uid),
        )
        result = []
        for r in rows:
            other = _one(conn, "SELECT * FROM users WHERE id = %s", (r["other_id"],))
            if other:
                result.append(user_to_dict(other))
        return jsonify(result)
    finally:
        conn.close()


@app.route("/chats/send", methods=["POST"])
def send_message():
    uid, err = require_auth()
    if err:
        return err
    data = request.get_json(force=True)
    receiver_id = data.get("receiver_id")
    message = (data.get("message") or "").strip()
    if not receiver_id or not message:
        return jsonify({"error": "receiver_id and message required"}), 400
    conn = get_db()
    try:
        target = _one(conn, "SELECT id FROM users WHERE id = %s", (receiver_id,))
        if not target:
            return jsonify({"error": "Recipient not found"}), 404
        _run(conn,
            "INSERT INTO private_messages (sender_id, receiver_id, message) VALUES (%s, %s, %s)",
            (uid, receiver_id, message),
        )
        conn.commit()
        return jsonify({"message": "Sent"}), 201
    finally:
        conn.close()


@app.route("/chats/history", methods=["GET"])
def chat_history():
    uid, err = require_auth()
    if err:
        return err
    other_id = request.args.get("with")
    if not other_id:
        return jsonify({"error": "Missing 'with' parameter"}), 400
    conn = get_db()
    try:
        rows = _all(conn,
            """
            SELECT pm.*, u.display_name, u.handle, u.profile_picture
            FROM private_messages pm
            JOIN users u ON u.id = pm.sender_id
            WHERE (pm.sender_id = %s AND pm.receiver_id = %s)
               OR (pm.sender_id = %s AND pm.receiver_id = %s)
            ORDER BY pm.timestamp ASC
            """,
            (uid, other_id, other_id, uid),
        )
        result = []
        for r in rows:
            d = dict(r)
            d["avatar_url"] = f"/avatar/image/{d['profile_picture']}" if d.get("profile_picture") else None
            result.append(d)
        return jsonify(result)
    finally:
        conn.close()


# ── Groups ────────────────────────────────────────────────────────────────────

@app.route("/groups", methods=["GET"])
def list_groups():
    uid, err = require_auth()
    if err:
        return err
    conn = get_db()
    try:
        rows = _all(conn,
            """
            SELECT g.*, u.display_name AS owner_name, u.handle AS owner_handle
            FROM groups g
            JOIN users u ON u.id = g.owner_id
            """,
        )
        result = []
        for r in rows:
            d = dict(r)
            member_count = _one(conn, 
                "SELECT COUNT(*) AS c FROM group_members WHERE group_id = %s", (d["id"],)
            )["c"]
            is_member = _one(conn, 
                "SELECT 1 FROM group_members WHERE group_id = %s AND user_id = %s", (d["id"], uid)
            )
            d["member_count"] = member_count
            d["is_member"] = bool(is_member)
            result.append(d)
        return jsonify(result)
    finally:
        conn.close()


@app.route("/groups/create", methods=["POST"])
def create_group():
    uid, err = require_auth()
    if err:
        return err
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Group name required"}), 400
    conn = get_db()
    try:
        group_id = _insert(conn, "INSERT INTO groups (name, owner_id) VALUES (%s, %s)", (name, uid))
        _run(conn, "INSERT INTO group_members (group_id, user_id) VALUES (%s, %s)", (group_id, uid))
        conn.commit()
        return jsonify({"message": "Group created", "group_id": group_id}), 201
    finally:
        conn.close()


@app.route("/groups/join", methods=["POST"])
def join_group():
    uid, err = require_auth()
    if err:
        return err
    data = request.get_json(force=True)
    group_id = data.get("group_id")
    if not group_id:
        return jsonify({"error": "group_id required"}), 400
    conn = get_db()
    try:
        group = _one(conn, "SELECT id FROM groups WHERE id = %s", (group_id,))
        if not group:
            return jsonify({"error": "Group not found"}), 404
        existing = _one(conn, 
            "SELECT 1 FROM group_members WHERE group_id = %s AND user_id = %s", (group_id, uid)
        )
        if existing:
            return jsonify({"message": "Already a member"})
        _run(conn, "INSERT INTO group_members (group_id, user_id) VALUES (%s, %s)", (group_id, uid))
        conn.commit()
        return jsonify({"message": "Joined group"})
    finally:
        conn.close()


@app.route("/groups/leave", methods=["POST"])
def leave_group():
    uid, err = require_auth()
    if err:
        return err
    data = request.get_json(force=True)
    group_id = data.get("group_id")
    conn = get_db()
    try:
        _run(conn,
            "DELETE FROM group_members WHERE group_id = %s AND user_id = %s", (group_id, uid)
        )
        conn.commit()
        return jsonify({"message": "Left group"})
    finally:
        conn.close()


@app.route("/groups/<int:group_id>/members", methods=["GET"])
def group_members(group_id):
    uid, err = require_auth()
    if err:
        return err
    conn = get_db()
    try:
        rows = _all(conn,
            """
            SELECT u.* FROM users u
            JOIN group_members gm ON gm.user_id = u.id
            WHERE gm.group_id = %s
            """,
            (group_id,),
        )
        return jsonify([user_to_dict(r) for r in rows])
    finally:
        conn.close()


@app.route("/groups/messages", methods=["GET"])
def group_messages():
    uid, err = require_auth()
    if err:
        return err
    group_id = request.args.get("group_id")
    if not group_id:
        return jsonify({"error": "group_id required"}), 400
    conn = get_db()
    try:
        rows = _all(conn,
            """
            SELECT gm.*, u.display_name, u.handle, u.profile_picture
            FROM group_messages gm
            JOIN users u ON u.id = gm.sender_id
            WHERE gm.group_id = %s
            ORDER BY gm.timestamp ASC
            """,
            (group_id,),
        )
        result = []
        for r in rows:
            d = dict(r)
            d["avatar_url"] = f"/avatar/image/{d['profile_picture']}" if d.get("profile_picture") else None
            result.append(d)
        return jsonify(result)
    finally:
        conn.close()


@app.route("/groups/messages/send", methods=["POST"])
def send_group_message():
    uid, err = require_auth()
    if err:
        return err
    data = request.get_json(force=True)
    group_id = data.get("group_id")
    message = (data.get("message") or "").strip()
    if not group_id or not message:
        return jsonify({"error": "group_id and message required"}), 400
    conn = get_db()
    try:
        member = _one(conn, 
            "SELECT 1 FROM group_members WHERE group_id = %s AND user_id = %s", (group_id, uid)
        )
        if not member:
            return jsonify({"error": "Not a member of this group"}), 403
        _run(conn,
            "INSERT INTO group_messages (group_id, sender_id, message) VALUES (%s, %s, %s)",
            (group_id, uid, message),
        )
        conn.commit()
        return jsonify({"message": "Sent"}), 201
    finally:
        conn.close()


# ── Forums ────────────────────────────────────────────────────────────────────

@app.route("/forums", methods=["GET"])
def list_forums():
    uid, err = require_auth()
    if err:
        return err
    conn = get_db()
    try:
        rows = _all(conn,
            """
            SELECT f.*, u.display_name AS creator_name, u.handle AS creator_handle
            FROM forums f
            JOIN users u ON u.id = f.creator_id
            ORDER BY f.created_at DESC
            """
        )
        result = []
        for r in rows:
            d = dict(r)
            thread_count = _one(conn, 
                "SELECT COUNT(*) AS c FROM threads WHERE forum_id = %s", (d["id"],)
            )["c"]
            d["thread_count"] = thread_count
            result.append(d)
        return jsonify(result)
    finally:
        conn.close()


@app.route("/forums/create", methods=["POST"])
def create_forum():
    uid, err = require_auth()
    if err:
        return err
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Forum name required"}), 400
    conn = get_db()
    try:
        forum_id = _insert(conn, "INSERT INTO forums (name, creator_id) VALUES (%s, %s)", (name, uid))
        conn.commit()
        return jsonify({"message": "Forum created", "forum_id": forum_id}), 201
    finally:
        conn.close()


@app.route("/forums/<int:forum_id>/threads", methods=["GET"])
def list_threads(forum_id):
    uid, err = require_auth()
    if err:
        return err
    conn = get_db()
    try:
        rows = _all(conn,
            """
            SELECT t.*, u.display_name AS author_name, u.handle AS author_handle, u.profile_picture
            FROM threads t
            JOIN users u ON u.id = t.author_id
            WHERE t.forum_id = %s
            ORDER BY t.created_at DESC
            """,
            (forum_id,),
        )
        result = []
        for r in rows:
            d = dict(r)
            reply_count = _one(conn, 
                "SELECT COUNT(*) AS c FROM forum_posts WHERE thread_id = %s", (d["id"],)
            )["c"]
            d["reply_count"] = reply_count
            d["avatar_url"] = f"/avatar/image/{d['profile_picture']}" if d.get("profile_picture") else None
            result.append(d)
        return jsonify(result)
    finally:
        conn.close()


@app.route("/forums/thread/create", methods=["POST"])
def create_thread():
    uid, err = require_auth()
    if err:
        return err
    data = request.get_json(force=True)
    forum_id = data.get("forum_id")
    title = (data.get("title") or "").strip()
    content = (data.get("content") or "").strip()
    if not forum_id or not title or not content:
        return jsonify({"error": "forum_id, title, and content required"}), 400
    conn = get_db()
    try:
        forum = _one(conn, "SELECT id FROM forums WHERE id = %s", (forum_id,))
        if not forum:
            return jsonify({"error": "Forum not found"}), 404
        thread_id = _insert(conn,
            "INSERT INTO threads (forum_id, author_id, title) VALUES (%s, %s, %s)",
            (forum_id, uid, title),
        )
        _run(conn,
            "INSERT INTO forum_posts (thread_id, author_id, content) VALUES (%s, %s, %s)",
            (thread_id, uid, content),
        )
        conn.commit()
        return jsonify({"message": "Thread created", "thread_id": thread_id}), 201
    finally:
        conn.close()


@app.route("/forums/thread/<int:thread_id>", methods=["GET"])
def get_thread(thread_id):
    uid, err = require_auth()
    if err:
        return err
    conn = get_db()
    try:
        thread = _one(conn,
            """
            SELECT t.*, u.display_name AS author_name, u.handle AS author_handle
            FROM threads t JOIN users u ON u.id = t.author_id
            WHERE t.id = %s
            """,
            (thread_id,),
        )
        if not thread:
            return jsonify({"error": "Thread not found"}), 404
        posts = _all(conn,
            """
            SELECT fp.*, u.display_name, u.handle, u.profile_picture
            FROM forum_posts fp
            JOIN users u ON u.id = fp.author_id
            WHERE fp.thread_id = %s
            ORDER BY fp.timestamp ASC
            """,
            (thread_id,),
        )
        result_posts = []
        for p in posts:
            d = dict(p)
            d["avatar_url"] = f"/avatar/image/{d['profile_picture']}" if d.get("profile_picture") else None
            result_posts.append(d)
        return jsonify({"thread": dict(thread), "posts": result_posts})
    finally:
        conn.close()


@app.route("/forums/thread/reply", methods=["POST"])
def reply_to_thread():
    uid, err = require_auth()
    if err:
        return err
    data = request.get_json(force=True)
    thread_id = data.get("thread_id")
    content = (data.get("content") or "").strip()
    if not thread_id or not content:
        return jsonify({"error": "thread_id and content required"}), 400
    conn = get_db()
    try:
        thread = _one(conn, "SELECT id FROM threads WHERE id = %s", (thread_id,))
        if not thread:
            return jsonify({"error": "Thread not found"}), 404
        _run(conn,
            "INSERT INTO forum_posts (thread_id, author_id, content) VALUES (%s, %s, %s)",
            (thread_id, uid, content),
        )
        conn.commit()
        return jsonify({"message": "Reply posted"}), 201
    finally:
        conn.close()


# ── Startup ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    database.init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
