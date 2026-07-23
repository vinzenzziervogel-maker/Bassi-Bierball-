import streamlit as st
import psycopg2
import psycopg2.extras
import pandas as pd
import hashlib
import secrets
import os
import time
import functools
from datetime import date, datetime
import plotly.graph_objects as go

import streamlit.components.v1 as components

DATABASE_URL = os.environ.get("DATABASE_URL", "")
ADMIN_USERNAME = "469Vini"

def get_conn(max_retries=3, retry_delay=0.4):
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL ist nicht gesetzt. Bitte als Umgebungsvariable in Render hinterlegen.")
    last_error = None
    for attempt in range(max_retries):
        try:
            conn = psycopg2.connect(DATABASE_URL, sslmode="require", connect_timeout=10)
            conn.autocommit = False
            return conn
        except psycopg2.OperationalError as e:
            last_error = e
            if attempt < max_retries - 1:
                time.sleep(retry_delay * (attempt + 1))
    raise last_error

def init_db():
    conn = get_conn()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            display_name TEXT NOT NULL,
            is_admin BOOLEAN DEFAULT FALSE,
            password_reset_allowed BOOLEAN DEFAULT FALSE
        )
    """)
    c.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE")
    c.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS password_reset_allowed BOOLEAN DEFAULT FALSE")
    c.execute("UPDATE users SET is_admin = TRUE WHERE username = %s", (ADMIN_USERNAME,))
    conn.commit()
    c.execute("""
        CREATE TABLE IF NOT EXISTS friendships (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            friend_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            requested_by INTEGER NOT NULL,
            UNIQUE(user_id, friend_id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS rulesets (
            id SERIAL PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            tropfen_erlaubt INTEGER NOT NULL,
            wurf_von_oben INTEGER NOT NULL,
            drei_sekunden_regel INTEGER NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS matches (
            id SERIAL PRIMARY KEY,
            match_date TEXT NOT NULL,
            ruleset_id INTEGER NOT NULL REFERENCES rulesets(id),
            host_id INTEGER NOT NULL REFERENCES users(id),
            winner TEXT,
            status TEXT NOT NULL,
            created_at TEXT,
            ort TEXT,
            notizen TEXT
        )
    """)
    c.execute("ALTER TABLE matches ADD COLUMN IF NOT EXISTS created_at TEXT")
    c.execute("ALTER TABLE matches ADD COLUMN IF NOT EXISTS ort TEXT")
    c.execute("ALTER TABLE matches ADD COLUMN IF NOT EXISTS notizen TEXT")

    c.execute("""
        CREATE TABLE IF NOT EXISTS match_invites (
            id SERIAL PRIMARY KEY,
            match_id INTEGER NOT NULL REFERENCES matches(id),
            user_id INTEGER NOT NULL REFERENCES users(id),
            team TEXT NOT NULL,
            status TEXT NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS match_participants (
            id SERIAL PRIMARY KEY,
            match_id INTEGER NOT NULL REFERENCES matches(id),
            user_id INTEGER NOT NULL REFERENCES users(id),
            team TEXT NOT NULL,
            treffer INTEGER,
            wuerfe INTEGER,
            platzierung INTEGER,
            strafrunden INTEGER
        )
    """)
    c.execute("ALTER TABLE match_participants ADD COLUMN IF NOT EXISTS strafrunden INTEGER")
    c.execute("""
        CREATE TABLE IF NOT EXISTS remember_tokens (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            token TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()

    c.execute("""
        CREATE TABLE IF NOT EXISTS groups (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            creator_id INTEGER NOT NULL REFERENCES users(id),
            created_at TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS group_members (
            id SERIAL PRIMARY KEY,
            group_id INTEGER NOT NULL REFERENCES groups(id),
            user_id INTEGER NOT NULL REFERENCES users(id),
            UNIQUE(group_id, user_id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS group_invites (
            id SERIAL PRIMARY KEY,
            group_id INTEGER NOT NULL REFERENCES groups(id),
            user_id INTEGER NOT NULL REFERENCES users(id),
            status TEXT NOT NULL,
            invited_by INTEGER NOT NULL REFERENCES users(id)
        )
    """)
    c.execute("ALTER TABLE matches ADD COLUMN IF NOT EXISTS group_id INTEGER REFERENCES groups(id)")
    conn.commit()

    c.execute("""
        CREATE TABLE IF NOT EXISTS temp_play_permissions (
            id SERIAL PRIMARY KEY,
            granter_id INTEGER NOT NULL REFERENCES users(id),
            grantee_id INTEGER NOT NULL REFERENCES users(id),
            expires_at TEXT NOT NULL
        )
    """)
    conn.commit()

    c.execute("SELECT COUNT(*) FROM rulesets")
    if c.fetchone()[0] == 0:
        c.executemany(
            "INSERT INTO rulesets (name, tropfen_erlaubt, wurf_von_oben, drei_sekunden_regel) VALUES (%s,%s,%s,%s)",
            [("Bassi-Regeln", 0, 0, 1), ("Studentenregeln", 1, 1, 0)]
        )
        conn.commit()
    conn.close()

def retry_db_write(max_retries=3, retry_delay=0.4):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_error = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
                    last_error = e
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay * (attempt + 1))
            raise last_error
        return wrapper
    return decorator

def hash_password(password, salt):
    return hashlib.sha256((salt + password).encode()).hexdigest()

def create_user(username, password, display_name):
    conn = get_conn()
    salt = secrets.token_hex(8)
    ph = hash_password(password, salt)
    ok = True
    try:
        c = conn.cursor()
        c.execute(
            """INSERT INTO users
               (username, password_hash, salt, display_name, is_admin, password_reset_allowed)
               VALUES (%s,%s,%s,%s,%s,%s)""",
            (username, ph, salt, display_name, False, False)
        )
        conn.commit()
    except psycopg2.IntegrityError:
        conn.rollback()
        ok = False
    finally:
        conn.close()
    return ok

def verify_login(username, password):
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute(
            "SELECT id, password_hash, salt, display_name, is_admin FROM users WHERE username = %s",
            (username,)
        )
        row = c.fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    user_id, ph, salt, display_name, is_admin = row
    if hash_password(password, salt) == ph:
        return {"id": user_id, "display_name": display_name, "username": username, "is_admin": bool(is_admin)}
    return None

def is_password_reset_allowed(username):
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute("SELECT id, password_reset_allowed FROM users WHERE username = %s", (username,))
        row = c.fetchone()
    finally:
        conn.close()
    if row is None:
        return None, False
    return row[0], bool(row[1])

def set_password_reset_allowed(target_user_id, allowed):
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute("UPDATE users SET password_reset_allowed = %s WHERE id = %s", (allowed, target_user_id))
        conn.commit()
    finally:
        conn.close()

def perform_one_time_password_reset(user_id, new_password):
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute("SELECT password_reset_allowed FROM users WHERE id = %s", (user_id,))
        row = c.fetchone()
        if row is None or not bool(row[0]):
            return False
        new_salt = secrets.token_hex(8)
        new_hash = hash_password(new_password, new_salt)
        c.execute(
            "UPDATE users SET password_hash = %s, salt = %s, password_reset_allowed = FALSE WHERE id = %s",
            (new_hash, new_salt, user_id)
        )
        conn.commit()
        return True
    finally:
        conn.close()

def create_remember_token(user_id):
    conn = get_conn()
    try:
        c = conn.cursor()
        token = secrets.token_hex(32)
        c.execute(
            "INSERT INTO remember_tokens (user_id, token, created_at) VALUES (%s,%s,%s)",
            (user_id, token, str(datetime.now()))
        )
        conn.commit()
    finally:
        conn.close()
    return token

def verify_remember_token(token):
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute(
            "SELECT u.id, u.username, u.display_name, u.is_admin FROM remember_tokens rt JOIN users u ON rt.user_id = u.id WHERE rt.token = %s",
            (token,)
        )
        row = c.fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    return {"id": row[0], "username": row[1], "display_name": row[2], "is_admin": bool(row[3])}

def delete_remember_token(token):
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute("DELETE FROM remember_tokens WHERE token = %s", (token,))
        conn.commit()
    finally:
        conn.close()

def get_user(user_id):
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute("SELECT id, username, display_name FROM users WHERE id = %s", (user_id,))
        row = c.fetchone()
    finally:
        conn.close()
    return row

def get_total_user_count():
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM users")
        count = c.fetchone()[0]
    finally:
        conn.close()
    return count

def get_all_users_overview():
    conn = get_conn()
    try:
        df = pd.read_sql(
            "SELECT id, username, display_name, is_admin, password_reset_allowed FROM users ORDER BY id",
            conn
        )
    finally:
        conn.close()
    return df

def get_all_matches_for_admin():
    conn = get_conn()
    try:
        df = pd.read_sql("""
            SELECT m.id, m.match_date AS "Datum", r.name AS "Regelwerk", m.status AS "Status",
                   u.display_name AS "Host", m.ort AS "Ort"
            FROM matches m JOIN rulesets r ON m.ruleset_id = r.id JOIN users u ON m.host_id = u.id
            ORDER BY m.match_date DESC, m.id DESC
        """, conn)
    finally:
        conn.close()
    return df

def get_all_groups_for_admin():
    conn = get_conn()
    try:
        df = pd.read_sql("""
            SELECT g.id, g.name AS "Gruppe", u.display_name AS "Ersteller", g.created_at AS "Erstellt am",
                   COALESCE(mc.match_count, 0) AS "Spiele"
            FROM groups g
            JOIN users u ON g.creator_id = u.id
            LEFT JOIN (
                SELECT group_id, COUNT(*) AS match_count FROM matches WHERE group_id IS NOT NULL GROUP BY group_id
            ) mc ON mc.group_id = g.id
            ORDER BY g.name
        """, conn)
    finally:
        conn.close()
    return df

def delete_group(group_id):
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute("UPDATE matches SET group_id = NULL WHERE group_id = %s", (group_id,))
        c.execute("DELETE FROM group_invites WHERE group_id = %s", (group_id,))
        c.execute("DELETE FROM group_members WHERE group_id = %s", (group_id,))
        c.execute("DELETE FROM groups WHERE id = %s", (group_id,))
        conn.commit()
    finally:
        conn.close()

def delete_user_account(target_user_id):
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute("SELECT id FROM matches WHERE host_id = %s", (target_user_id,))
        hosted_match_ids = [r[0] for r in c.fetchall()]
        for mid in hosted_match_ids:
            c.execute("DELETE FROM match_participants WHERE match_id = %s", (mid,))
            c.execute("DELETE FROM match_invites WHERE match_id = %s", (mid,))
            c.execute("DELETE FROM matches WHERE id = %s", (mid,))

        c.execute("DELETE FROM match_participants WHERE user_id = %s", (target_user_id,))
        c.execute("DELETE FROM match_invites WHERE user_id = %s", (target_user_id,))
        c.execute("DELETE FROM friendships WHERE user_id = %s OR friend_id = %s", (target_user_id, target_user_id))
        c.execute("DELETE FROM remember_tokens WHERE user_id = %s", (target_user_id,))
        c.execute("DELETE FROM users WHERE id = %s", (target_user_id,))
        conn.commit()
    finally:
        conn.close()

def delete_user_account(target_user_id):
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute("SELECT id FROM matches WHERE host_id = %s", (target_user_id,))
        hosted_match_ids = [row[0] for row in c.fetchall()]
        for mid in hosted_match_ids:
            c.execute("DELETE FROM match_participants WHERE match_id = %s", (mid,))
            c.execute("DELETE FROM match_invites WHERE match_id = %s", (mid,))
        c.execute("DELETE FROM matches WHERE host_id = %s", (target_user_id,))
        c.execute("DELETE FROM match_participants WHERE user_id = %s", (target_user_id,))
        c.execute("DELETE FROM match_invites WHERE user_id = %s", (target_user_id,))
        c.execute("DELETE FROM friendships WHERE user_id = %s OR friend_id = %s", (target_user_id, target_user_id))
        c.execute("DELETE FROM remember_tokens WHERE user_id = %s", (target_user_id,))
        c.execute("DELETE FROM users WHERE id = %s", (target_user_id,))
        conn.commit()
    finally:
        conn.close()

def update_profile(user_id, display_name):
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute("UPDATE users SET display_name = %s WHERE id = %s", (display_name, user_id))
        conn.commit()
    finally:
        conn.close()

def search_users(query, exclude_id):
    conn = get_conn()
    try:
        df = pd.read_sql(
            "SELECT id, username, display_name FROM users WHERE (username ILIKE %s OR display_name ILIKE %s) AND id != %s",
            conn, params=(f"%{query}%", f"%{query}%", exclude_id)
        )
    finally:
        conn.close()
    return df

@retry_db_write()
def send_friend_request(user_id, friend_id):
    conn = get_conn()
    ok = True
    try:
        c = conn.cursor()
        c.execute(
            "INSERT INTO friendships (user_id, friend_id, status, requested_by) VALUES (%s,%s,%s,%s)",
            (user_id, friend_id, "ausstehend", user_id)
        )
        conn.commit()
    except psycopg2.IntegrityError:
        conn.rollback()
        ok = False
    finally:
        conn.close()
    return ok

@retry_db_write()
def respond_friend_request(request_id, accept):
    conn = get_conn()
    try:
        c = conn.cursor()
        if accept:
            c.execute("UPDATE friendships SET status = 'akzeptiert' WHERE id = %s", (request_id,))
        else:
            c.execute("DELETE FROM friendships WHERE id = %s", (request_id,))
        conn.commit()
    finally:
        conn.close()

def get_pending_friend_requests(user_id):
    conn = get_conn()
    try:
        df = pd.read_sql("""
            SELECT f.id, u.id AS requester_id, u.display_name, u.username
            FROM friendships f JOIN users u ON f.requested_by = u.id
            WHERE f.friend_id = %s AND f.status = 'ausstehend' AND f.requested_by != %s
        """, conn, params=(user_id, user_id))
    finally:
        conn.close()
    return df

def get_friends(user_id):
    conn = get_conn()
    try:
        df = pd.read_sql("""
            SELECT u.id, u.display_name, u.username FROM friendships f
            JOIN users u ON u.id = (CASE WHEN f.user_id = %s THEN f.friend_id ELSE f.user_id END)
            WHERE (f.user_id = %s OR f.friend_id = %s) AND f.status = 'akzeptiert'
        """, conn, params=(user_id, user_id, user_id))
    finally:
        conn.close()
    return df

def create_group(name, creator_id):
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute(
            "INSERT INTO groups (name, creator_id, created_at) VALUES (%s,%s,%s) RETURNING id",
            (name, creator_id, str(datetime.now()))
        )
        group_id = c.fetchone()[0]
        c.execute("INSERT INTO group_members (group_id, user_id) VALUES (%s,%s)", (group_id, creator_id))
        conn.commit()
    finally:
        conn.close()
    return group_id

def get_my_groups(user_id):
    conn = get_conn()
    try:
        df = pd.read_sql("""
            SELECT g.id, g.name, g.creator_id
            FROM groups g JOIN group_members gm ON gm.group_id = g.id
            WHERE gm.user_id = %s
            ORDER BY g.name
        """, conn, params=(user_id,))
    finally:
        conn.close()
    return df

def get_group_members(group_id):
    conn = get_conn()
    try:
        df = pd.read_sql("""
            SELECT u.id, u.display_name, u.username
            FROM group_members gm JOIN users u ON u.id = gm.user_id
            WHERE gm.group_id = %s
            ORDER BY u.display_name
        """, conn, params=(group_id,))
    finally:
        conn.close()
    return df

@retry_db_write()
def invite_to_group(group_id, user_id, invited_by):
    conn = get_conn()
    ok = True
    try:
        c = conn.cursor()
        c.execute("SELECT 1 FROM group_members WHERE group_id = %s AND user_id = %s", (group_id, user_id))
        if c.fetchone() is not None:
            ok = False
        else:
            c.execute(
                "INSERT INTO group_invites (group_id, user_id, status, invited_by) VALUES (%s,%s,%s,%s)",
                (group_id, user_id, "ausstehend", invited_by)
            )
            conn.commit()
    except psycopg2.IntegrityError:
        conn.rollback()
        ok = False
    finally:
        conn.close()
    return ok

def get_pending_group_invites(user_id):
    conn = get_conn()
    try:
        df = pd.read_sql("""
            SELECT gi.id AS invite_id, g.id AS group_id, g.name AS group_name, u.display_name AS invited_by_name
            FROM group_invites gi
            JOIN groups g ON gi.group_id = g.id
            JOIN users u ON gi.invited_by = u.id
            WHERE gi.user_id = %s AND gi.status = 'ausstehend'
        """, conn, params=(user_id,))
    finally:
        conn.close()
    return df

@retry_db_write()
def respond_group_invite(invite_id, accept):
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute("SELECT group_id, user_id FROM group_invites WHERE id = %s", (invite_id,))
        row = c.fetchone()
        if row:
            group_id, uid = row
            if accept:
                c.execute(
                    "INSERT INTO group_members (group_id, user_id) VALUES (%s,%s) ON CONFLICT DO NOTHING",
                    (group_id, uid)
                )
                c.execute("UPDATE group_invites SET status = 'angenommen' WHERE id = %s", (invite_id,))
            else:
                c.execute("UPDATE group_invites SET status = 'abgelehnt' WHERE id = %s", (invite_id,))
            conn.commit()
    finally:
        conn.close()

def find_common_groups(user_ids):
    if not user_ids:
        return pd.DataFrame(columns=["id", "name"])
    conn = get_conn()
    try:
        df = pd.read_sql("""
            SELECT g.id, g.name
            FROM groups g
            WHERE NOT EXISTS (
                SELECT 1 FROM (SELECT UNNEST(%s::int[]) AS uid) needed
                WHERE NOT EXISTS (
                    SELECT 1 FROM group_members gm WHERE gm.group_id = g.id AND gm.user_id = needed.uid
                )
            )
            ORDER BY g.name
        """, conn, params=(user_ids,))
    finally:
        conn.close()
    return df

def get_group_player_stats(group_id):
    conn = get_conn()
    try:
        df = pd.read_sql("""
            SELECT u.id, u.display_name AS "Spieler",
                   COUNT(mp.id) AS "Spiele",
                   SUM(CASE WHEN mp.team = m.winner THEN 1 ELSE 0 END) AS "Siege",
                   ROUND(AVG(mp.treffer), 2) AS "Ø Treffer",
                   ROUND(AVG(mp.wuerfe), 2) AS "Ø Würfe",
                   ROUND(SUM(mp.treffer) * 1.0 / NULLIF(SUM(mp.wuerfe), 0), 3) AS "Trefferquote",
                   ROUND(AVG(mp.strafrunden), 2) AS "Ø Strafrunden",
                   COALESCE(SUM(mp.strafrunden), 0) AS "Strafrunden Gesamt",
                   ROUND(SUM(mp.strafrunden) * 1.0 / NULLIF(SUM(mp.wuerfe), 0), 3) AS "Strafrundenquote"
            FROM match_participants mp
            JOIN matches m ON mp.match_id = m.id AND m.status = 'abgeschlossen' AND m.group_id = %s
            JOIN users u ON mp.user_id = u.id
            GROUP BY u.id, u.display_name
        """, conn, params=(group_id,))
    finally:
        conn.close()
    if not df.empty:
        df["Siegquote"] = (df["Siege"] / df["Spiele"]).round(3)
        df = apply_ranking_sort(df)
    return df

def get_group_match_history_for_player(group_id, user_id):
    conn = get_conn()
    try:
        df = pd.read_sql("""
            SELECT m.match_date AS "Datum", m.id AS "match_id",
                   mp.treffer AS "Treffer", mp.wuerfe AS "Wuerfe",
                   CASE WHEN mp.team = m.winner THEN 1 ELSE 0 END AS "Sieg"
            FROM match_participants mp
            JOIN matches m ON mp.match_id = m.id AND m.status = 'abgeschlossen' AND m.group_id = %s
            WHERE mp.user_id = %s
            ORDER BY m.match_date ASC, m.id ASC
        """, conn, params=(group_id, user_id))
    finally:
        conn.close()
    if not df.empty:
        df["Spielnummer"] = df.index + 1
        df["Kum_Siege"] = df["Sieg"].cumsum()
        df["Siegquote_Verlauf"] = (df["Kum_Siege"] / df["Spielnummer"] * 100).round(1)
        df["Kum_Treffer"] = df["Treffer"].cumsum()
        df["Kum_Wuerfe"] = df["Wuerfe"].cumsum()
        df["Trefferquote_Verlauf"] = (df["Kum_Treffer"] / df["Kum_Wuerfe"].replace(0, pd.NA) * 100).round(1)
    return df

def apply_ranking_sort(df):
    df = df.copy()
    treffer_q = df["Trefferquote"].fillna(0)
    strafr_q = df["Strafrundenquote"].fillna(0) if "Strafrundenquote" in df.columns else pd.Series([0]*len(df))
    max_strafr = strafr_q.max() if strafr_q.max() > 0 else 1
    strafr_score = 1 - (strafr_q / max_strafr)
    df["_ranking_score"] = (treffer_q.rank(pct=True) * 0.5) + (strafr_score.rank(pct=True) * 0.5)
    df = df.sort_values(by=["Siegquote", "_ranking_score"], ascending=[False, False]).reset_index(drop=True)
    df = df.drop(columns=["_ranking_score"])
    return df

@retry_db_write()
def grant_temp_play_permission(granter_id, grantee_id, hours):
    conn = get_conn()
    try:
        c = conn.cursor()
        expires_at = datetime.now() + pd.Timedelta(hours=hours)
        c.execute(
            "INSERT INTO temp_play_permissions (granter_id, grantee_id, expires_at) VALUES (%s,%s,%s)",
            (granter_id, grantee_id, str(expires_at))
        )
        conn.commit()
    finally:
        conn.close()

def get_active_temp_permissions_granted(granter_id):
    conn = get_conn()
    try:
        df = pd.read_sql("""
            SELECT tpp.id, u.id AS grantee_id, u.display_name, u.username, tpp.expires_at
            FROM temp_play_permissions tpp
            JOIN users u ON tpp.grantee_id = u.id
            WHERE tpp.granter_id = %s AND tpp.expires_at > %s
            ORDER BY tpp.expires_at DESC
        """, conn, params=(granter_id, str(datetime.now())))
    finally:
        conn.close()
    return df

def get_players_addable_without_invite(host_id):
    conn = get_conn()
    try:
        df = pd.read_sql("""
            SELECT u.id, u.display_name, u.username
            FROM temp_play_permissions tpp
            JOIN users u ON tpp.granter_id = u.id
            WHERE tpp.grantee_id = %s AND tpp.expires_at > %s
        """, conn, params=(host_id, str(datetime.now())))
    finally:
        conn.close()
    return df

def revoke_temp_permission(permission_id):
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute("DELETE FROM temp_play_permissions WHERE id = %s", (permission_id,))
        conn.commit()
    finally:
        conn.close()

def cleanup_expired_temp_permissions():
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute("DELETE FROM temp_play_permissions WHERE expires_at <= %s", (str(datetime.now()),))
        conn.commit()
    finally:
        conn.close()

def get_rulesets():
    conn = get_conn()
    try:
        df = pd.read_sql("SELECT * FROM rulesets ORDER BY id", conn)
    finally:
        conn.close()
    return df

def save_custom_ruleset(name, flags):
    conn = get_conn()
    ok = True
    try:
        c = conn.cursor()
        c.execute(
            "INSERT INTO rulesets (name, tropfen_erlaubt, wurf_von_oben, drei_sekunden_regel) VALUES (%s,%s,%s,%s)",
            (name, *flags)
        )
        conn.commit()
    except psycopg2.IntegrityError:
        conn.rollback()
        ok = False
    finally:
        conn.close()
    return ok

@retry_db_write()
def create_match(match_date, ruleset_id, host_id, invite_assignments, ort="", notizen="", group_id=None, direct_add_ids=None):
    if direct_add_ids is None:
        direct_add_ids = set()
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute(
            "INSERT INTO matches (match_date, ruleset_id, host_id, winner, status, created_at, ort, notizen, group_id) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
            (str(match_date), ruleset_id, host_id, None, "einladung_offen", str(datetime.now()), ort, notizen, group_id)
        )
        match_id = c.fetchone()[0]
        c.execute(
            "INSERT INTO match_participants (match_id, user_id, team, treffer, wuerfe, platzierung, strafrunden) VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (match_id, host_id, invite_assignments[host_id], None, None, None, None)
        )
        for uid, team in invite_assignments.items():
            if uid == host_id:
                continue
            if uid in direct_add_ids:
                c.execute(
                    "INSERT INTO match_participants (match_id, user_id, team, treffer, wuerfe, platzierung, strafrunden) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                    (match_id, uid, team, None, None, None, None)
                )
            else:
                c.execute(
                    "INSERT INTO match_invites (match_id, user_id, team, status) VALUES (%s,%s,%s,%s)",
                    (match_id, uid, team, "ausstehend")
                )
        conn.commit()
    finally:
        conn.close()
    return match_id

def get_pending_invites(user_id):
    conn = get_conn()
    try:
        df = pd.read_sql("""
            SELECT mi.id AS invite_id, m.id AS match_id, m.match_date, r.name AS regelwerk,
                   u.display_name AS host_name, mi.team
            FROM match_invites mi
            JOIN matches m ON mi.match_id = m.id
            JOIN rulesets r ON m.ruleset_id = r.id
            JOIN users u ON m.host_id = u.id
            WHERE mi.user_id = %s AND mi.status = 'ausstehend'
        """, conn, params=(user_id,))
    finally:
        conn.close()
    return df

@retry_db_write()
def respond_invite(invite_id, accept):
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute("SELECT match_id, user_id, team FROM match_invites WHERE id = %s", (invite_id,))
        row = c.fetchone()
        if row:
            match_id, user_id, team = row
            if accept:
                c.execute(
                    "INSERT INTO match_participants (match_id, user_id, team, treffer, wuerfe, platzierung, strafrunden) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                    (match_id, user_id, team, None, None, None, None)
                )
                c.execute("UPDATE match_invites SET status = 'angenommen' WHERE id = %s", (invite_id,))
            else:
                c.execute("UPDATE match_invites SET status = 'abgelehnt' WHERE id = %s", (invite_id,))
            conn.commit()
    finally:
        conn.close()

def get_open_matches_for_host(host_id):
    conn = get_conn()
    try:
        df = pd.read_sql("""
            SELECT m.id, m.match_date, r.name AS regelwerk, m.status, m.ort AS ort, m.notizen AS notizen
            FROM matches m JOIN rulesets r ON m.ruleset_id = r.id
            WHERE m.host_id = %s AND m.status = 'einladung_offen'
            ORDER BY m.match_date DESC
        """, conn, params=(host_id,))
    finally:
        conn.close()
    return df

def get_match_invite_status(match_id):
    conn = get_conn()
    try:
        df = pd.read_sql("""
            SELECT u.display_name AS "Spieler", mi.team AS "Team", mi.status AS "Status"
            FROM match_invites mi JOIN users u ON mi.user_id = u.id
            WHERE mi.match_id = %s
        """, conn, params=(match_id,))
    finally:
        conn.close()
    return df

def get_match_participants_for_completion(match_id):
    conn = get_conn()
    try:
        df = pd.read_sql("""
            SELECT mp.id, u.id AS user_id, u.display_name AS "Spieler", mp.team AS "Team"
            FROM match_participants mp JOIN users u ON mp.user_id = u.id
            WHERE mp.match_id = %s
            ORDER BY mp.team, u.display_name
        """, conn, params=(match_id,))
    finally:
        conn.close()
    return df

@retry_db_write()
def finalize_match(match_id, winner, stats_by_participant_id):
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute("UPDATE matches SET winner = %s, status = 'abgeschlossen' WHERE id = %s", (winner, match_id))
        for pid, stats in stats_by_participant_id.items():
            c.execute(
                "UPDATE match_participants SET treffer = %s, wuerfe = %s, platzierung = %s, strafrunden = %s WHERE id = %s",
                (stats["treffer"], stats["wuerfe"], stats["platzierung"], stats.get("strafrunden"), pid)
            )
        conn.commit()
    finally:
        conn.close()

def get_all_matches_feed():
    conn = get_conn()
    try:
        df = pd.read_sql("""
            SELECT m.id, m.match_date AS "Datum", r.name AS "Regelwerk", m.winner AS "Gewinner",
                   u.display_name AS "Host", m.host_id AS "HostId", m.status AS "Status", m.ort AS "Ort", m.notizen AS "Notizen"
            FROM matches m JOIN rulesets r ON m.ruleset_id = r.id JOIN users u ON m.host_id = u.id
            WHERE m.status IN ('einladung_offen', 'abgeschlossen')
            ORDER BY m.match_date DESC, m.id DESC
        """, conn)
    finally:
        conn.close()
    return df

def get_match_participants_view(match_id):
    conn = get_conn()
    try:
        df = pd.read_sql("""
            SELECT mp.team AS "Team", u.display_name AS "Spieler", mp.treffer AS "Treffer", mp.wuerfe AS "Wuerfe", mp.strafrunden AS "Strafrunden"
            FROM match_participants mp JOIN users u ON mp.user_id = u.id
            WHERE mp.match_id = %s
            ORDER BY mp.team, u.display_name
        """, conn, params=(match_id,))
    finally:
        conn.close()
    return df

def delete_match(match_id):
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute("DELETE FROM match_participants WHERE match_id = %s", (match_id,))
        c.execute("DELETE FROM match_invites WHERE match_id = %s", (match_id,))
        c.execute("DELETE FROM matches WHERE id = %s", (match_id,))
        conn.commit()
    finally:
        conn.close()

def get_player_stats_for_friends(user_id):
    friend_ids = get_friends(user_id)["id"].tolist() + [user_id]
    conn = get_conn()
    try:
        df = pd.read_sql("""
            SELECT u.id, u.display_name AS "Spieler",
                   COUNT(mp.id) AS "Spiele",
                   SUM(CASE WHEN mp.team = m.winner THEN 1 ELSE 0 END) AS "Siege",
                   ROUND(AVG(mp.treffer), 2) AS "Ø Treffer",
                   ROUND(AVG(mp.wuerfe), 2) AS "Ø Würfe",
                   ROUND(SUM(mp.treffer) * 1.0 / NULLIF(SUM(mp.wuerfe), 0), 3) AS "Trefferquote",
                   ROUND(AVG(mp.strafrunden), 2) AS "Ø Strafrunden",
                   COALESCE(SUM(mp.strafrunden), 0) AS "Strafrunden Gesamt",
                   ROUND(SUM(mp.strafrunden) * 1.0 / NULLIF(SUM(mp.wuerfe), 0), 3) AS "Strafrundenquote"
            FROM match_participants mp
            JOIN matches m ON mp.match_id = m.id AND m.status = 'abgeschlossen'
            JOIN users u ON mp.user_id = u.id
            WHERE u.id = ANY(%s)
            GROUP BY u.id, u.display_name
        """, conn, params=(friend_ids,))
    finally:
        conn.close()
    if not df.empty:
        df["Siegquote"] = (df["Siege"] / df["Spiele"]).round(3)
        df = apply_ranking_sort(df)
    return df

def get_stats_for_single_user(target_user_id):
    conn = get_conn()
    try:
        df = pd.read_sql("""
            SELECT u.id, u.display_name AS "Spieler",
                   COUNT(mp.id) AS "Spiele",
                   SUM(CASE WHEN mp.team = m.winner THEN 1 ELSE 0 END) AS "Siege",
                   ROUND(AVG(mp.treffer), 2) AS "Ø Treffer",
                   ROUND(AVG(mp.wuerfe), 2) AS "Ø Würfe",
                   ROUND(SUM(mp.treffer) * 1.0 / NULLIF(SUM(mp.wuerfe), 0), 3) AS "Trefferquote",
                   ROUND(AVG(mp.strafrunden), 2) AS "Ø Strafrunden",
                   COALESCE(SUM(mp.strafrunden), 0) AS "Strafrunden Gesamt"
            FROM match_participants mp
            JOIN matches m ON mp.match_id = m.id AND m.status = 'abgeschlossen'
            JOIN users u ON mp.user_id = u.id
            WHERE u.id = %s
            GROUP BY u.id, u.display_name
        """, conn, params=(target_user_id,))
    finally:
        conn.close()
    if not df.empty:
        df["Siegquote"] = (df["Siege"] / df["Spiele"]).round(3)
    return df

def get_match_history_for_player(user_id):
    conn = get_conn()
    try:
        df = pd.read_sql("""
            SELECT m.match_date AS "Datum", m.id AS "match_id",
                   mp.treffer AS "Treffer", mp.wuerfe AS "Wuerfe",
                   CASE WHEN mp.team = m.winner THEN 1 ELSE 0 END AS "Sieg"
            FROM match_participants mp
            JOIN matches m ON mp.match_id = m.id AND m.status = 'abgeschlossen'
            WHERE mp.user_id = %s
            ORDER BY m.match_date ASC, m.id ASC
        """, conn, params=(user_id,))
    finally:
        conn.close()
    if not df.empty:
        df["Spielnummer"] = df.index + 1
        df["Kum_Siege"] = df["Sieg"].cumsum()
        df["Siegquote_Verlauf"] = (df["Kum_Siege"] / df["Spielnummer"] * 100).round(1)
        df["Kum_Treffer"] = df["Treffer"].cumsum()
        df["Kum_Wuerfe"] = df["Wuerfe"].cumsum()
        df["Trefferquote_Verlauf"] = (df["Kum_Treffer"] / df["Kum_Wuerfe"].replace(0, pd.NA) * 100).round(1)
    return df

def get_full_match_list_for_user(target_user_id):
    conn = get_conn()
    try:
        df = pd.read_sql("""
            SELECT m.id, m.match_date AS "Datum", r.name AS "Regelwerk", m.winner, u.display_name AS "Host", m.ort AS "Ort"
            FROM match_participants mp
            JOIN matches m ON mp.match_id = m.id AND m.status = 'abgeschlossen'
            JOIN rulesets r ON m.ruleset_id = r.id
            JOIN users u ON m.host_id = u.id
            WHERE mp.user_id = %s
            ORDER BY m.match_date DESC, m.id DESC
        """, conn, params=(target_user_id,))
    finally:
        conn.close()
    return df

def get_latest_completed_match_result_for_user(uid):
    conn = get_conn()
    try:
        df = pd.read_sql("""
            SELECT m.id AS match_id, mp.team, m.winner
            FROM match_participants mp
            JOIN matches m ON mp.match_id = m.id AND m.status = 'abgeschlossen'
            WHERE mp.user_id = %s
            ORDER BY m.match_date DESC, m.id DESC
            LIMIT 1
        """, conn, params=(uid,))
    finally:
        conn.close()
    if df.empty:
        return None
    row = df.iloc[0]
    return {"match_id": int(row["match_id"]), "is_winner": row["team"] == row["winner"]}

def render_teams_vs(participants_df):
    team_a_names = participants_df.loc[participants_df["Team"] == "A", "Spieler"].tolist()
    team_b_names = participants_df.loc[participants_df["Team"] == "B", "Spieler"].tolist()
    team_a_str = ", ".join(team_a_names) if team_a_names else "–"
    team_b_str = ", ".join(team_b_names) if team_b_names else "–"
    st.markdown(f"**{team_a_str}**  vs  **{team_b_str}**")

def render_running_match_names(participants_df):
    st.markdown('<span style="color:#2e8b57; font-weight:700;">● Spiel laeuft</span>', unsafe_allow_html=True)

def render_match_stats_table(participants_df, winner):
    display_df = participants_df.copy()
    quotes = []
    for _, row in display_df.iterrows():
        w = row["Wuerfe"]
        t = row["Treffer"]
        if pd.notna(w) and w and w > 0:
            quotes.append(f"{(t / w * 100):.1f}%")
        else:
            quotes.append("–")
    display_df["Trefferquote"] = quotes
    display_df["Ergebnis"] = display_df["Team"].apply(lambda t: "Sieg" if t == winner else "Niederlage")
    if "Strafrunden" not in display_df.columns:
        display_df["Strafrunden"] = None
    display_df = display_df[["Spieler", "Team", "Ergebnis", "Treffer", "Wuerfe", "Trefferquote", "Strafrunden"]]
    st.dataframe(display_df, use_container_width=True, hide_index=True)

@st.cache_resource
def _run_init_db_once():
    init_db()
    return True

_init_db_ok = False
_init_db_last_error = None
for _init_attempt in range(3):
    try:
        _init_db_ok = _run_init_db_once()
        break
    except Exception as e:
        _init_db_last_error = e
        time.sleep(0.5 * (_init_attempt + 1))

if not _init_db_ok:
    st.error(f"Fehler bei der Datenbank-Initialisierung: {_init_db_last_error}")
    if st.button("🔁 Erneut versuchen"):
        st.cache_resource.clear()
        st.rerun()
    st.stop()

st.set_page_config(page_title="Bassi Bierball", layout="wide")

if "user" not in st.session_state:
    st.session_state.user = None

query_params = st.query_params
if st.session_state.user is None and "remember_token" in query_params:
    token_from_url = query_params["remember_token"]
    try:
        remembered_user = verify_remember_token(token_from_url)
        if remembered_user:
            st.session_state.user = remembered_user
    except Exception:
        pass

if st.session_state.user is None:
    if "pending_reset_username" not in st.session_state:
        st.session_state.pending_reset_username = None

    st.title("Bassi Bierball – Login")
    login_tab, register_tab = st.tabs(["Anmelden", "Registrieren"])

    with login_tab:
        if st.session_state.pending_reset_username:
            pw_username = st.session_state.pending_reset_username
            st.warning(f"Für den Account **{pw_username}** wurde ein einmaliger Passwort-Reset vom Admin freigeschaltet. Bitte setze jetzt ein neues Passwort.")
            with st.form("password_reset_form"):
                reset_new_pw = st.text_input("Neues Passwort", type="password", key="reset_new_pw_login")
                reset_new_pw2 = st.text_input("Neues Passwort wiederholen", type="password", key="reset_new_pw2_login")
                reset_submit = st.form_submit_button("Neues Passwort setzen")
                if reset_submit:
                    if not reset_new_pw or reset_new_pw != reset_new_pw2:
                        st.warning("Die Passwörter stimmen nicht überein oder sind leer.")
                    elif len(reset_new_pw) < 4:
                        st.warning("Das Passwort sollte mindestens 4 Zeichen haben.")
                    else:
                        target_uid, allowed = is_password_reset_allowed(pw_username)
                        if target_uid and allowed:
                            reset_success = perform_one_time_password_reset(target_uid, reset_new_pw)
                            if reset_success:
                                st.session_state.pending_reset_username = None
                                st.success("Passwort erfolgreich geändert. Du kannst dich jetzt mit deinem neuen Passwort anmelden.")
                                st.rerun()
                            else:
                                st.error("Der Passwort-Reset ist nicht mehr gültig. Bitte wende dich an den Admin.")
                                st.session_state.pending_reset_username = None
                                st.rerun()
                        else:
                            st.error("Der Passwort-Reset ist nicht mehr gültig. Bitte wende dich an den Admin.")
                            st.session_state.pending_reset_username = None
                            st.rerun()
            if st.button("Abbrechen", key="cancel_reset"):
                st.session_state.pending_reset_username = None
                st.rerun()
        else:
            with st.form("login_form"):
                u = st.text_input("Benutzername")
                p = st.text_input("Passwort", type="password")
                remember_me = st.checkbox("Angemeldet bleiben", value=True)
                submitted = st.form_submit_button("Anmelden")
                if submitted:
                    if not u.strip() or not p:
                        st.warning("Bitte Benutzername und Passwort eingeben.")
                    else:
                        try:
                            result = verify_login(u.strip(), p)
                        except Exception as e:
                            st.error(f"Technischer Fehler beim Login: {e}")
                            result = None
                        if result:
                            st.session_state.user = result
                            if remember_me:
                                token = create_remember_token(result["id"])
                                st.query_params["remember_token"] = token
                            st.rerun()
                        else:
                            try:
                                target_uid, allowed = is_password_reset_allowed(u.strip())
                            except Exception:
                                target_uid, allowed = None, False
                            if target_uid and allowed:
                                st.session_state.pending_reset_username = u.strip()
                                st.rerun()
                            else:
                                st.error("Benutzername oder Passwort falsch.")

    with register_tab:
        st.caption("Wähle einen Benutzernamen und ein Passwort. Falls du dein Passwort später vergisst, kann der Admin einen einmaligen Passwort-Reset für dich freischalten.")
        with st.form("register_form"):
            new_u = st.text_input("Benutzername wählen")
            new_dn = st.text_input("Anzeigename")
            new_p = st.text_input("Passwort", type="password")
            new_p2 = st.text_input("Passwort wiederholen", type="password")
            reg_submitted = st.form_submit_button("Account erstellen")
            if reg_submitted:
                if not new_u.strip() or not new_p or not new_dn.strip():
                    st.warning("Bitte Benutzername, Anzeigename und Passwort ausfüllen.")
                elif new_p != new_p2:
                    st.warning("Die beiden Passwörter stimmen nicht überein.")
                elif len(new_p) < 4:
                    st.warning("Das Passwort sollte mindestens 4 Zeichen haben.")
                else:
                    try:
                        success = create_user(new_u.strip(), new_p, new_dn.strip())
                    except Exception as e:
                        st.error(f"Technischer Fehler bei der Registrierung: {e}")
                        success = False
                    if success:
                        st.success("Account erstellt! Du kannst dich jetzt anmelden.")
                    else:
                        st.warning("Dieser Benutzername ist bereits vergeben.")
    st.stop()

user_id = st.session_state.user["id"]
display_name = st.session_state.user["display_name"]

st.sidebar.write(f"Angemeldet als **{display_name}**")

APP_URL = os.environ.get("APP_URL", "https://bierball-league-v2.onrender.com")
SHARE_MESSAGE = "Spiele ranked Bierball und finde heraus, wer die wahre Nummer 1 ist mit der Bassi Bierball App:"
SHARE_TEXT = SHARE_MESSAGE + " " + APP_URL

share_html = f"""
<div style="margin-bottom: 10px;">
  <button id="share-btn" style="
      width: 100%;
      padding: 0.6rem 1rem;
      background-color: #2e8b57;
      color: white;
      border: none;
      border-radius: 8px;
      font-size: 0.95rem;
      font-weight: 600;
      cursor: pointer;
  ">📤 App teilen</button>
</div>
<script>
  const btn = document.getElementById("share-btn");
  btn.addEventListener("click", async () => {{
    const shareData = {{
      title: "Bassi Bierball",
      text: {SHARE_MESSAGE!r},
      url: {APP_URL!r}
    }};
    if (navigator.share) {{
      try {{
        await navigator.share(shareData);
      }} catch (err) {{
        console.log("Teilen abgebrochen oder fehlgeschlagen:", err);
      }}
    }} else {{
      try {{
        await navigator.clipboard.writeText({SHARE_TEXT!r});
        btn.innerText = "✅ Link kopiert!";
        setTimeout(() => {{ btn.innerText = "📤 App teilen"; }}, 2000);
      }} catch (err) {{
        alert({SHARE_TEXT!r});
      }}
    }}
  }});
</script>
"""

with st.sidebar:
    components.html(share_html, height=60)

if st.sidebar.button("Abmelden"):
    if "remember_token" in st.query_params:
        try:
            delete_remember_token(st.query_params["remember_token"])
        except Exception:
            pass
        del st.query_params["remember_token"]
    st.session_state.user = None
    st.rerun()

BASSI_LOGO_GIF_BLACK_BASE64 = "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"
BASSI_LOGO_GIF_WHITE_BASE64 = "R0lGODlh9AGnAIEAAP7+/v///wAAAAAAACH/C05FVFNDQVBFMi4wAwEAAAAh+QQJZAAAACwAAAAA9AGnAAAI/wABCBxIsKDBgwgTKlzIsKHDhxAjSpxIsaLFixgzatzIsaPHjyBDihxJsqTJkyhTqlzJsqXLlzBjypxJs6bNmzhz6tzJs6fPn0CDCh1KtKjRo0iTKl3KtKnTp1CjSp1KtarVq1izat3KtavXr2DDih1LtqzZs2jTql3Ltq3bt3Djyp1Lt67du3jz6t3Lt6/fv4ADCx5MuLDhw4gTK17MuLHjx5AjS55MubLly5gza97MubPnz6BDix5NurTp06hTq17NurXr17Bjy55Nu7bt27hz697Nu7fv38CDCx9OvLjx48iTK1/OvLnz59CjS59Ovbr169iza78doLv3ANvDv//8Tr58d/HoSZpfXz69+4/s439/D5a8Zfn4wdPfKn9y/v77YfWffo4NyF6AAhpI4GIKmoegVQ16x2CE9j04FYXzIYZhhhZGtaGEh314XodQiQhiYSKS6KGJIxKWoopOsXiiixjC+JSMLdJIoY0x4qhhhDz2KOOPDQbJFI45oqigkUciqZiBTDbp45P5RSnlkIwBaKVSThbo4JZNYenljGBe+SFkHJYpZI1opqnmmktGVuFSG3Y4YGVzCrWeRV/u1+d9bvIUKHxkircnnn/alGdKg16nZZuHytSoS0lih5+cj6o06UyFUvffYxwmql6lPXUK3Z2NpRkpoaQOtalybor/qmShq2ZkalILnhqorIItOlCtFLW6YkG85taeQcAG9mqyDd0qFZS+8VpsX68KNC2ywlZFK7O0HYjQtXlVay242V617XzOxgbiptzi5atC0+ZaX67Hlvtahu8S1G5d+Sa0L1kt9mkva6qmC0Cmdol7ELhirXvswfLKVrDBEP/bVr/NYgywt+Nyd+7AFSvMlsYZR6zWqiCnNqjIgJHca54po2aqy8pSPCt4NutrMme30uyXzzfv7G/OlGX7MJExawb0Z0eHuDRmT/PMMLVNj0Zg0lJPrRfHVl8ttGj2sewu16HliHVmFYpNV5Vd66wazESvja7WRWOrMplRvzWnxXgu/yzzrmq75Svddju98Neb5Zv3yZNW7VDcdyHc5uONB56Wxo4zBHnC8SGKeMhfL16Wy5nDeza/nRc9sLiiN0zz05ujTjakmrPe+lelH070eafPJXmq6fp8e1e5D52yfr3L9XuWOAsN9PBZEa4zyF4btjyDHX+rNvTmik5ywJ9vHXH41v9qPPnEWs7f7ZhXb/34dVurffLcX6h++sH/in7k8PtnPraxG9f9IMS9zIGPSMSK38EAmDwBBrB7D8TfytzntOL9KHv6i2AGByi3d9XvTRNZFAenN0Ll5Q+EWpEeCgNkwRWqqIQujKEMZ0jDGtrwhjjMoQ53yMMe+vCHQAyiEFqHSMQiGvGISEyiEpfIxCY68YlQjKIUp0jFKlrxiljMoha3yMUuevGLYAyjGMdIxjKa8YxoTKMa18jGNrrxjXCMoxznSMc62vGOeMyjHvfIxz768Y+ADORkAgIAIfkECWQAAAAsAAAAAPQBpwCB////////AAAAAAAACP8AAQgcSLCgwYMIEypcyLChw4cQI0qcSLGixYsYM2rcyLGjx48gQ4ocSbKkyZMoU6pcybKly5cwY8qcSbOmzZs4c+rcybOnz59AgwodSrSo0aNIkypdyrSp06dQo0qdSrWq1atYs2rdyrWr169gw4odS7as2bNo06pdy7at27dw48qdS7eu3bt48+rdy7ev37+AAwseTLiw4cOIEytezLix48eQI0ueTLmy5cuYM2vezLmz58+gQ4seTbq06dOoU6tezbq169ewY8ueTbu27du4c+vezbu379/AgwsfTry48ePIkytfzry58+fQo0ufTr36xwDYs2u3zn2n9u/fE4L/H08+vOzt3WOWJx9y/XjP69PDdF9+/nvJ9APIb5m/fk3/hvWH3X4rCRgfT+j9ZWB2BKq0IIC8PchggydJyF5vFg5IoUkZ3rdbhxty2KF5uo0YIkkjeoibiSeKlCJ4H4LYYnsvTphbijPSWKN+JbKIEI85SrSjjSvKONCFQUI0pIY3GglAgk8CmWRDS0bUX5RIQjakQUxOSeWOLkEoWI0/SunlQmDeBKOCZBJE5JkMvfgTiXlZWJCYcKLpZFB00vWgnl3m+eWCTL0Zl4GAminoQ/lJZahbVyrU56JCToqce4kqSqmVWSq3ZqKbYoTpclCK92ionB6YnKVunoqqkpEa/8eqQKW+SpGAl7o6q62MlqqicLXSGiyvqQaK5a49GoossXF+2uqyRQYKLbOSOnuntRgSOS21Zf767LaxJQgut1xquGunTTI4LrnfCuuqu9japiq7lUq57KiAooYnvQ75+u6R+5abYWXe8juootvGex2+hSlsMKgCGwuUw3UO+zDEES9lsV0bX2yqpvCCbNS6aJH8sMQA/4tUx2uZ7PFB6D6lclosv9xszLLObPPHARNX884wv+eyvD8DnTKUQ9OWNL/oLn2ezkDjXHSMKBt9dMdTp1u10Th/K/JvTtvadcRfR0jxywXzXHayZ3vc9rVQXyRhYvRZ7XXcYS9cN17mpf9t89hwx21Tz2atCXhzh+td9NtC5e1Un34zF2tJkQe+dVJrb2Vp5blezflGn4ec+WoUM+4zkCpmXZHppgc9+mNtOy7v3QhfDjq4LgvO2LSyK0276yJOTbLqdONOvNmeS3x8vXirvnyAzj9fZPK1635rwuvqZ7tjJvf+GpNIhp6R8VkPaD1h4pMtOaEsCZ49j9sr1rrrr4O9d1bm1g+99PDaHSb8+msY/0TnvwIB0DJ5S18BRXVAonlvgfSLn2oeCEH6JauCGMygBtc3vw2ual4enM6nBhhCtiFNgiUcjpgCmELf5M9XLXzOC8XFwhim627CsiGppEU4HbpQWQr0odZXwEdCIc4GhEZMohKXyMQmOvGJUIyiFKdIxSpa8YpYzKIWt8jFLnrxi2AMoxjHSMYymvGMaEyjGtfIxja68Y1wjKMc50jHOtrxjnjMox73yMc++vGPHgsIACH5BAlkAAAALAAAAAD0AacAgf///////wAAAAAAAAj/AAEIHEiwoMGDCBMqXMiwocOHECNKnEixosWLGDNq3Mixo8ePIEOKHEmypMmTKFOqXMmypcuXMGPKnEmzps2bOHPq3Mmzp8+fQIMKHUq0qNGjSJMqXcq0qdOnUKNKnUq1qtWrWLNq3cq1q9evYMOKHUu2rNmzaNOqXcu2rdu3cOPKnUu3rt27ePPq3cu3r9+/gAMLHky4sOHDiBMrXsy4sePHkCNLnky5suXLmDNr3sy5s+fPoEOLHk26tOnTqFOrXs26tevXsGPLnk279sMAtnMLDsAbN2/dwMf2pvjbIO7gyJP2Ho5w+XHjzp8XlD6devLrPYsTpM7cOoDl1Q96/x84Hrv5muUVWtcO3fjC9Ofjt4R/G/569fLz06Qv3r3E8uzpJ+B8//n3noHb8TfggiKB19B9DEFInoIMVtggcxDxt55zFnYoU4DThRghgh6W+J+DGIEoEHcUbmfii/VFp2KB/YmYkHctwmihjDKmWKON7f2o45Df8WgkfkgC6WKQQhJlJIZE7vXklOqNZ+WN2s24olBT8hillF0e+V6PzUWoIVBhivllXWlSuVGOSrXp5Zp0yflkR3AiZWd0dNa555x+/glln24JCqhchqJIaKGJ8jlXo3ku2hWkjlakpVSQSvoWpRxaOmmjmjLK6aUHfppoqKJyOhGpVIGKalujDv86ZliuvrpWrKyumGtVp9oK66gPRhpVr77eCmygdhabaq2P7qnssoLileyz0MoJZpjUxuVsX9hm26ybgN3prV2VDnbouNqeG1in6CIqbmHstlttuebKKm9abRoW77348kkmvIrya9a/E+6aF70C00qwrvaCJGycCydsasMRexQwVuBKrFXFDF/MEcetdqkxxiCr+fFwDfPqoLojN8VywcWlbCl3XgX8cstGmSzeyjKfGN7EOyPMJM42iVwllD1nGKDBT3ncsdMME33Tu0ezyDSWSNcM9dNaJi31SvuOKevWDlX6sJ5eq0v21z+FXeTV0Dl69lFrwzxo3WzzBLXXWOv/nBXeXGfpW9507w33hG+DrDLcPcY8N+HzbS2s4EJf5XawZkM+1M0zVwd403z3naXmQWWc4oaHM/V5cyg+TvpJRmuEo+tFXb7qc7S/PhKHnEfUeu5Orl4leYmFDlq8vccoPOjGz7rlYctvFnbySotV+e3RI+ua09S7azv2iH0/Gtndb3q9Z7gD75j4gfNV/mXpq8a+3akP7Df60tVP2fwJZi+c6fhT0vhWd75ltS80S1Nf+D73vrMgr4CWwVFpIEg//SnMZhSczOwGCDjFQYt1/lvg/dZnH/4lrnkO/F4GHwNAEqZnhR781dpW2JgW1rBrJqRhv/BmwhuOkDEUY2AP6ndovCEqxoZA/E7QmKZDtDQxcdL74RF9YzUmGjGF2QthvRq4G115zopaBMsT7ZYZm2kQcfRTGgrtt8YvKvBgEpRM/Pp3tTaS5YpLfKO0mrQ+NO4vjFyLoIQgM8fKADKQhoyhvgpJG0UC0YLcOiT+7Kg7i1FygpXMpCY3yclOevKToAylKEdJylKa8pSoTKUqV8nKVrrylbCMpSxnScta2vKWuMylLnfJy1768pfADKYwh0nMYhrzmMhMpjKXycxmOvOZ0IymNKdJzWpa85rYzKY2t8nNbnrzm+AMpzjHSc5ymvOc6EynOmMZEAA7"

st.markdown(
    """
    <style>
    .bassi-header-wrap {
        display: flex;
        flex-direction: column;
        align-items: flex-start;
        justify-content: flex-start;
        gap: 0.3rem;
        margin-bottom: 0.5rem;
    }
    .bassi-header-wrap h1 {
        font-size: 2.25rem;
        margin: 0;
        white-space: nowrap;
        text-align: left;
    }
    .bassi-header-logo {
        height: auto;
        width: min(256px, 100%);
        max-width: 100%;
    }
    .bassi-logo-light { display: inline; }
    .bassi-logo-dark { display: none; }
    @media (prefers-color-scheme: dark) {
        .bassi-logo-light { display: none; }
        .bassi-logo-dark { display: inline; }
    }
    @media (max-width: 640px) {
        .bassi-header-wrap h1 {
            font-size: 1.8rem;
        }
        .bassi-header-logo {
            width: min(224px, 100%);
        }
    }
    </style>
    """
    + f'<div class="bassi-header-wrap">'
    + f'<img class="bassi-header-logo bassi-logo-light" src="data:image/gif;base64,{BASSI_LOGO_GIF_BLACK_BASE64}" />'
    + f'<img class="bassi-header-logo bassi-logo-dark" src="data:image/gif;base64,{BASSI_LOGO_GIF_WHITE_BASE64}" />'
    + '<h1>Bassi Bierball</h1></div>',
    unsafe_allow_html=True
)

if st.button("🔄 Aktualisieren", key="manual_refresh_btn"):
    st.rerun()

pending_friend_count = len(get_pending_friend_requests(user_id))
pending_invite_count = len(get_pending_invites(user_id)) + len(get_pending_group_invites(user_id))

all_matches_feed = get_all_matches_feed()
current_matches_total = len(all_matches_feed)
if "last_seen_matches_total" not in st.session_state:
    st.session_state.last_seen_matches_total = current_matches_total
new_matches_count = max(0, current_matches_total - st.session_state.last_seen_matches_total)

freunde_label = f"Freunde 🔴{pending_friend_count}" if pending_friend_count > 0 else "Freunde"
einladungen_label = f"Einladungen 🔴{pending_invite_count}" if pending_invite_count > 0 else "Einladungen"
spiele_label = f"Spiele 🔴{new_matches_count}" if new_matches_count > 0 else "Spiele"

is_admin_user = bool(st.session_state.user.get("is_admin", False))

tab_names = ["Profil", freunde_label, "Neues Spiel", einladungen_label, spiele_label, "Rangliste"]
if is_admin_user:
    tab_names.append("⚙️ Admin")

tabs = st.tabs(tab_names)

# --- TAB: Profil ---
with tabs[0]:
    user_row = get_user(user_id)
    _, username, current_display_name = user_row
    st.header(f"Mein Profil @{username}")

    with st.form("profile_form"):
        new_display_name = st.text_input("Anzeigename", value=current_display_name)
        profile_submitted = st.form_submit_button("Speichern")
        if profile_submitted:
            update_profile(user_id, new_display_name.strip())
            st.session_state.user["display_name"] = new_display_name.strip()
            st.success("Profil aktualisiert.")
            st.rerun()

    st.divider()
    st.subheader("Meine Statistiken")
    own_stats = get_stats_for_single_user(user_id)
    if own_stats.empty:
        st.info("Noch keine abgeschlossenen Spiele.")
    else:
        r = own_stats.iloc[0]
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Spiele", int(r["Spiele"]))
        c2.metric("Siegquote", f"{r['Siegquote']*100:.1f}%")
        c3.metric("Trefferquote", f"{r['Trefferquote']*100:.1f}%" if pd.notna(r["Trefferquote"]) else "–")
        c4.metric("Strafrunden gesamt", int(r["Strafrunden Gesamt"]))

# --- TAB: Freunde ---
with tabs[1]:
    st.header("Freunde verwalten")

    st.subheader("Neue Freunde finden")
    search_query = st.text_input("Nutzer suchen (Benutzername oder Anzeigename)")
    if search_query.strip():
        results = search_users(search_query.strip(), user_id)
        if results.empty:
            st.info("Keine Nutzer gefunden.")
        else:
            for _, r in results.iterrows():
                c1, c2 = st.columns([4, 1])
                with c1:
                    st.write(f"{r['display_name']} (@{r['username']})")
                with c2:
                    if st.button("Anfrage senden", key=f"friend_req_{r['id']}"):
                        if send_friend_request(user_id, int(r["id"])):
                            st.success("Freundschaftsanfrage gesendet.")
                        else:
                            st.warning("Anfrage existiert bereits oder ihr seid schon Freunde.")

    st.divider()
    st.subheader("Offene Freundschaftsanfragen")
    pending = get_pending_friend_requests(user_id)
    if pending.empty:
        st.caption("Keine offenen Anfragen.")
    else:
        for _, r in pending.iterrows():
            c1, c2, c3 = st.columns([3, 1, 1])
            with c1:
                st.write(f"{r['display_name']} (@{r['username']})")
            with c2:
                if st.button("Annehmen", key=f"accept_{r['id']}"):
                    respond_friend_request(int(r["id"]), True)
                    st.rerun()
            with c3:
                if st.button("Ablehnen", key=f"decline_{r['id']}"):
                    respond_friend_request(int(r["id"]), False)
                    st.rerun()

    st.divider()
    st.subheader("Von mir erteilte temporäre Zugriffe")
    cleanup_expired_temp_permissions()
    active_grants = get_active_temp_permissions_granted(user_id)
    if active_grants.empty:
        st.caption("Keine aktiven temporären Zugriffe erteilt.")
    else:
        for _, g in active_grants.iterrows():
            gc1, gc2 = st.columns([4, 1])
            with gc1:
                st.write(f"**{g['display_name']}** (@{g['username']}) – gültig bis {g['expires_at']}")
            with gc2:
                if st.button("Entziehen", key=f"revoke_{g['id']}"):
                    revoke_temp_permission(int(g["id"]))
                    st.rerun()

    st.divider()
    st.subheader("Meine Freunde")
    friends_df = get_friends(user_id)
    if friends_df.empty:
        st.caption("Noch keine Freunde hinzugefügt.")
    else:
        if "selected_friend_id" not in st.session_state:
            st.session_state.selected_friend_id = None

        for _, fr in friends_df.iterrows():
            c1, c2, c3 = st.columns([3, 1, 1])
            with c1:
                st.write(f"**{fr['display_name']}** (@{fr['username']})")
            with c2:
                if st.button("Profil ansehen", key=f"view_friend_{fr['id']}"):
                    st.session_state.selected_friend_id = int(fr["id"])
                    st.rerun()
            with c3:
                if st.button("⚡ Zugriff geben", key=f"grant_temp_{fr['id']}"):
                    st.session_state[f"show_grant_{fr['id']}"] = True

            if st.session_state.get(f"show_grant_{fr['id']}", False):
                gc1, gc2 = st.columns([2, 1])
                with gc1:
                    hours_choice = st.selectbox(
                        f"Temporären Zugriff für {fr['display_name']} gewähren",
                        [1, 6, 24],
                        format_func=lambda h: f"{h} Stunde{'n' if h != 1 else ''}",
                        key=f"hours_select_{fr['id']}"
                    )
                with gc2:
                    st.markdown("<div style='height:1.6rem;'></div>", unsafe_allow_html=True)
                    if st.button("Bestätigen", key=f"confirm_grant_{fr['id']}"):
                        grant_temp_play_permission(user_id, int(fr["id"]), hours_choice)
                        st.session_state[f"show_grant_{fr['id']}"] = False
                        st.success(f"{fr['display_name']} kann dich jetzt {hours_choice}h ohne Einladung zu Spielen hinzufügen.")
                        st.rerun()

        if st.session_state.selected_friend_id is not None:
            fid = st.session_state.selected_friend_id
            friend_row = get_user(fid)
            if friend_row:
                st.divider()
                st.subheader(f"Profil von {friend_row[2]}")
                if st.button("Schließen", key="close_friend_profile"):
                    st.session_state.selected_friend_id = None
                    st.rerun()

                fstats = get_stats_for_single_user(fid)
                if fstats.empty:
                    st.info("Dieser Nutzer hat noch keine abgeschlossenen Spiele.")
                else:
                    fr_row = fstats.iloc[0]
                    c1, c2, c3, c4 = st.columns(4)
                    c1.metric("Spiele", int(fr_row["Spiele"]))
                    c2.metric("Siegquote", f"{fr_row['Siegquote']*100:.1f}%")
                    c3.metric("Trefferquote", f"{fr_row['Trefferquote']*100:.1f}%" if pd.notna(fr_row["Trefferquote"]) else "–")
                    c4.metric("Strafrunden gesamt", int(fr_row["Strafrunden Gesamt"]))

                st.markdown("**Alle Spiele, an denen dieser Nutzer teilgenommen hat (zur Transparenz sichtbar für alle Freunde):**")
                friend_matches = get_full_match_list_for_user(fid)
                if friend_matches.empty:
                    st.caption("Keine abgeschlossenen Spiele.")
                else:
                    for _, fm in friend_matches.iterrows():
                        with st.expander(f"{fm['Datum']} – {fm['Regelwerk']} (Host: {fm['Host']})"):
                            pdf = get_match_participants_view(int(fm["id"]))
                            render_teams_vs(pdf)
                            st.markdown("<br>", unsafe_allow_html=True)
                            render_match_stats_table(pdf, fm["winner"])

    st.divider()
    st.subheader("Meine Gruppen")
    st.caption("Erstelle Gruppen mit deinen Freunden. Spiele, bei denen alle Mitspieler Mitglieder derselben Gruppe sind, werden automatisch in der Gruppenstatistik erfasst.")

    with st.expander("➕ Neue Gruppe erstellen"):
        new_group_name = st.text_input("Gruppenname", key="new_group_name_input")
        if st.button("Gruppe erstellen", key="create_group_btn"):
            if new_group_name.strip():
                new_gid = create_group(new_group_name.strip(), user_id)
                st.success(f"Gruppe '{new_group_name.strip()}' erstellt.")
                st.session_state["expand_group_" + str(new_gid)] = True
                st.rerun()
            else:
                st.warning("Bitte einen Gruppennamen eingeben.")

    my_groups_df = get_my_groups(user_id)
    if my_groups_df.empty:
        st.caption("Du bist noch in keiner Gruppe.")
    else:
        friends_for_invite_df = get_friends(user_id)
        for _, grp in my_groups_df.iterrows():
            gid = int(grp["id"])
            with st.expander(f"👥 {grp['name']}"):
                members_df = get_group_members(gid)
                st.markdown("**Mitglieder:** " + ", ".join(members_df["display_name"].tolist()))

                invitable_friends = friends_for_invite_df.loc[~friends_for_invite_df["id"].isin(members_df["id"])]
                if not invitable_friends.empty:
                    invite_name = st.selectbox("Freund einladen", invitable_friends["display_name"].tolist(), key=f"group_invite_select_{gid}")
                    if st.button("Einladen", key=f"group_invite_btn_{gid}"):
                        invite_uid = int(invitable_friends.loc[invitable_friends["display_name"] == invite_name, "id"].iloc[0])
                        if invite_to_group(gid, invite_uid, user_id):
                            st.success("Einladung gesendet.")
                            st.rerun()
                        else:
                            st.warning("Diese Person wurde bereits eingeladen oder ist bereits Mitglied.")
                else:
                    st.caption("Alle deine Freunde sind bereits in dieser Gruppe oder du hast keine weiteren Freunde zum Einladen.")

# --- TAB: Neues Spiel ---
with tabs[2]:
    st.header("Neues Spiel erstellen")
    friends_df = get_friends(user_id)
    rulesets_df = get_rulesets()

    if friends_df.empty:
        st.info("Du brauchst mindestens einen Freund, um ein Spiel zu starten. Füge zuerst Freunde im Tab 'Freunde' hinzu.")
    else:
        col1, col2, col3 = st.columns(3)
        with col1:
            match_date = st.date_input("Datum", value=date.today())
        with col2:
            match_ort = st.text_input("Ort", placeholder="z.B. Bassinplatz")
        with col3:
            ruleset_names = rulesets_df["name"].tolist() + ["Individuell (neu definieren)"]
            chosen_ruleset_name = st.selectbox("Regelwerk", ruleset_names)

        ruleset_id = None
        match_notizen = ""
        if chosen_ruleset_name == "Individuell (neu definieren)":
            st.subheader("Individuelles Regelwerk definieren")
            new_name = st.text_input("Name des neuen Regelwerks")
            f1 = st.checkbox("Tropfen erlaubt")
            f2 = st.checkbox("Wurf von oben")
            f3 = st.checkbox("3-Sekunden-Regel")
            if st.button("Regelwerk speichern"):
                if new_name.strip():
                    if save_custom_ruleset(new_name.strip(), [int(f1), int(f2), int(f3)]):
                        st.success("Regelwerk gespeichert. Bitte oben erneut auswählen.")
                        st.rerun()
                    else:
                        st.warning("Ein Regelwerk mit diesem Namen existiert bereits.")
        else:
            ruleset_id = int(rulesets_df.loc[rulesets_df["name"] == chosen_ruleset_name, "id"].iloc[0])
            rrow = rulesets_df.loc[rulesets_df["id"] == ruleset_id].iloc[0]
            st.caption(
                f"Tropfen erlaubt: {'Ja' if rrow.tropfen_erlaubt else 'Nein'}  \n"
                f"Von oben werfen Pflicht: {'Ja' if rrow.wurf_von_oben else 'Nein'}  \n"
                f"3-Sekunden-Regel: {'Ja' if rrow.drei_sekunden_regel else 'Nein'}"
            )

        match_notizen = st.text_area(
            "Individuelle Zusatzregeln (optional)",
            placeholder="z.B. Sonderregeln, Ausnahmen oder Absprachen für dieses Spiel..."
        )

        direct_add_df = get_players_addable_without_invite(user_id)
        direct_add_names = direct_add_df["display_name"].tolist() if not direct_add_df.empty else []
        if direct_add_names:
            st.caption(f"⚡ Direkt hinzufügbar (temporäre Berechtigung, keine Einladung nötig): {', '.join(direct_add_names)}")

        all_addable_names = friends_df["display_name"].tolist() + [n for n in direct_add_names if n not in friends_df["display_name"].tolist()]
        combined_lookup_df = pd.concat(
            [friends_df[["id", "display_name"]], direct_add_df[["id", "display_name"]]], ignore_index=True
        ).drop_duplicates(subset=["id"]) if not direct_add_df.empty else friends_df[["id", "display_name"]]

        st.divider()
        st.subheader("Team A")
        team_a_friends = st.multiselect("Spieler für Team A", all_addable_names, key="ta")
        host_in_team_a = st.checkbox("Ich spiele in Team A", value=True)

        st.subheader("Team B")
        remaining_friends = [n for n in all_addable_names if n not in team_a_friends]
        team_b_friends = st.multiselect("Spieler für Team B", remaining_friends, key="tb")

        preview_ids = [user_id]
        for name in team_a_friends:
            preview_ids.append(int(combined_lookup_df.loc[combined_lookup_df["display_name"] == name, "id"].iloc[0]))
        for name in team_b_friends:
            preview_ids.append(int(combined_lookup_df.loc[combined_lookup_df["display_name"] == name, "id"].iloc[0]))

        detected_groups_df = find_common_groups(preview_ids) if len(preview_ids) > 1 else pd.DataFrame(columns=["id", "name"])
        selected_group_id = None
        if not detected_groups_df.empty:
            st.success(f"Alle ausgewählten Spieler sind gemeinsam in {'einer Gruppe' if len(detected_groups_df) == 1 else 'mehreren Gruppen'}. Das Spiel wird automatisch in der Gruppenstatistik erfasst.")
            if len(detected_groups_df) == 1:
                selected_group_id = int(detected_groups_df.iloc[0]["id"])
                st.caption(f"Erkannte Gruppe: **{detected_groups_df.iloc[0]['name']}**")
            else:
                chosen_group_name = st.selectbox("Mehrere passende Gruppen erkannt – welche soll gezählt werden?", detected_groups_df["name"].tolist())
                selected_group_id = int(detected_groups_df.loc[detected_groups_df["name"] == chosen_group_name, "id"].iloc[0])

        if st.button("Spiel erstellen", type="primary"):
            if ruleset_id is None:
                st.error("Bitte ein gültiges Regelwerk auswählen.")
            elif not team_a_friends and not team_b_friends:
                st.error("Bitte mindestens einen Spieler hinzufügen.")
            else:
                invite_assignments = {}
                direct_add_ids = set()
                invite_assignments[user_id] = "A" if host_in_team_a else "B"
                for name in team_a_friends:
                    uid = int(combined_lookup_df.loc[combined_lookup_df["display_name"] == name, "id"].iloc[0])
                    invite_assignments[uid] = "A"
                    if name in direct_add_names:
                        direct_add_ids.add(uid)
                for name in team_b_friends:
                    uid = int(combined_lookup_df.loc[combined_lookup_df["display_name"] == name, "id"].iloc[0])
                    invite_assignments[uid] = "B"
                    if name in direct_add_names:
                        direct_add_ids.add(uid)
                create_match(match_date, ruleset_id, user_id, invite_assignments, match_ort.strip(), match_notizen.strip(), selected_group_id, direct_add_ids)
                st.success("Spiel erstellt! Direkt hinzugefügte Spieler nehmen ohne Einladung teil, andere erhalten eine Einladung.")
                st.rerun()

    st.divider()
    open_matches = get_open_matches_for_host(user_id)
    if open_matches.empty:
        st.subheader("Meine offenen Spiele")
        st.caption("Keine offenen Spiele.")
    else:
        for _, m in open_matches.iterrows():
            invite_status = get_match_invite_status(int(m["id"]))
            all_accepted = invite_status.empty or (invite_status["Status"] == "angenommen").all()
            status_label = "bereit" if all_accepted else "warte auf Zusagen"
            ort_display = f" – {m['ort']}" if m.get("ort") else ""
            with st.expander(f"Spiel {m['id']} – {m['match_date']}{ort_display} ({m['regelwerk']}) ({status_label})"):
                notizen_value_open = m.get("notizen")
                has_notizen_open = pd.notna(notizen_value_open) and str(notizen_value_open).strip() != ""
                if has_notizen_open:
                    st.info(f"**Individuelle Zusatzregeln:** {str(notizen_value_open).strip()}")
                else:
                    st.caption(f"Regelwerk: {m['regelwerk']}")
                st.dataframe(invite_status, use_container_width=True, hide_index=True)

                participants = get_match_participants_for_completion(int(m["id"]))
                st.markdown("**Ergebnis eintragen und Spiel abschließen:**")
                winner_choice = st.radio(
                    "Gewinner (Pflichtauswahl)",
                    ["– Bitte auswählen –", "Team A", "Team B"],
                    key=f"winner_{m['id']}",
                    horizontal=True
                )

                stats_inputs = {}
                for _, p in participants.iterrows():
                    c1, c2, c3 = st.columns(3)
                    with c1:
                        treffer = st.number_input(f"Treffer – {p['Spieler']} (Team {p['Team']})", min_value=0, step=1, key=f"tr_{m['id']}_{p['id']}")
                    with c2:
                        wuerfe = st.number_input(f"Würfe – {p['Spieler']}", min_value=0, step=1, key=f"wu_{m['id']}_{p['id']}")
                    with c3:
                        strafrunden = st.number_input(f"Strafrunden – {p['Spieler']}", min_value=0, step=1, key=f"sr_{m['id']}_{p['id']}")
                    stats_inputs[int(p["id"])] = {"treffer": treffer, "wuerfe": wuerfe, "platzierung": None, "strafrunden": strafrunden}

                if st.button("Spiel abschließen", key=f"finalize_{m['id']}"):
                    if winner_choice == "– Bitte auswählen –":
                        st.error("Bitte wähle zuerst das Gewinner-Team aus, bevor du das Spiel abschließt.")
                    else:
                        winner_code = "A" if winner_choice == "Team A" else "B"
                        finalize_match(int(m["id"]), winner_code, stats_inputs)
                        st.session_state["show_result_banner"] = True
                        st.success("Spiel abgeschlossen!")
                        st.rerun()

                if is_admin_user:
                    if st.button("Spiel löschen (Admin)", key=f"delete_open_{m['id']}"):
                        delete_match(int(m["id"]))
                        st.success("Spiel gelöscht.")
                        st.rerun()

# --- TAB: Einladungen ---
with tabs[3]:
    st.header("Meine Einladungen")

    st.subheader("Spiel-Einladungen")
    invites_df = get_pending_invites(user_id)
    if invites_df.empty:
        st.info("Keine offenen Spiel-Einladungen.")
    else:
        for _, inv in invites_df.iterrows():
            c1, c2, c3 = st.columns([3, 1, 1])
            with c1:
                st.write(f"{inv['host_name']} lädt dich zu einem Spiel ein ({inv['match_date']}, {inv['regelwerk']}, Team {inv['team']})")
            with c2:
                if st.button("Annehmen", key=f"inv_accept_{inv['invite_id']}"):
                    respond_invite(int(inv["invite_id"]), True)
                    st.rerun()
            with c3:
                if st.button("Ablehnen", key=f"inv_decline_{inv['invite_id']}"):
                    respond_invite(int(inv["invite_id"]), False)
                    st.rerun()

    st.divider()
    st.subheader("Gruppen-Einladungen")
    group_invites_df = get_pending_group_invites(user_id)
    if group_invites_df.empty:
        st.info("Keine offenen Gruppen-Einladungen.")
    else:
        for _, ginv in group_invites_df.iterrows():
            c1, c2, c3 = st.columns([3, 1, 1])
            with c1:
                st.write(f"{ginv['invited_by_name']} lädt dich in die Gruppe **{ginv['group_name']}** ein")
            with c2:
                if st.button("Annehmen", key=f"ginv_accept_{ginv['invite_id']}"):
                    respond_group_invite(int(ginv["invite_id"]), True)
                    st.rerun()
            with c3:
                if st.button("Ablehnen", key=f"ginv_decline_{ginv['invite_id']}"):
                    respond_group_invite(int(ginv["invite_id"]), False)
                    st.rerun()

# --- TAB: Spiele ---
with tabs[4]:
    st.header("Spiele")

    if "spiele_tab_last_seen_match" not in st.session_state:
        st.session_state["spiele_tab_last_seen_match"] = None
    if "spiele_tab_banner_dismissed" not in st.session_state:
        st.session_state["spiele_tab_banner_dismissed"] = False

    _latest_result = get_latest_completed_match_result_for_user(user_id)
    if _latest_result is not None:
        if st.session_state["spiele_tab_last_seen_match"] != _latest_result["match_id"]:
            st.session_state["spiele_tab_last_seen_match"] = _latest_result["match_id"]
            st.session_state["spiele_tab_banner_dismissed"] = False

        if not st.session_state["spiele_tab_banner_dismissed"]:
            if _latest_result["is_winner"]:
                banner_html = """
                <div id="bassi-result-banner" style="text-align:center; padding: 1.5rem 0;">
                    <h1 style="color:#22c55e; font-size:3rem; margin-bottom:0.5rem;">Gewinner</h1>
                    <img src="https://i.giphy.com/media/v1.Y2lkPTc5MGI3NjExN2d4M3YxY3p0M2JscDlqNWZ6OHJqNHVxZnB5MzB2ZXRsNWR0eHNidCZlcD12MV9naWZzX3NlYXJjaCZjdD1n/V6vYGxjArFFde/giphy.gif"
                         style="max-width: 320px; width: 90%; border-radius: 12px;" />
                </div>
                """
            else:
                banner_html = """
                <div id="bassi-result-banner" style="text-align:center; padding: 1.5rem 0;">
                    <h1 style="color:#ef4444; font-size:3rem; margin-bottom:0.5rem;">Loser</h1>
                    <img src="https://i.giphy.com/media/v1.Y2lkPTc5MGI3NjExM3JqOXoxcjd1YW1jNGxqcGg3OWhwZnF6NDA3YndqeHF2Nm43Z2VjdSZlcD12MV9naWZzX3NlYXJjaCZjdD1n/7fF2Cc85jFZSZRHbyQ/giphy.gif"
                         style="max-width: 320px; width: 90%; border-radius: 12px;" />
                </div>
                """
            st.markdown(banner_html, unsafe_allow_html=True)
            if st.button("Ausblenden", key="dismiss_result_banner"):
                st.session_state["spiele_tab_banner_dismissed"] = True
                st.rerun()
            st.divider()

    if all_matches_feed.empty:
        st.info("Noch keine Spiele vorhanden.")
    else:
        for _, m in all_matches_feed.iterrows():
            try:
                date_display = datetime.strptime(str(m["Datum"]), "%Y-%m-%d").strftime("%d/%m/%Y")
            except Exception:
                date_display = str(m["Datum"])
            ort_part = f" {m['Ort']}" if m.get("Ort") else ""
            title = f"{date_display}{ort_part} Bierball"

            with st.expander(title):
                pdf = get_match_participants_view(int(m["id"]))
                render_teams_vs(pdf)
                notizen_value = m.get("Notizen")
                has_notizen = pd.notna(notizen_value) and str(notizen_value).strip() != ""
                if has_notizen:
                    st.info(f"**Individuelle Zusatzregeln:** {str(notizen_value).strip()}")
                else:
                    st.caption(f"Regelwerk: {m['Regelwerk']}")
                if m["Status"] == "einladung_offen":
                    render_running_match_names(pdf)
                else:
                    st.markdown("<br>", unsafe_allow_html=True)
                    render_match_stats_table(pdf, m["Gewinner"])

                if is_admin_user:
                    if st.button("Dieses Spiel löschen (Admin)", key=f"del_hist_{m['id']}"):
                        delete_match(int(m["id"]))
                        st.success("Spiel gelöscht.")
                        st.rerun()

# --- TAB: Rangliste ---
with tabs[5]:
    st.header("Rangliste (Gesamt)")
    stats_df = get_player_stats_for_friends(user_id)
    if stats_df.empty:
        st.info("Noch keine Statistiken vorhanden.")
    else:
        ranked_df = stats_df.reset_index(drop=True)
        ranked_df.insert(0, "Rang", ranked_df.index + 1)
        display_ranked = ranked_df.drop(columns=["id"]).copy()
        display_ranked["Siegquote"] = (display_ranked["Siegquote"] * 100).round(1).astype(str) + " %"
        st.dataframe(display_ranked, use_container_width=True, hide_index=True)

        st.divider()
        st.header("Meine Gruppen")
        my_groups_rangliste_df = get_my_groups(user_id)
        group_stats_lookup = {}
        if my_groups_rangliste_df.empty:
            st.caption("Du bist noch in keiner Gruppe. Erstelle eine Gruppe im Tab 'Freunde'.")
        else:
            for _, grp in my_groups_rangliste_df.iterrows():
                gid = int(grp["id"])
                gname = grp["name"]
                group_stats_df = get_group_player_stats(gid)
                st.subheader(gname)
                if group_stats_df.empty:
                    st.caption("Noch keine abgeschlossenen Spiele in dieser Gruppe.")
                else:
                    group_ranked_df = group_stats_df.reset_index(drop=True)
                    group_ranked_df.insert(0, "Rang", group_ranked_df.index + 1)
                    group_stats_lookup[gid] = group_ranked_df
                    display_group_ranked = group_ranked_df.drop(columns=["id"]).copy()
                    display_group_ranked["Siegquote"] = (display_group_ranked["Siegquote"] * 100).round(1).astype(str) + " %"
                    st.dataframe(display_group_ranked, use_container_width=True, hide_index=True)

        st.divider()
        st.header("Individuelle Statistiken")
        selected_name = st.selectbox("Spieler auswählen", ranked_df["Spieler"].tolist(), key="rangliste_player_select")
        srow = ranked_df.loc[ranked_df["Spieler"] == selected_name].iloc[0]
        selected_uid = int(srow["id"])
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Spiele", int(srow["Spiele"]))
        c2.metric("Siegquote", f"{srow['Siegquote']*100:.1f}%")
        c3.metric("Trefferquote", f"{srow['Trefferquote']*100:.1f}%" if pd.notna(srow["Trefferquote"]) else "–")
        c4.metric("Strafrunden gesamt", int(srow["Strafrunden Gesamt"]))

        st.divider()
        st.subheader(f"Entwicklung über die Zeit – {selected_name}")
        st.caption("Verlauf der Siegquote und Trefferquote (kumuliert in %) über die gespielten Spiele (Gesamt, grün/blau) sowie je Gruppe (andere Farben), sofern der Spieler dort Spiele hat.")
        history_df = get_match_history_for_player(selected_uid)

        group_colors = ["#e67e22", "#8e44ad", "#c0392b", "#16a085", "#f1c40f", "#34495e"]
        group_histories = []
        if not my_groups_rangliste_df.empty:
            for idx, grp in my_groups_rangliste_df.iterrows():
                gid = int(grp["id"])
                if gid in group_stats_lookup and selected_uid in group_stats_lookup[gid]["id"].values:
                    ghist = get_group_match_history_for_player(gid, selected_uid)
                    if not ghist.empty and len(ghist) >= 2:
                        group_histories.append((grp["name"], ghist, group_colors[idx % len(group_colors)]))

        if history_df.empty or len(history_df) < 2:
            st.caption("Noch nicht genug abgeschlossene Spiele für eine Zeitverlaufs-Grafik (mindestens 2 nötig).")
        else:
            fig_sieg = go.Figure()
            fig_sieg.add_trace(go.Scatter(
                x=history_df["Spielnummer"], y=history_df["Siegquote_Verlauf"],
                mode="lines+markers", line=dict(color="#2e8b57"), name="Siegquote Gesamt (%)"
            ))
            for gname, ghist, gcolor in group_histories:
                fig_sieg.add_trace(go.Scatter(
                    x=ghist["Spielnummer"], y=ghist["Siegquote_Verlauf"],
                    mode="lines+markers", line=dict(color=gcolor), name=f"Siegquote {gname} (%)"
                ))
            fig_sieg.update_layout(title="Siegquote im Verlauf", xaxis_title="Spielnummer", yaxis_title="Siegquote (%)", yaxis_range=[0, 100])
            st.plotly_chart(fig_sieg, use_container_width=True)

            fig_treffer = go.Figure()
            fig_treffer.add_trace(go.Scatter(
                x=history_df["Spielnummer"], y=history_df["Trefferquote_Verlauf"],
                mode="lines+markers", line=dict(color="#2980b9"), name="Trefferquote Gesamt (%)"
            ))
            for gname, ghist, gcolor in group_histories:
                fig_treffer.add_trace(go.Scatter(
                    x=ghist["Spielnummer"], y=ghist["Trefferquote_Verlauf"],
                    mode="lines+markers", line=dict(color=gcolor, dash="dot"), name=f"Trefferquote {gname} (%)"
                ))
            fig_treffer.update_layout(title="Trefferquote im Verlauf", xaxis_title="Spielnummer", yaxis_title="Trefferquote (%)", yaxis_range=[0, 100])
            st.plotly_chart(fig_treffer, use_container_width=True)

# --- TAB: Admin ---
if is_admin_user:
    with tabs[6]:
        st.header("⚙️ Admin-Bereich")
        st.caption("Dieser Bereich ist nur für Administratoren sichtbar.")

        total_users = get_total_user_count()
        st.metric("Registrierte Nutzer insgesamt", total_users)

        st.divider()
        st.subheader("Alle registrierten Nutzer")
        users_overview = get_all_users_overview()
        st.dataframe(users_overview, use_container_width=True, hide_index=True)

        st.divider()
        st.subheader("Passwort-Reset freischalten")
        st.caption("Schaltet für einen Nutzer einmalig frei, dass er beim nächsten Login-Versuch (nach einer falschen Passworteingabe) sein Passwort selbst neu setzen kann. Die Freischaltung erlischt automatisch, sobald das neue Passwort gesetzt wurde.")
        users_overview_reset = get_all_users_overview()
        for _, u_row in users_overview_reset.iterrows():
            target_uid = int(u_row["id"])
            c1, c2 = st.columns([5, 1])
            with c1:
                reset_status = "🟢 Freigeschaltet" if u_row.get("password_reset_allowed") else "⚪ Nicht freigeschaltet"
                st.write(f"**{u_row['display_name']}** (@{u_row['username']}) – {reset_status}")
            with c2:
                if u_row.get("password_reset_allowed"):
                    if st.button("Zurücknehmen", key=f"revoke_reset_{target_uid}"):
                        set_password_reset_allowed(target_uid, False)
                        st.success(f"Freischaltung für @{u_row['username']} zurückgenommen.")
                        st.rerun()
                else:
                    if st.button("Freischalten", key=f"grant_reset_{target_uid}"):
                        set_password_reset_allowed(target_uid, True)
                        st.success(f"Passwort-Reset für @{u_row['username']} freigeschaltet.")
                        st.rerun()

        st.divider()
        st.subheader("Account löschen")
        st.caption("Löscht den Account und alle zugehörigen Daten (Freundschaften, Einladungen, Spielteilnahmen sowie von diesem Nutzer gehostete Spiele) unwiderruflich.")
        for _, u_row in users_overview.iterrows():
            target_uid = int(u_row["id"])
            if target_uid == user_id:
                continue
            c1, c2 = st.columns([5, 1])
            with c1:
                admin_tag = " (Admin)" if u_row["is_admin"] else ""
                st.write(f"**{u_row['display_name']}** (@{u_row['username']}){admin_tag}")
            with c2:
                confirm_key = f"confirm_del_user_{target_uid}"
                if st.session_state.get(confirm_key, False):
                    if st.button("Bestätigen", key=f"confirm_btn_{target_uid}", type="primary"):
                        delete_user_account(target_uid)
                        st.session_state[confirm_key] = False
                        st.success(f"Account @{u_row['username']} wurde gelöscht.")
                        st.rerun()
                else:
                    if st.button("Löschen", key=f"del_user_{target_uid}"):
                        st.session_state[confirm_key] = True
                        st.rerun()

        st.divider()
        st.subheader("Account löschen")
        st.caption("Löscht den Nutzer-Account inklusive aller zugehörigen Spiele, Einladungen und Freundschaften unwiderruflich.")

        deletable_users = users_overview[users_overview["username"] != ADMIN_USERNAME]
        if deletable_users.empty:
            st.caption("Keine löschbaren Accounts vorhanden.")
        else:
            options = deletable_users.apply(
                lambda r: f"{r['display_name']} (@{r['username']}, ID {r['id']})", axis=1
            ).tolist()
            selected_option = st.selectbox("Nutzer auswählen", options, key="admin_delete_user_select")
            selected_idx = options.index(selected_option)
            selected_row = deletable_users.iloc[selected_idx]

            confirm_delete = st.checkbox(
                f"Ich bestätige, dass der Account '{selected_row['display_name']}' unwiderruflich gelöscht werden soll.",
                key="admin_delete_confirm"
            )
            if st.button("Account endgültig löschen", key="admin_delete_user_btn", type="primary", disabled=not confirm_delete):
                delete_user_account(int(selected_row["id"]))
                st.success(f"Account '{selected_row['display_name']}' wurde gelöscht.")
                st.rerun()

        st.divider()
        st.subheader("Alle Spiele (inkl. Löschen)")
        admin_matches = get_all_matches_for_admin()
        if admin_matches.empty:
            st.info("Keine Spiele vorhanden.")
        else:
            for _, am in admin_matches.iterrows():
                c1, c2 = st.columns([5, 1])
                with c1:
                    st.write(f"**Spiel {am['id']}** – {am['Datum']} ({am['Regelwerk']}), Host: {am['Host']}, Status: {am['Status']}")
                with c2:
                    if st.button("Löschen", key=f"admin_del_{am['id']}"):
                        delete_match(int(am["id"]))
                        st.success(f"Spiel {am['id']} gelöscht.")
                        st.rerun()

        st.divider()
        st.subheader("Alle Gruppen (inkl. Mitglieder und Löschen)")
        st.caption("Löscht eine Gruppe unwiderruflich inklusive aller Mitgliedschaften und Einladungen. Bereits gespielte Spiele bleiben erhalten, verlieren aber die Gruppenzuordnung.")
        admin_groups = get_all_groups_for_admin()
        if admin_groups.empty:
            st.info("Keine Gruppen vorhanden.")
        else:
            for _, ag in admin_groups.iterrows():
                gid = int(ag["id"])
                c1, c2 = st.columns([5, 1])
                with c1:
                    st.write(f"**{ag['Gruppe']}** (Ersteller: {ag['Ersteller']}, Spiele: {int(ag['Spiele'])})")
                    members_admin_df = get_group_members(gid)
                    st.caption("Mitglieder: " + (", ".join(members_admin_df["display_name"].tolist()) if not members_admin_df.empty else "–"))
                with c2:
                    confirm_group_key = f"confirm_del_group_{gid}"
                    if st.session_state.get(confirm_group_key, False):
                        if st.button("Bestätigen", key=f"confirm_group_btn_{gid}", type="primary"):
                            delete_group(gid)
                            st.session_state[confirm_group_key] = False
                            st.success(f"Gruppe '{ag['Gruppe']}' wurde gelöscht.")
                            st.rerun()
                    else:
                        if st.button("Löschen", key=f"admin_del_group_{gid}"):
                            st.session_state[confirm_group_key] = True
                            st.rerun()

st.session_state.last_seen_matches_total = current_matches_total
