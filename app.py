import streamlit as st
import psycopg2
import psycopg2.extras
import pandas as pd
import hashlib
import secrets
import os
from datetime import date, datetime
import plotly.graph_objects as go
from streamlit_autorefresh import st_autorefresh

DATABASE_URL = os.environ.get("DATABASE_URL", "")

SECURITY_QUESTIONS = {
    1: "Wie hieß dein erstes Haustier?",
    2: "In welcher Stadt bist du geboren?",
    3: "Wie hieß deine erste Schule?",
    4: "Was ist der Vorname deiner Mutter?",
    5: "Wie hieß dein Kindheits-Idol oder bester Freund?"
}

def get_conn():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL ist nicht gesetzt. Bitte als Umgebungsvariable in Render hinterlegen.")
    return psycopg2.connect(DATABASE_URL, sslmode="require")

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
            sq1_id INTEGER,
            sq1_salt TEXT,
            sq1_hash TEXT,
            sq2_id INTEGER,
            sq2_salt TEXT,
            sq2_hash TEXT
        )
    """)
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
            ort TEXT
        )
    """)
    c.execute("ALTER TABLE matches ADD COLUMN IF NOT EXISTS created_at TEXT")
    c.execute("ALTER TABLE matches ADD COLUMN IF NOT EXISTS ort TEXT")

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
            platzierung INTEGER
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS remember_tokens (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            token TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL
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

def hash_text(text, salt):
    return hashlib.sha256((salt + text.strip().lower()).encode()).hexdigest()

def hash_password(password, salt):
    return hashlib.sha256((salt + password).encode()).hexdigest()

def create_user(username, password, display_name, sq1_id, sq1_answer, sq2_id, sq2_answer):
    conn = get_conn()
    salt = secrets.token_hex(8)
    ph = hash_password(password, salt)
    sq1_salt = secrets.token_hex(8)
    sq2_salt = secrets.token_hex(8)
    sq1_hash = hash_text(sq1_answer, sq1_salt)
    sq2_hash = hash_text(sq2_answer, sq2_salt)
    ok = True
    try:
        c = conn.cursor()
        c.execute(
            """INSERT INTO users
               (username, password_hash, salt, display_name, sq1_id, sq1_salt, sq1_hash, sq2_id, sq2_salt, sq2_hash)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (username, ph, salt, display_name, sq1_id, sq1_salt, sq1_hash, sq2_id, sq2_salt, sq2_hash)
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
            "SELECT id, password_hash, salt, display_name FROM users WHERE username = %s",
            (username,)
        )
        row = c.fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    user_id, ph, salt, display_name = row
    if hash_password(password, salt) == ph:
        return {"id": user_id, "display_name": display_name, "username": username}
    return None

def get_security_questions_for_user(username):
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute("SELECT id, sq1_id, sq2_id FROM users WHERE username = %s", (username,))
        row = c.fetchone()
    finally:
        conn.close()
    return row

def verify_security_answers(username, answer1, answer2):
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute(
            "SELECT id, sq1_salt, sq1_hash, sq2_salt, sq2_hash FROM users WHERE username = %s",
            (username,)
        )
        row = c.fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    user_id, sq1_salt, sq1_hash, sq2_salt, sq2_hash = row
    if sq1_salt is None or sq2_salt is None:
        return None
    if hash_text(answer1, sq1_salt) == sq1_hash and hash_text(answer2, sq2_salt) == sq2_hash:
        return user_id
    return None

def reset_password(user_id, new_password):
    conn = get_conn()
    try:
        c = conn.cursor()
        new_salt = secrets.token_hex(8)
        new_hash = hash_password(new_password, new_salt)
        c.execute("UPDATE users SET password_hash = %s, salt = %s WHERE id = %s", (new_hash, new_salt, user_id))
        conn.commit()
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
            "SELECT u.id, u.username, u.display_name FROM remember_tokens rt JOIN users u ON rt.user_id = u.id WHERE rt.token = %s",
            (token,)
        )
        row = c.fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    return {"id": row[0], "username": row[1], "display_name": row[2]}

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

def create_match(match_date, ruleset_id, host_id, invite_assignments, ort=""):
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute(
            "INSERT INTO matches (match_date, ruleset_id, host_id, winner, status, created_at, ort) VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id",
            (str(match_date), ruleset_id, host_id, None, "einladung_offen", str(datetime.now()), ort)
        )
        match_id = c.fetchone()[0]
        c.execute(
            "INSERT INTO match_participants (match_id, user_id, team, treffer, wuerfe, platzierung) VALUES (%s,%s,%s,%s,%s,%s)",
            (match_id, host_id, invite_assignments[host_id], None, None, None)
        )
        for uid, team in invite_assignments.items():
            if uid == host_id:
                continue
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
                    "INSERT INTO match_participants (match_id, user_id, team, treffer, wuerfe, platzierung) VALUES (%s,%s,%s,%s,%s,%s)",
                    (match_id, user_id, team, None, None, None)
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
            SELECT m.id, m.match_date, r.name AS regelwerk, m.status, m.ort AS ort
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
            SELECT u.display_name AS Spieler, mi.team AS Team, mi.status AS Status
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
            SELECT mp.id, u.id AS user_id, u.display_name AS Spieler, mp.team AS Team
            FROM match_participants mp JOIN users u ON mp.user_id = u.id
            WHERE mp.match_id = %s
            ORDER BY mp.team, u.display_name
        """, conn, params=(match_id,))
    finally:
        conn.close()
    return df

def finalize_match(match_id, winner, stats_by_participant_id):
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute("UPDATE matches SET winner = %s, status = 'abgeschlossen' WHERE id = %s", (winner, match_id))
        for pid, stats in stats_by_participant_id.items():
            c.execute(
                "UPDATE match_participants SET treffer = %s, wuerfe = %s, platzierung = %s WHERE id = %s",
                (stats["treffer"], stats["wuerfe"], stats["platzierung"], pid)
            )
        conn.commit()
    finally:
        conn.close()

def get_all_matches_feed():
    conn = get_conn()
    try:
        df = pd.read_sql("""
            SELECT m.id, m.match_date AS "Datum", r.name AS "Regelwerk", m.winner AS "Gewinner",
                   u.display_name AS "Host", m.host_id AS "HostId", m.status AS "Status", m.ort AS "Ort"
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
            SELECT mp.team AS "Team", u.display_name AS "Spieler", mp.treffer AS "Treffer", mp.wuerfe AS "Wuerfe"
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
                   ROUND(SUM(mp.treffer) * 1.0 / NULLIF(SUM(mp.wuerfe), 0), 3) AS "Trefferquote"
            FROM match_participants mp
            JOIN matches m ON mp.match_id = m.id AND m.status = 'abgeschlossen'
            JOIN users u ON mp.user_id = u.id
            WHERE u.id = ANY(%s)
            GROUP BY u.id, u.display_name
            ORDER BY "Siege" DESC, "Trefferquote" DESC
        """, conn, params=(friend_ids,))
    finally:
        conn.close()
    if not df.empty:
        df["Siegquote"] = (df["Siege"] / df["Spiele"]).round(3)
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
                   ROUND(SUM(mp.treffer) * 1.0 / NULLIF(SUM(mp.wuerfe), 0), 3) AS "Trefferquote"
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
    display_df = display_df[["Spieler", "Team", "Ergebnis", "Treffer", "Wuerfe", "Trefferquote"]]
    st.dataframe(display_df, use_container_width=True, hide_index=True)

try:
    init_db()
except Exception as e:
    st.error(f"Fehler bei der Datenbank-Initialisierung: {e}")
    st.stop()

st.set_page_config(page_title="Bierball League", layout="wide")

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
    st.title("Bierball League – Login")
    login_tab, register_tab, reset_tab = st.tabs(["Anmelden", "Registrieren", "Passwort vergessen?"])

    with login_tab:
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
                        st.error("Benutzername oder Passwort falsch.")

    with register_tab:
        st.caption("Wähle zwei unterschiedliche Sicherheitsfragen – damit kannst du später dein Passwort zurücksetzen, falls du es vergisst.")
        with st.form("register_form"):
            new_u = st.text_input("Benutzername wählen")
            new_dn = st.text_input("Anzeigename")
            new_p = st.text_input("Passwort", type="password")
            new_p2 = st.text_input("Passwort wiederholen", type="password")
            q_options = list(SECURITY_QUESTIONS.items())
            sq1_choice = st.selectbox("Sicherheitsfrage 1", q_options, format_func=lambda x: x[1], key="sq1_choice")
            sq1_answer = st.text_input("Antwort 1")
            remaining_q = [q for q in q_options if q[0] != sq1_choice[0]]
            sq2_choice = st.selectbox("Sicherheitsfrage 2", remaining_q, format_func=lambda x: x[1], key="sq2_choice")
            sq2_answer = st.text_input("Antwort 2")
            reg_submitted = st.form_submit_button("Account erstellen")
            if reg_submitted:
                if not new_u.strip() or not new_p or not new_dn.strip():
                    st.warning("Bitte Benutzername, Anzeigename und Passwort ausfüllen.")
                elif new_p != new_p2:
                    st.warning("Die beiden Passwörter stimmen nicht überein.")
                elif len(new_p) < 4:
                    st.warning("Das Passwort sollte mindestens 4 Zeichen haben.")
                elif not sq1_answer.strip() or not sq2_answer.strip():
                    st.warning("Bitte beide Sicherheitsfragen beantworten.")
                else:
                    try:
                        success = create_user(
                            new_u.strip(), new_p, new_dn.strip(),
                            sq1_choice[0], sq1_answer, sq2_choice[0], sq2_answer
                        )
                    except Exception as e:
                        st.error(f"Technischer Fehler bei der Registrierung: {e}")
                        success = False
                    if success:
                        st.success("Account erstellt! Du kannst dich jetzt anmelden.")
                    else:
                        st.warning("Dieser Benutzername ist bereits vergeben.")

    with reset_tab:
        st.subheader("Passwort zurücksetzen")
        reset_username = st.text_input("Dein Benutzername", key="reset_username")
        if reset_username.strip():
            try:
                q_row = get_security_questions_for_user(reset_username.strip())
            except Exception:
                q_row = None
            if q_row is None:
                st.info("Benutzername nicht gefunden.")
            elif q_row[1] is None or q_row[2] is None:
                st.warning("Für diesen Account wurden noch keine Sicherheitsfragen hinterlegt.")
            else:
                _, sq1_id, sq2_id = q_row
                with st.form("reset_form"):
                    st.write(f"**{SECURITY_QUESTIONS[sq1_id]}**")
                    a1 = st.text_input("Antwort 1", key="reset_a1")
                    st.write(f"**{SECURITY_QUESTIONS[sq2_id]}**")
                    a2 = st.text_input("Antwort 2", key="reset_a2")
                    new_pw = st.text_input("Neues Passwort", type="password", key="reset_new_pw")
                    new_pw2 = st.text_input("Neues Passwort wiederholen", type="password", key="reset_new_pw2")
                    reset_submitted = st.form_submit_button("Passwort zurücksetzen")
                    if reset_submitted:
                        if not new_pw or new_pw != new_pw2:
                            st.warning("Die neuen Passwörter stimmen nicht überein oder sind leer.")
                        elif len(new_pw) < 4:
                            st.warning("Das neue Passwort sollte mindestens 4 Zeichen haben.")
                        else:
                            verified_uid = verify_security_answers(reset_username.strip(), a1, a2)
                            if verified_uid:
                                reset_password(verified_uid, new_pw)
                                st.success("Passwort wurde zurückgesetzt. Du kannst dich jetzt mit dem neuen Passwort anmelden.")
                            else:
                                st.error("Eine oder beide Antworten sind falsch.")
    st.stop()

user_id = st.session_state.user["id"]
display_name = st.session_state.user["display_name"]

st_autorefresh(interval=15000, key="live_refresh")

st.sidebar.write(f"Angemeldet als **{display_name}**")
if st.sidebar.button("Abmelden"):
    if "remember_token" in st.query_params:
        try:
            delete_remember_token(st.query_params["remember_token"])
        except Exception:
            pass
        del st.query_params["remember_token"]
    st.session_state.user = None
    st.rerun()

st.title("Bierball League")

pending_friend_count = len(get_pending_friend_requests(user_id))
pending_invite_count = len(get_pending_invites(user_id))

all_matches_feed = get_all_matches_feed()
current_matches_total = len(all_matches_feed)
if "last_seen_matches_total" not in st.session_state:
    st.session_state.last_seen_matches_total = current_matches_total
new_matches_count = max(0, current_matches_total - st.session_state.last_seen_matches_total)

freunde_label = f"Freunde 🔴{pending_friend_count}" if pending_friend_count > 0 else "Freunde"
einladungen_label = f"Einladungen 🔴{pending_invite_count}" if pending_invite_count > 0 else "Einladungen"
spiele_label = f"Spiele 🔴{new_matches_count}" if new_matches_count > 0 else "Spiele"

tabs = st.tabs(["Profil", freunde_label, "Neues Spiel", einladungen_label, spiele_label, "Rangliste"])

# --- TAB: Profil ---
with tabs[0]:
    st.header("Mein Profil")
    user_row = get_user(user_id)
    _, username, current_display_name = user_row

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
        c1, c2, c3 = st.columns(3)
        c1.metric("Spiele", int(r["Spiele"]))
        c2.metric("Siegquote", f"{r['Siegquote']*100:.1f}%")
        c3.metric("Trefferquote", f"{r['Trefferquote']*100:.1f}%" if pd.notna(r["Trefferquote"]) else "–")

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
    st.subheader("Meine Freunde")
    friends_df = get_friends(user_id)
    if friends_df.empty:
        st.caption("Noch keine Freunde hinzugefügt.")
    else:
        if "selected_friend_id" not in st.session_state:
            st.session_state.selected_friend_id = None

        for _, fr in friends_df.iterrows():
            c1, c2 = st.columns([3, 1])
            with c1:
                st.write(f"**{fr['display_name']}** (@{fr['username']})")
            with c2:
                if st.button("Profil ansehen", key=f"view_friend_{fr['id']}"):
                    st.session_state.selected_friend_id = int(fr["id"])
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
                    c1, c2, c3 = st.columns(3)
                    c1.metric("Spiele", int(fr_row["Spiele"]))
                    c2.metric("Siegquote", f"{fr_row['Siegquote']*100:.1f}%")
                    c3.metric("Trefferquote", f"{fr_row['Trefferquote']*100:.1f}%" if pd.notna(fr_row["Trefferquote"]) else "–")

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

        st.divider()
        st.subheader("Team A")
        team_a_friends = st.multiselect("Freunde für Team A", friends_df["display_name"].tolist(), key="ta")
        host_in_team_a = st.checkbox("Ich spiele in Team A", value=True)

        st.subheader("Team B")
        remaining_friends = [n for n in friends_df["display_name"].tolist() if n not in team_a_friends]
        team_b_friends = st.multiselect("Freunde für Team B", remaining_friends, key="tb")

        if st.button("Einladungen senden", type="primary"):
            if ruleset_id is None:
                st.error("Bitte ein gültiges Regelwerk auswählen.")
            elif not team_a_friends and not team_b_friends:
                st.error("Bitte mindestens einen Freund einladen.")
            else:
                invite_assignments = {}
                invite_assignments[user_id] = "A" if host_in_team_a else "B"
                for name in team_a_friends:
                    uid = int(friends_df.loc[friends_df["display_name"] == name, "id"].iloc[0])
                    invite_assignments[uid] = "A"
                for name in team_b_friends:
                    uid = int(friends_df.loc[friends_df["display_name"] == name, "id"].iloc[0])
                    invite_assignments[uid] = "B"
                create_match(match_date, ruleset_id, user_id, invite_assignments, match_ort.strip())
                st.success("Spiel erstellt und Einladungen versendet!")
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
                st.dataframe(invite_status, use_container_width=True, hide_index=True)

                participants = get_match_participants_for_completion(int(m["id"]))
                st.markdown("**Ergebnis eintragen und Spiel abschließen:**")
                winner_choice = st.radio("Gewinner", ["Team A", "Team B"], key=f"winner_{m['id']}", horizontal=True)
                winner_code = "A" if winner_choice == "Team A" else "B"

                stats_inputs = {}
                for _, p in participants.iterrows():
                    c1, c2 = st.columns(2)
                    with c1:
                        treffer = st.number_input(f"Treffer – {p['Spieler']} (Team {p['Team']})", min_value=0, step=1, key=f"tr_{m['id']}_{p['id']}")
                    with c2:
                        wuerfe = st.number_input(f"Würfe – {p['Spieler']}", min_value=0, step=1, key=f"wu_{m['id']}_{p['id']}")
                    stats_inputs[int(p["id"])] = {"treffer": treffer, "wuerfe": wuerfe, "platzierung": None}

                if st.button("Spiel abschließen", key=f"finalize_{m['id']}"):
                    finalize_match(int(m["id"]), winner_code, stats_inputs)
                    st.success("Spiel abgeschlossen!")
                    st.rerun()

                if st.button("Spiel löschen", key=f"delete_open_{m['id']}"):
                    delete_match(int(m["id"]))
                    st.success("Spiel gelöscht.")
                    st.rerun()

# --- TAB: Einladungen ---
with tabs[3]:
    st.header("Meine Einladungen")
    invites_df = get_pending_invites(user_id)
    if invites_df.empty:
        st.info("Keine offenen Einladungen.")
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

# --- TAB: Spiele ---
with tabs[4]:
    st.header("Spiele")
    if all_matches_feed.empty:
        st.info("Noch keine Spiele vorhanden.")
    else:
        for _, m in all_matches_feed.iterrows():
            try:
                date_display = datetime.strptime(str(m["Datum"]), "%Y-%m-%d").strftime("%d/%m/%Y")
            except Exception:
                date_display = str(m["Datum"])
            ort_part = f" {m['Ort']}" if m.get("Ort") else ""
            title = f"{date_display}{ort_part} Bierball League"

            with st.expander(title):
                pdf = get_match_participants_view(int(m["id"]))
                render_teams_vs(pdf)
                if m["Status"] == "einladung_offen":
                    render_running_match_names(pdf)
                else:
                    st.markdown("<br>", unsafe_allow_html=True)
                    render_match_stats_table(pdf, m["Gewinner"])

                is_host = (int(m["HostId"]) == user_id)
                if is_host:
                    if st.button("Dieses Spiel löschen", key=f"del_hist_{m['id']}"):
                        delete_match(int(m["id"]))
                        st.success("Spiel gelöscht.")
                        st.rerun()

# --- TAB: Rangliste ---
with tabs[5]:
    st.header("Rangliste (du und deine Freunde)")
    stats_df = get_player_stats_for_friends(user_id)
    if stats_df.empty:
        st.info("Noch keine Statistiken vorhanden.")
    else:
        ranked_df = stats_df.sort_values(by="Siegquote", ascending=False).reset_index(drop=True)
        ranked_df.insert(0, "Rang", ranked_df.index + 1)
        display_ranked = ranked_df.drop(columns=["id"]).copy()
        display_ranked["Siegquote"] = (display_ranked["Siegquote"] * 100).round(1).astype(str) + " %"
        st.dataframe(display_ranked, use_container_width=True, hide_index=True)

        st.divider()
        st.subheader("Individuelle Statistiken ansehen")
        selected_name = st.selectbox("Spieler auswählen", ranked_df["Spieler"].tolist(), key="rangliste_player_select")
        srow = ranked_df.loc[ranked_df["Spieler"] == selected_name].iloc[0]
        selected_uid = int(srow["id"])
        c1, c2, c3 = st.columns(3)
        c1.metric("Spiele", int(srow["Spiele"]))
        c2.metric("Siegquote", f"{srow['Siegquote']*100:.1f}%")
        c3.metric("Trefferquote", f"{srow['Trefferquote']*100:.1f}%" if pd.notna(srow["Trefferquote"]) else "–")

        st.divider()
        st.subheader(f"Entwicklung über die Zeit – {selected_name}")
        st.caption("Verlauf der Siegquote und Trefferquote (kumuliert in %) über die gespielten Spiele.")
        history_df = get_match_history_for_player(selected_uid)
        if history_df.empty or len(history_df) < 2:
            st.caption("Noch nicht genug abgeschlossene Spiele für eine Zeitverlaufs-Grafik (mindestens 2 nötig).")
        else:
            fig_sieg = go.Figure()
            fig_sieg.add_trace(go.Scatter(
                x=history_df["Spielnummer"], y=history_df["Siegquote_Verlauf"],
                mode="lines+markers", line=dict(color="#2e8b57"), name="Siegquote (%)"
            ))
            fig_sieg.update_layout(title="Siegquote im Verlauf", xaxis_title="Spielnummer", yaxis_title="Siegquote (%)", yaxis_range=[0, 100])
            st.plotly_chart(fig_sieg, use_container_width=True)

            fig_treffer = go.Figure()
            fig_treffer.add_trace(go.Scatter(
                x=history_df["Spielnummer"], y=history_df["Trefferquote_Verlauf"],
                mode="lines+markers", line=dict(color="#2980b9"), name="Trefferquote (%)"
            ))
            fig_treffer.update_layout(title="Trefferquote im Verlauf", xaxis_title="Spielnummer", yaxis_title="Trefferquote (%)", yaxis_range=[0, 100])
            st.plotly_chart(fig_treffer, use_container_width=True)

st.session_state.last_seen_matches_total = current_matches_total
