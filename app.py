
import streamlit as st
import sqlite3
import pandas as pd
import hashlib
import secrets
from datetime import date
from io import BytesIO

DB_PATH = "bierball_v2.db"

def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    conn = get_conn()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            display_name TEXT NOT NULL,
            profile_pic BLOB
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS friendships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            friend_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            requested_by INTEGER NOT NULL,
            UNIQUE(user_id, friend_id)
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS rulesets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            tropfen_erlaubt INTEGER NOT NULL,
            wurf_von_oben INTEGER NOT NULL,
            drei_sekunden_regel INTEGER NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            match_date TEXT NOT NULL,
            ruleset_id INTEGER NOT NULL,
            host_id INTEGER NOT NULL,
            winner TEXT,
            status TEXT NOT NULL,
            FOREIGN KEY (ruleset_id) REFERENCES rulesets(id),
            FOREIGN KEY (host_id) REFERENCES users(id)
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS match_invites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            match_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            team TEXT NOT NULL,
            status TEXT NOT NULL,
            FOREIGN KEY (match_id) REFERENCES matches(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS match_participants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            match_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            team TEXT NOT NULL,
            treffer INTEGER,
            wuerfe INTEGER,
            platzierung INTEGER,
            FOREIGN KEY (match_id) REFERENCES matches(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()

    c.execute("SELECT COUNT(*) FROM rulesets")
    if c.fetchone()[0] == 0:
        c.executemany(
            "INSERT INTO rulesets (name, tropfen_erlaubt, wurf_von_oben, drei_sekunden_regel) VALUES (?,?,?,?)",
            [("Bassi-Regeln", 0, 0, 1), ("Studentenregeln", 1, 1, 0)]
        )
        conn.commit()
    conn.close()

def hash_password(password, salt):
    return hashlib.sha256((salt + password).encode()).hexdigest()

def create_user(username, password, display_name):
    conn = get_conn()
    salt = secrets.token_hex(8)
    ph = hash_password(password, salt)
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, salt, display_name) VALUES (?,?,?,?)",
            (username, ph, salt, display_name)
        )
        conn.commit()
        ok = True
    except sqlite3.IntegrityError:
        ok = False
    conn.close()
    return ok

def verify_login(username, password):
    conn = get_conn()
    row = conn.execute("SELECT id, password_hash, salt, display_name FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if row is None:
        return None
    user_id, ph, salt, display_name = row
    if hash_password(password, salt) == ph:
        return {"id": user_id, "display_name": display_name, "username": username}
    return None

def get_user(user_id):
    conn = get_conn()
    row = conn.execute("SELECT id, username, display_name, profile_pic FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return row

def update_profile(user_id, display_name, profile_pic_bytes):
    conn = get_conn()
    if profile_pic_bytes is not None:
        conn.execute("UPDATE users SET display_name = ?, profile_pic = ? WHERE id = ?", (display_name, profile_pic_bytes, user_id))
    else:
        conn.execute("UPDATE users SET display_name = ? WHERE id = ?", (display_name, user_id))
    conn.commit()
    conn.close()

def search_users(query, exclude_id):
    conn = get_conn()
    df = pd.read_sql(
        "SELECT id, username, display_name FROM users WHERE (username LIKE ? OR display_name LIKE ?) AND id != ?",
        conn, params=(f"%{query}%", f"%{query}%", exclude_id)
    )
    conn.close()
    return df

def send_friend_request(user_id, friend_id):
    conn = get_conn()
    ok = True
    try:
        conn.execute(
            "INSERT INTO friendships (user_id, friend_id, status, requested_by) VALUES (?,?,?,?)",
            (user_id, friend_id, "ausstehend", user_id)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        ok = False
    conn.close()
    return ok

def respond_friend_request(request_id, accept):
    conn = get_conn()
    if accept:
        conn.execute("UPDATE friendships SET status = 'akzeptiert' WHERE id = ?", (request_id,))
    else:
        conn.execute("DELETE FROM friendships WHERE id = ?", (request_id,))
    conn.commit()
    conn.close()

def get_pending_friend_requests(user_id):
    conn = get_conn()
    df = pd.read_sql('''
        SELECT f.id, u.id AS requester_id, u.display_name, u.username
        FROM friendships f JOIN users u ON f.requested_by = u.id
        WHERE f.friend_id = ? AND f.status = 'ausstehend' AND f.requested_by != ?
    ''', conn, params=(user_id, user_id))
    conn.close()
    return df

def get_friends(user_id):
    conn = get_conn()
    df = pd.read_sql('''
        SELECT u.id, u.display_name, u.username FROM friendships f
        JOIN users u ON u.id = (CASE WHEN f.user_id = ? THEN f.friend_id ELSE f.user_id END)
        WHERE (f.user_id = ? OR f.friend_id = ?) AND f.status = 'akzeptiert'
    ''', conn, params=(user_id, user_id, user_id))
    conn.close()
    return df

def get_rulesets():
    conn = get_conn()
    df = pd.read_sql("SELECT * FROM rulesets ORDER BY id", conn)
    conn.close()
    return df

def save_custom_ruleset(name, flags):
    conn = get_conn()
    ok = True
    try:
        conn.execute(
            "INSERT INTO rulesets (name, tropfen_erlaubt, wurf_von_oben, drei_sekunden_regel) VALUES (?,?,?,?)",
            (name, *flags)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        ok = False
    conn.close()
    return ok

def create_match(match_date, ruleset_id, host_id, invite_assignments):
    conn = get_conn()
    c = conn.cursor()
    c.execute(
        "INSERT INTO matches (match_date, ruleset_id, host_id, winner, status) VALUES (?,?,?,?,?)",
        (str(match_date), ruleset_id, host_id, None, "einladung_offen")
    )
    match_id = c.lastrowid
    c.execute(
        "INSERT INTO match_participants (match_id, user_id, team, treffer, wuerfe, platzierung) VALUES (?,?,?,?,?,?)",
        (match_id, host_id, invite_assignments[host_id], None, None, None)
    )
    for uid, team in invite_assignments.items():
        if uid == host_id:
            continue
        c.execute(
            "INSERT INTO match_invites (match_id, user_id, team, status) VALUES (?,?,?,?)",
            (match_id, uid, team, "ausstehend")
        )
    conn.commit()
    conn.close()
    return match_id

def get_pending_invites(user_id):
    conn = get_conn()
    df = pd.read_sql('''
        SELECT mi.id AS invite_id, m.id AS match_id, m.match_date, r.name AS regelwerk,
               u.display_name AS host_name, mi.team
        FROM match_invites mi
        JOIN matches m ON mi.match_id = m.id
        JOIN rulesets r ON m.ruleset_id = r.id
        JOIN users u ON m.host_id = u.id
        WHERE mi.user_id = ? AND mi.status = 'ausstehend'
    ''', conn, params=(user_id,))
    conn.close()
    return df

def respond_invite(invite_id, accept):
    conn = get_conn()
    row = conn.execute("SELECT match_id, user_id, team FROM match_invites WHERE id = ?", (invite_id,)).fetchone()
    if row:
        match_id, user_id, team = row
        if accept:
            conn.execute(
                "INSERT INTO match_participants (match_id, user_id, team, treffer, wuerfe, platzierung) VALUES (?,?,?,?,?,?)",
                (match_id, user_id, team, None, None, None)
            )
            conn.execute("UPDATE match_invites SET status = 'angenommen' WHERE id = ?", (invite_id,))
        else:
            conn.execute("UPDATE match_invites SET status = 'abgelehnt' WHERE id = ?", (invite_id,))
        conn.commit()
    conn.close()

def get_open_matches_for_host(host_id):
    conn = get_conn()
    df = pd.read_sql('''
        SELECT m.id, m.match_date, r.name AS regelwerk, m.status
        FROM matches m JOIN rulesets r ON m.ruleset_id = r.id
        WHERE m.host_id = ? AND m.status = 'einladung_offen'
        ORDER BY m.match_date DESC
    ''', conn, params=(host_id,))
    conn.close()
    return df

def get_match_invite_status(match_id):
    conn = get_conn()
    df = pd.read_sql('''
        SELECT u.display_name AS Spieler, mi.team AS Team, mi.status AS Status
        FROM match_invites mi JOIN users u ON mi.user_id = u.id
        WHERE mi.match_id = ?
    ''', conn, params=(match_id,))
    conn.close()
    return df

def get_match_participants_for_completion(match_id):
    conn = get_conn()
    df = pd.read_sql('''
        SELECT mp.id, u.id AS user_id, u.display_name AS Spieler, mp.team AS Team
        FROM match_participants mp JOIN users u ON mp.user_id = u.id
        WHERE mp.match_id = ?
        ORDER BY mp.team, u.display_name
    ''', conn, params=(match_id,))
    conn.close()
    return df

def finalize_match(match_id, winner, stats_by_participant_id):
    conn = get_conn()
    c = conn.cursor()
    c.execute("UPDATE matches SET winner = ?, status = 'abgeschlossen' WHERE id = ?", (winner, match_id))
    for pid, stats in stats_by_participant_id.items():
        c.execute(
            "UPDATE match_participants SET treffer = ?, wuerfe = ?, platzierung = ? WHERE id = ?",
            (stats["treffer"], stats["wuerfe"], stats["platzierung"], pid)
        )
    conn.commit()
    conn.close()

def get_all_completed_matches():
    conn = get_conn()
    df = pd.read_sql('''
        SELECT m.id, m.match_date AS Datum, r.name AS Regelwerk, m.winner AS Gewinner, u.display_name AS Host
        FROM matches m JOIN rulesets r ON m.ruleset_id = r.id JOIN users u ON m.host_id = u.id
        WHERE m.status = 'abgeschlossen'
        ORDER BY m.match_date DESC, m.id DESC
    ''', conn)
    conn.close()
    return df

def get_match_participants_view(match_id):
    conn = get_conn()
    df = pd.read_sql('''
        SELECT mp.team AS Team, u.display_name AS Spieler, mp.treffer AS Treffer, mp.wuerfe AS Wuerfe,
               mp.platzierung AS "Individuelle Platzierung"
        FROM match_participants mp JOIN users u ON mp.user_id = u.id
        WHERE mp.match_id = ?
        ORDER BY mp.team, u.display_name
    ''', conn, params=(match_id,))
    conn.close()
    return df

def delete_match(match_id):
    conn = get_conn()
    conn.execute("DELETE FROM match_participants WHERE match_id = ?", (match_id,))
    conn.execute("DELETE FROM match_invites WHERE match_id = ?", (match_id,))
    conn.execute("DELETE FROM matches WHERE id = ?", (match_id,))
    conn.commit()
    conn.close()

def get_player_stats_for_friends(user_id):
    friend_ids = get_friends(user_id)["id"].tolist() + [user_id]
    conn = get_conn()
    placeholders = ",".join("?" * len(friend_ids))
    df = pd.read_sql(f'''
        SELECT u.id, u.display_name AS Spieler,
               COUNT(mp.id) AS Spiele,
               SUM(CASE WHEN mp.team = m.winner THEN 1 ELSE 0 END) AS Siege,
               ROUND(AVG(mp.treffer), 2) AS "Ø Treffer",
               ROUND(AVG(mp.wuerfe), 2) AS "Ø Würfe",
               ROUND(SUM(mp.treffer) * 1.0 / NULLIF(SUM(mp.wuerfe), 0), 3) AS Trefferquote,
               ROUND(AVG(mp.platzierung), 2) AS "Ø Individuelle Platzierung"
        FROM match_participants mp
        JOIN matches m ON mp.match_id = m.id AND m.status = 'abgeschlossen'
        JOIN users u ON mp.user_id = u.id
        WHERE u.id IN ({placeholders})
        GROUP BY u.id, u.display_name
        ORDER BY Siege DESC, Trefferquote DESC
    ''', conn, params=friend_ids)
    conn.close()
    if not df.empty:
        df["Siegquote"] = (df["Siege"] / df["Spiele"]).round(3)
    return df

try:
    init_db()
except Exception as e:
    st.error(f"Fehler bei der Datenbank-Initialisierung: {e}")
    st.stop()

st.set_page_config(page_title="Bierball League", layout="wide")

if "user" not in st.session_state:
    st.session_state.user = None

if st.session_state.user is None:
    st.title("Bierball League – Login")
    login_tab, register_tab = st.tabs(["Anmelden", "Registrieren"])

    with login_tab:
        with st.form("login_form"):
            u = st.text_input("Benutzername")
            p = st.text_input("Passwort", type="password")
            submitted = st.form_submit_button("Anmelden")
            if submitted:
                result = verify_login(u.strip(), p)
                if result:
                    st.session_state.user = result
                    st.rerun()
                else:
                    st.error("Benutzername oder Passwort falsch.")

    with register_tab:
        with st.form("register_form"):
            new_u = st.text_input("Benutzername wählen")
            new_dn = st.text_input("Anzeigename")
            new_p = st.text_input("Passwort", type="password")
            reg_submitted = st.form_submit_button("Account erstellen")
            if reg_submitted:
                if not new_u.strip() or not new_p.strip() or not new_dn.strip():
                    st.warning("Bitte alle Felder ausfüllen.")
                elif create_user(new_u.strip(), new_p, new_dn.strip()):
                    st.success("Account erstellt! Du kannst dich jetzt anmelden.")
                else:
                    st.warning("Dieser Benutzername ist bereits vergeben.")
    st.stop()

user_id = st.session_state.user["id"]
display_name = st.session_state.user["display_name"]

st.sidebar.write(f"Angemeldet als **{display_name}**")
if st.sidebar.button("Abmelden"):
    st.session_state.user = None
    st.rerun()

st.title("Bierball League")

tabs = st.tabs(["Profil", "Freunde", "Neues Spiel", "Einladungen", "Spielverlauf", "Rangliste"])

# --- TAB: Profil ---
with tabs[0]:
    st.header("Mein Profil")
    user_row = get_user(user_id)
    _, username, current_display_name, current_pic = user_row

    col1, col2 = st.columns([1, 3])
    with col1:
        if current_pic:
            st.image(BytesIO(current_pic), width=120)
        else:
            st.write("Kein Profilbild")
    with col2:
        with st.form("profile_form"):
            new_display_name = st.text_input("Anzeigename", value=current_display_name)
            new_pic_file = st.file_uploader("Profilbild hochladen", type=["png", "jpg", "jpeg"])
            profile_submitted = st.form_submit_button("Speichern")
            if profile_submitted:
                pic_bytes = new_pic_file.read() if new_pic_file else None
                update_profile(user_id, new_display_name.strip(), pic_bytes)
                st.session_state.user["display_name"] = new_display_name.strip()
                st.success("Profil aktualisiert.")
                st.rerun()

    st.divider()
    st.subheader("Meine Statistiken")
    own_stats = get_player_stats_for_friends(user_id)
    own_row = own_stats.loc[own_stats["id"] == user_id] if not own_stats.empty else pd.DataFrame()
    if own_row.empty:
        st.info("Noch keine abgeschlossenen Spiele.")
    else:
        r = own_row.iloc[0]
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Spiele", int(r["Spiele"]))
        c2.metric("Siegquote", f"{r['Siegquote']*100:.1f}%")
        c3.metric("Trefferquote", f"{r['Trefferquote']*100:.1f}%" if pd.notna(r["Trefferquote"]) else "–")
        c4.metric("Ø Individuelle Platzierung", r["Ø Individuelle Platzierung"])

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
        st.dataframe(friends_df[["display_name", "username"]].rename(
            columns={"display_name": "Name", "username": "Benutzername"}
        ), use_container_width=True, hide_index=True)

# --- TAB: Neues Spiel ---
with tabs[2]:
    st.header("Neues Spiel erstellen")
    friends_df = get_friends(user_id)
    rulesets_df = get_rulesets()

    if friends_df.empty:
        st.info("Du brauchst mindestens einen Freund, um ein Spiel zu starten. Füge zuerst Freunde im Tab 'Freunde' hinzu.")
    else:
        col1, col2 = st.columns(2)
        with col1:
            match_date = st.date_input("Datum", value=date.today())
        with col2:
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
                create_match(match_date, ruleset_id, user_id, invite_assignments)
                st.success("Spiel erstellt und Einladungen versendet!")
                st.rerun()

    st.divider()
    st.subheader("Meine offenen Spiele (warte auf Zusagen)")
    open_matches = get_open_matches_for_host(user_id)
    if open_matches.empty:
        st.caption("Keine offenen Spiele.")
    else:
        for _, m in open_matches.iterrows():
            with st.expander(f"Spiel {m['id']} – {m['match_date']} ({m['regelwerk']})"):
                invite_status = get_match_invite_status(int(m["id"]))
                st.dataframe(invite_status, use_container_width=True, hide_index=True)

                participants = get_match_participants_for_completion(int(m["id"]))
                st.markdown("**Ergebnis eintragen und Spiel abschließen:**")
                winner_choice = st.radio("Gewinner", ["Team A", "Team B"], key=f"winner_{m['id']}", horizontal=True)
                winner_code = "A" if winner_choice == "Team A" else "B"

                stats_inputs = {}
                for _, p in participants.iterrows():
                    c1, c2, c3 = st.columns(3)
                    with c1:
                        treffer = st.number_input(f"Treffer – {p['Spieler']} (Team {p['Team']})", min_value=0, step=1, key=f"tr_{m['id']}_{p['id']}")
                    with c2:
                        wuerfe = st.number_input(f"Würfe – {p['Spieler']}", min_value=0, step=1, key=f"wu_{m['id']}_{p['id']}")
                    with c3:
                        platz = st.number_input(f"Individuelle Platzierung – {p['Spieler']}", min_value=1, step=1, key=f"pl_{m['id']}_{p['id']}")
                    stats_inputs[int(p["id"])] = {"treffer": treffer, "wuerfe": wuerfe, "platzierung": platz}

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

# --- TAB: Spielverlauf ---
with tabs[4]:
    st.header("Spielverlauf (abgeschlossene Spiele)")
    matches_df = get_all_completed_matches()
    if matches_df.empty:
        st.info("Noch keine abgeschlossenen Spiele.")
    else:
        st.dataframe(matches_df.drop(columns=["id"]), use_container_width=True, hide_index=True)
        selected_id = st.selectbox("Details zu Spiel-ID anzeigen", matches_df["id"].tolist())
        if selected_id:
            st.dataframe(get_match_participants_view(int(selected_id)), use_container_width=True, hide_index=True)
            if st.button("Dieses Spiel löschen"):
                delete_match(int(selected_id))
                st.success("Spiel gelöscht.")
                st.rerun()

# --- TAB: Rangliste ---
with tabs[5]:
    st.header("Rangliste (du und deine Freunde)")
    stats_df = get_player_stats_for_friends(user_id)
    if stats_df.empty:
        st.info("Noch keine Statistiken vorhanden.")
    else:
        st.dataframe(stats_df.drop(columns=["id"]), use_container_width=True, hide_index=True)
