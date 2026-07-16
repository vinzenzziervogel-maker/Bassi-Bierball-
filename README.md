# Bierball League v2 – Mit Nutzer-Accounts, Freunden & Einladungen

## Neue Features gegenüber dem Prototyp
- Nutzer-Accounts mit Login/Registrierung (Benutzername + Passwort, sicher gehasht)
- Eigener Profil-Reiter: Anzeigename, Profilbild-Upload, persönliche Statistiken
- Freundesfunktion: Nutzer suchen, Freundschaftsanfragen senden/annehmen/ablehnen
- Einladungssystem: Host erstellt Spiel, wählt Freunde für Team A/B, diese bekommen
  Einladungen im eigenen "Einladungen"-Tab und können annehmen/ablehnen
- Nur echte Nutzer-Accounts (keine manuelle Namenseingabe mehr)
- Rangliste & Statistiken beziehen sich automatisch auf dich + deine Freunde

## Setup lokal
1. pip install -r requirements.txt
2. streamlit run app.py

## Deployment auf Render.com
1. Neues GitHub-Repository erstellen (z.B. "bierball-league-v2")
2. Dateien app.py, requirements.txt und README.md hochladen
3. Auf render.com: New -> Web Service -> Repository verbinden
4. Start Command: streamlit run app.py --server.port $PORT --server.address 0.0.0.0
5. Deploy klicken

## Wichtiger Hinweis zu Daten
SQLite läuft lokal in der Datei bierball_v2.db. Auf Render (kostenloser Tier) ist der
Dateispeicher NICHT persistent über Neustarts hinweg - für produktiven Dauerbetrieb
später auf eine externe DB (z.B. Supabase/PostgreSQL) umsteigen.

## Funktionsablauf (Kurzfassung)
1. Account erstellen und einloggen
2. Im Tab "Freunde" andere Nutzer suchen und Freundschaftsanfragen senden
3. Im Tab "Neues Spiel" ein Spiel erstellen: Regelwerk wählen, Freunde für Team A/B
   auswählen -> Einladungen werden automatisch versendet
4. Eingeladene Freunde nehmen die Einladung im Tab "Einladungen" an
5. Host trägt im Tab "Neues Spiel" unter "Meine offenen Spiele" das Ergebnis und die
   individuellen Stats ein und schließt das Spiel ab
6. Danach erscheinen die Werte automatisch in Spielverlauf, Profil und Rangliste
   aller beteiligten Spieler
