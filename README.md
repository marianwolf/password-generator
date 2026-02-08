# Passwort-Manager

Ein sicherer Passwort-Manager mit SQLite-Datenbank und starker Verschlüsselung.

## Funktionen

- 🔐 **Sichere Verschlüsselung** - Passwörter werden mit AES-256 verschlüsselt
- 📁 **SQLite-Datenbank** - Lokale Speicherung ohne externe Server
- 🏷️ **Kategorien** - Passwörter können kategorisiert werden
- ⭐ **Favoriten** - Wichtige Passwörter als Favoriten markieren
- 🔍 **Suche** - Passwörter schnell finden
- 📊 **Statistiken** - Übersicht über gespeicherte Passwörter

## Installation

```bash
# Abhängigkeiten installieren
pip install -r requirements.txt
```

## Verwendung

```bash
# Passwort-Manager starten
python main.py
```

## Befehle

| Befehl | Beschreibung |
|--------|-------------|
| `hilfe`, `?`, `help`, `h` | Diese Hilfe anzeigen |
| `add`, `neu` | Neuen Passwort-Eintrag hinzufügen |
| `list`, `ls`, `liste` | Alle Passwörter anzeigen |
| `search`, `suchen` | Passwörter durchsuchen |
| `details`, `show` | Passwort-Details anzeigen |
| `edit`, `bearbeiten` | Passwort bearbeiten |
| `delete`, `loeschen` | Passwort löschen |
| `favorit`, `fav` | Favorit umschalten |
| `stats`, `statistik` | Statistiken anzeigen |
| `clear`, `cls` | Bildschirm löschen |
| `exit`, `quit`, `x` | Beenden |

## Sicherheit

- Das Master-Passwort wird niemals im Klartext gespeichert
- Passwörter werden mit Fernet (symmetrische Verschlüsselung) verschlüsselt
- PBKDF2 wird verwendet, um den Verschlüsselungsschlüssel aus dem Master-Passwort abzuleiten
- 480.000 Iterationen für zusätzliche Sicherheit

## Dateien

- `main.py` - Hauptanwendung mit GUI-Interface
- `database.py` - Datenbank-Verwaltung
- `encryption.py` - Verschlüsselungs-Funktionen
- `passwords.db` - SQLite-Datenbank (wird automatisch erstellt)
