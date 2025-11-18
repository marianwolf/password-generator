import sqlite3
import bcrypt
import os

# --- Bcrypt Funktionen (wie von Ihnen definiert) ---

def hash_password(password: str) -> bytes:
    """ Hashes ein Passwort sicher mit bcrypt (Work Factor 12). """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))

def check_password(password: str, hashed_password: bytes) -> bool:
    """ Vergleicht ein eingegebenes Passwort mit dem gespeicherten Hash. """
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
    except ValueError:
        return False

# --- Datenbank Funktionen ---

DB_FILE = 'password_manager.db'

def init_db():
    """ Initialisiert die SQLite-Datenbank und erstellt die Tabelle. """
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # WICHTIG: Die Spalte 'hashed_password' speichert den bcrypt-Hash (der Salt und Cost enthält).
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            hashed_password BLOB NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def register_user(username: str, password: str) -> bool:
    """ Registriert einen neuen Benutzer mit sicher gehashtem Passwort. """
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        
        # 1. Passwort Hashen
        hashed_pw = hash_password(password)
        
        # 2. Speichern mit Prepared Statement (gegen SQL Injection)
        c.execute("INSERT INTO users (username, hashed_password) VALUES (?, ?)", 
                  (username, hashed_pw))
        
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        print(f"Fehler: Benutzername '{username}' existiert bereits.")
        return False
    except Exception as e:
        print(f"Ein Fehler ist aufgetreten: {e}")
        return False


def authenticate_user(username: str, password: str) -> bool:
    """ Authentifiziert einen Benutzer durch Vergleich des Passworts mit dem gespeicherten Hash. """
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Abrufen des Hashes mit Prepared Statement
    c.execute("SELECT hashed_password FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()

    if result:
        # 1. Gespeicherten Hash abrufen (als bytes)
        hashed_pw_from_db = result[0]
        
        # 2. Passwort überprüfen
        return check_password(password, hashed_pw_from_db)
    else:
        # Benutzer nicht gefunden
        return False

# --- Benutzer-Interface (CLI) ---

def main_menu():
    """ Hauptmenü des CLI-Interfaces. """
    print("\n" + "="*40)
    print("🔑 Passwort Manager - Hauptmenü")
    print("="*40)
    print("1. Benutzer registrieren")
    print("2. Anmelden")
    print("3. Datenbank beenden und löschen (NUR ZUM TESTEN)")
    print("4. Beenden")
    print("="*40)

def handle_register():
    """ CLI-Handler für die Registrierung. """
    print("\n--- Benutzer registrieren ---")
    username = input("Benutzername: ").strip()
    # Verhindert, dass das eingegebene Passwort im Terminal sichtbar ist
    try:
        import getpass
        password = getpass.getpass("Passwort: ").strip()
    except ImportError:
        # Fallback, falls getpass nicht verfügbar ist
        password = input("Passwort: ").strip() 
        
    if username and password:
        if register_user(username, password):
            print(f"✅ Registrierung von '{username}' erfolgreich.")
        else:
            print("❌ Registrierung fehlgeschlagen.")
    else:
        print("Eingabe darf nicht leer sein.")


def handle_login():
    """ CLI-Handler für die Anmeldung. """
    print("\n--- Anmelden ---")
    username = input("Benutzername: ").strip()
    try:
        import getpass
        password = getpass.getpass("Passwort: ").strip()
    except ImportError:
        password = input("Passwort: ").strip()
        
    if username and password:
        if authenticate_user(username, password):
            print(f"\n🎉 Anmeldung erfolgreich! Willkommen, {username}.")
            # Hier müsste die Logik zum Anzeigen/Verwalten der Passwörter folgen
            print("(Kernfunktionalität des Managers würde hier gestartet.)")
        else:
            print("❌ Anmeldung fehlgeschlagen: Benutzername oder Passwort ungültig.")
    else:
        print("Eingabe darf nicht leer sein.")

def handle_cleanup():
    """ Löscht die Datenbankdatei (NUR FÜR TESTZWECKE!). """
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
        print(f"Datenbankdatei '{DB_FILE}' gelöscht.")
    else:
        print("Datenbankdatei nicht gefunden.")


# --- Hauptprogramm ---

if __name__ == "__main__":
    init_db()  # Datenbank beim Start initialisieren
    
    while True:
        main_menu()
        choice = input("Wahl (1-4): ").strip()
        
        if choice == '1':
            handle_register()
        elif choice == '2':
            handle_login()
        elif choice == '3':
            handle_cleanup()
        elif choice == '4':
            print("Auf Wiedersehen!")
            break
        else:
            print("Ungültige Eingabe. Bitte wählen Sie 1, 2, 3 oder 4.")