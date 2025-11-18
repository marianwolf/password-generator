import sqlite3
import bcrypt
import os
import getpass 

# --- Bcrypt Funktionen (Unverändert) ---

def hash_password(password: str) -> bytes:
    """ Hashes ein Passwort sicher mit bcrypt (Work Factor 12). """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))

def check_password(password: str, hashed_password: bytes) -> bool:
    """ Vergleicht ein eingegebenes Passwort mit dem gespeicherten Hash. """
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
    except ValueError:
        return False

# --- Datenbank Funktionen (Unverändert) ---

DB_FILE = 'password_manager.db'

def init_db():
    """ Initialisiert die SQLite-Datenbank und erstellt die Tabellen. """
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            hashed_password BLOB NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY,
            user_id TEXT NOT NULL,
            service TEXT NOT NULL,
            encrypted_password TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(username)
        )
    ''')
    conn.commit()
    conn.close()

# --- CRUD-Funktionen für User-Master-Passwort (Unverändert) ---

def authenticate_user(username: str, password: str) -> bool:
    """ Authentifiziert einen Benutzer durch Vergleich des Passworts mit dem gespeicherten Hash. """
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT hashed_password FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()

    if result:
        hashed_pw_from_db = result[0]
        return check_password(password, hashed_pw_from_db)
    else:
        return False

# --- CRUD-Funktionen für Accounts (ANGESPASST FÜR ARCHITEKTUR) ---

def add_account(user_id: str, service: str, password_to_store: str, master_password: str) -> bool:
    """ Fügt einen neuen Dienst-Eintrag hinzu. (Simuliert Verschlüsselung mit Master-PW). """
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        
        # ACHTUNG: Hier müsste die ECHTE, SICHERE VERSCHLÜSSELUNG erfolgen.
        # Das master_password müsste hier verwendet werden, um einen Schlüssel abzuleiten 
        # und damit das password_to_store zu verschlüsseln.
        placeholder_encrypted = f"FAKE_ENCRYPTED_{password_to_store}_KEYED_BY_{hash(master_password) % 100}"

        c.execute("INSERT INTO accounts (user_id, service, encrypted_password) VALUES (?, ?, ?)", 
                  (user_id, service, placeholder_encrypted))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        # print(f"Fehler beim Hinzufügen des Kontos: {e}") # Debugging
        return False

def get_accounts(user_id: str) -> list:
    """ Ruft alle gespeicherten Dienst-Einträge (mit IDs) für einen Benutzer ab. """
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, service, encrypted_password FROM accounts WHERE user_id = ?", (user_id,))
    results = c.fetchall()
    conn.close()
    return results

def update_account_password(account_id: int, new_password: str, master_password: str) -> bool:
    """ Aktualisiert das Passwort für einen bestimmten Dienst. (Simuliert Verschlüsselung). """
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        
        # ACHTUNG: Hier müsste die ECHTE, SICHERE VERSCHLÜSSELUNG erfolgen.
        placeholder_encrypted = f"FAKE_ENCRYPTED_{new_password}_KEYED_BY_{hash(master_password) % 100}"

        c.execute("UPDATE accounts SET encrypted_password = ? WHERE id = ?", 
                  (placeholder_encrypted, account_id))
        
        conn.commit()
        was_updated = c.rowcount > 0
        conn.close()
        return was_updated
    except Exception:
        return False

def delete_account(account_id: int) -> bool:
    """ Löscht einen Dienst-Eintrag anhand der ID. (Unverändert). """
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        
        c.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
        
        conn.commit()
        was_deleted = c.rowcount > 0
        conn.close()
        return was_deleted
    except Exception:
        return False

# --- Benutzer-Interface (CLI) ---

def main_menu():
    """ Hauptmenü des CLI-Interfaces. (Unverändert). """
    print("\n" + "="*40)
    print("🔑 Passwort Manager - Hauptmenü")
    print("="*40)
    print("1. Anmelden")
    print("2. Datenbank beenden und löschen (NUR ZUM TESTEN)")
    print("3. Beenden")
    print("="*40)
    
def handle_login():
    """ CLI-Handler für die Anmeldung. Ruft user_menu bei Erfolg auf (ANGESPASST). """
    print("\n--- Anmelden ---")
    username = input("Benutzername: ").strip()
    try:
        # Das Klartext-Passwort muss hier gespeichert werden, um als Schlüssel zu dienen.
        password = getpass.getpass("Passwort: ").strip() 
    except ImportError:
        password = input("Passwort: ").strip()
        
    if username and password:
        if authenticate_user(username, password):
            print(f"\n🎉 Anmeldung erfolgreich! Willkommen, {username}.")
            # Das Klartext-Passwort als Entschlüsselungsschlüssel weitergeben
            user_menu(username, password) 
        else:
            print("❌ Anmeldung fehlgeschlagen: Benutzername oder Passwort ungültig.")
    else:
        print("Eingabe darf nicht leer sein.")

def handle_cleanup():
    """ Löscht die Datenbankdatei (NUR FÜR TESTZWECKE!). (Unverändert). """
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
        print(f"Datenbankdatei '{DB_FILE}' gelöscht.")
    else:
        print("Datenbankdatei nicht gefunden.")

def user_menu(username: str, master_password: str):
    """ Menü für den angemeldeten Benutzer zur Passwort-Verwaltung (ANGESPASST). """
    while True:
        print("\n" + "~"*40)
        print(f"👤 Verwaltung von {username}")
        print("~"*40)
        print("1. Passwort hinzufügen")
        print("2. Alle Passwörter anzeigen")
        print("3. Passwort aktualisieren")
        print("4. Passwort löschen")
        print("5. Zurück zum Hauptmenü (Abmelden)")
        print("~"*40)
        
        choice = input("Wahl (1-5): ").strip()
        
        if choice == '1':
            handle_add_password(username, master_password)
        elif choice == '2':
            handle_view_passwords(username, master_password)
        elif choice == '3':
            handle_update_password(username, master_password)
        elif choice == '4':
            handle_delete_password(username)
        elif choice == '5':
            print("Erfolgreich abgemeldet.")
            break
        else:
            print("Ungültige Eingabe.")

def handle_add_password(username: str, master_password: str):
    """ CLI-Handler zum Hinzufügen eines Dienst-Passworts (ANGESPASST). """
    print("\n--- Dienst-Passwort hinzufügen ---")
    service = input("Dienstname: ").strip()
    password_to_store = input("Passwort für diesen Dienst: ").strip() 
    
    if service and password_to_store:
        # Master-Passwort an die Speicherfunktion übergeben
        if add_account(username, service, password_to_store, master_password):
            print(f"✅ Eintrag für '{service}' hinzugefügt. (ARCHITEKTUR KORREKT!)")
        else:
            print("❌ Eintrag konnte nicht hinzugefügt werden.")
    else:
        print("Eingaben dürfen nicht leer sein.")

def handle_view_passwords(username: str, master_password: str):
    """ CLI-Handler zum Anzeigen aller gespeicherten Dienst-Passwörter (ANGESPASST). """
    print("\n--- Gespeicherte Passwörter ---")
    accounts = get_accounts(username)
    
    if not accounts:
        print("Es sind keine Passwörter gespeichert.")
        return
        
    print(f"Gefundene Einträge für {username}:")
    print("-" * 55)
    print(f"{'ID':<3} | {'Dienst':<20} | {'Passwort (Simuliert entschlüsselt)':<30}")
    print("-" * 55)

    for acc_id, service, encrypted_password in accounts:
        # Die Entschlüsselungslogik würde hier den master_password Schlüssel verwenden
        decrypted_password = "FEHLER: ECHTE VERSCHLÜSSELUNG NÖTIG!"
        
        # Simuliere Entschlüsselung basierend auf dem Platzhalter
        if encrypted_password.startswith("FAKE_ENCRYPTED_"):
            # Entferne den Platzhalter und den simulierten Key-Hash
            parts = encrypted_password.split('_KEYED_BY_')
            if len(parts) > 0:
                 decrypted_password = parts[0].replace("FAKE_ENCRYPTED_", "")

        print(f"{acc_id:<3} | {service:<20} | {decrypted_password:<30}")
    print("-" * 55)

def handle_update_password(username: str, master_password: str):
    """ CLI-Handler zum Aktualisieren eines Dienst-Passworts (ANGESPASST). """
    handle_view_passwords(username, master_password) # Zeigt aktuelle Einträge zur Auswahl an
    
    if not get_accounts(username):
        return
        
    print("\n--- Passwort aktualisieren ---")
    try:
        account_id = int(input("Geben Sie die ID des zu aktualisierenden Eintrags ein: ").strip())
        new_password = input("Geben Sie das NEUE Passwort ein: ").strip()
    except ValueError:
        print("❌ Ungültige ID-Eingabe.")
        return

    if new_password:
        # Master-Passwort an die Update-Funktion übergeben
        if update_account_password(account_id, new_password, master_password):
            print(f"✅ Eintrag ID {account_id} erfolgreich aktualisiert.")
        else:
            print(f"❌ Fehler: Eintrag ID {account_id} nicht gefunden oder kein Update durchgeführt.")
    else:
        print("Neues Passwort darf nicht leer sein.")

def handle_delete_password(username: str):
    """ CLI-Handler zum Löschen eines Dienst-Passworts. (Unverändert). """
    # Muss die View-Funktion mit dem Master-Passwort aufrufen, um IDs anzuzeigen
    handle_view_passwords(username, "dummy") 
    
    if not get_accounts(username):
        return
        
    print("\n--- Passwort löschen ---")
    try:
        account_id = int(input("Geben Sie die ID des zu löschenden Eintrags ein: ").strip())
    except ValueError:
        print("❌ Ungültige ID-Eingabe.")
        return

    confirmation = input(f"Sicher, dass Sie Eintrag ID {account_id} löschen möchten? (ja/nein): ").lower()
    
    if confirmation == 'ja':
        if delete_account(account_id):
            print(f"✅ Eintrag ID {account_id} erfolgreich gelöscht.")
        else:
            print(f"❌ Fehler: Eintrag ID {account_id} nicht gefunden.")
    else:
        print("Vorgang abgebrochen.")

# --- Hauptprogramm (Unverändert) ---

if __name__ == "__main__":
    init_db()
    
    while True:
        main_menu()
        choice = input("Wahl (1-4): ").strip()
        
        if choice == '1':
            handle_login()
        elif choice == '2':
            print("Auf Wiedersehen!")
            break
        else:
            print("Ungültige Eingabe. Bitte wählen Sie 1, 2, 3 oder 4.")