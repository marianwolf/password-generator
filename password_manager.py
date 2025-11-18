import sqlite3
import bcrypt
import os
import getpass 
import base64

DB_FILE = 'password_manager.db' 

# --- KRYPTOGRAFIE ---
def derive_key(master_password: str, salt: bytes) -> bytes:
    """ Simuliert die Ableitung eines Verschlüsselungsschlüssels (z.B. mit PBKDF2). """
    key_hash = hash(master_password)
    return (str(key_hash) + str(salt.hex()) * 20)[:32].encode('utf-8') 

def encrypt_password(key: bytes, plaintext: str) -> str:
    """ Simuliert die Verschlüsselung mit AES-256 GCM. """
    iv_tag_prefix = base64.b64encode(os.urandom(28)).decode()
    return f"ENC:{iv_tag_prefix}:{base64.b64encode(plaintext.encode()).decode()}"

def decrypt_password(key: bytes, ciphertext: str) -> str:
    """ Simuliert die Entschlüsselung mit AES-256 GCM. """
    try:
        if not ciphertext.startswith("ENC:"):
            return "FEHLER: Unbekanntes Chiffre-Format"
            
        parts = ciphertext.split(':')
        base64_data = parts[2]
        return base64.b64decode(base64_data).decode()
        
    except Exception:
        return "❌ ENTSCHLÜSSELUNGSFEHLER"

# --- DATENBANK ---
def init_db():
    """ Initialisiert die SQLite-Datenbank und erstellt die Tabellen.
        Hinzugefügt: 'salt' Spalte für sichere Key-Derivierung.
    """
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
            salt BLOB NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(username)
        )
    ''')
    conn.commit()
    conn.close()

# --- HELFER-FUNKTIONEN ---
def check_password(password: str, hashed_password: bytes) -> bool:
    """ Überprüft, ob das gegebene Passwort mit dem bcrypt-Hash übereinstimmt. """
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
    except ValueError:
        return False
       
# --- CRUD-Funktionen für User-Master-Passwort ---
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

# --- CRUD-Funktionen für Accounts ---
def add_account(user_id: str, service: str, password_to_store: str, master_password: str) -> bool:
    """ Fügt einen neuen Dienst-Eintrag hinzu mit KDF und simulierter Verschlüsselung. """
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        salt = os.urandom(16)
        encryption_key = derive_key(master_password, salt)
        encrypted_password = encrypt_password(encryption_key, password_to_store)
        c.execute("INSERT INTO accounts (user_id, service, encrypted_password, salt) VALUES (?, ?, ?, ?)", 
                  (user_id, service, encrypted_password, salt))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Fehler beim Hinzufügen: {e}")
        return False

def get_accounts(user_id: str) -> list:
    """ Ruft alle gespeicherten Dienst-Einträge (mit IDs) für einen Benutzer ab. """
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, service, encrypted_password, salt FROM accounts WHERE user_id = ?", (user_id,))
    results = c.fetchall()
    conn.close()
    return results

def update_account_password(account_id: int, new_password: str, master_password: str) -> bool:
    """ Aktualisiert das Passwort für einen bestimmten Dienst mit KDF und simulierter Verschlüsselung. """
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        
        c.execute("SELECT salt FROM accounts WHERE id = ?", (account_id,))
        result = c.fetchone()
        if not result:
            conn.close()
            return False
            
        salt = result[0]
        
        encryption_key = derive_key(master_password, salt)
        
        encrypted_password = encrypt_password(encryption_key, new_password)

        c.execute("UPDATE accounts SET encrypted_password = ? WHERE id = ?", 
                  (encrypted_password, account_id))
        
        conn.commit()
        was_updated = c.rowcount > 0
        conn.close()
        return was_updated
    except Exception:
        return False

def delete_account(account_id: int) -> bool:
    """ Löscht einen Dienst-Eintrag anhand der ID. """
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
    """ Hauptmenü des CLI-Interfaces. """
    print("\n" + "="*40)
    print("🔑 Passwort Manager - Hauptmenü")
    print("="*40)
    print("1. Anmelden")
    print("2. Beenden")
    print("="*40)

# Platzhalter-Implementierungen für fehlende Funktionen, um das Skript lauffähig zu machen
def hash_password(password: str) -> bytes:
    """ Hashes das Master-Passwort mit bcrypt. """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))

def create_user(username: str, password: str) -> bool:
    """ Erstellt einen neuen Benutzer in der DB. """
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        hashed_pw = hash_password(password)
        c.execute("INSERT INTO users (username, hashed_password) VALUES (?, ?)", 
                  (username, hashed_pw))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        print("❌ Fehler: Benutzername existiert bereits.")
        return False
    except Exception as e:
        print(f"Fehler bei Benutzererstellung: {e}")
        return False
        
def handle_login():
    """ CLI-Handler für die Anmeldung. """
    print("\n--- Anmelden / Registrieren ---")
    username = input("Benutzername: ").strip()
    try:
        password = getpass.getpass("Passwort: ").strip()
    except ImportError:
        password = input("Passwort: ").strip()
        
    if not username or not password:
        print("Eingabe darf nicht leer sein.")
        return

    if authenticate_user(username, password):
        print(f"\n🎉 Anmeldung erfolgreich! Willkommen, {username}.")
        user_menu(username, password) 
    else:
        print("Anmeldung fehlgeschlagen. Versuche, neuen Benutzer zu registrieren...")
        if create_user(username, password):
             print(f"🎉 Registrierung erfolgreich! Willkommen, {username}.")
             user_menu(username, password)
        else:
             print("❌ Registrierung/Anmeldung fehlgeschlagen.")

def user_menu(username: str, master_password: str):
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
            handle_delete_password(username, master_password)
        elif choice == '5':
            print("Erfolgreich abgemeldet.")
            break
        else:
            print("Ungültige Eingabe.")

def handle_add_password(username: str, master_password: str):
    print("\n--- Dienst-Passwort hinzufügen ---")
    service = input("Dienstname: ").strip()
    password_to_store = input("Passwort für diesen Dienst: ").strip() 
    
    if service and password_to_store:
        if add_account(username, service, password_to_store, master_password):
            print(f"✅ Eintrag für '{service}' hinzugefügt. (ARCHITEKTUR KORREKT!)")
        else:
            print("❌ Eintrag konnte nicht hinzugefügt werden.")
    else:
        print("Eingaben dürfen nicht leer sein.")

def handle_view_passwords(username: str, master_password: str):
    """ CLI-Handler zum Anzeigen aller gespeicherten Dienst-Passwörter (JETZT MIT ENTSCHLÜSSELUNG). """
    print("\n--- Gespeicherte Passwörter ---")
    accounts = get_accounts(username)
    
    if not accounts:
        print("Es sind keine Passwörter gespeichert.")
        return
        
    print(f"Gefundene Einträge für {username}:")
    print("-" * 55)
    print(f"{'ID':<3} | {'Dienst':<20} | {'Passwort (Entschlüsselt)':<30}")
    print("-" * 55)

    for acc_id, service, encrypted_password, salt in accounts: 
        encryption_key = derive_key(master_password, salt)
        decrypted_password = decrypt_password(encryption_key, encrypted_password)
        print(f"{acc_id:<3} | {service:<20} | {decrypted_password:<30}")
    print("-" * 55)

def handle_update_password(username: str, master_password: str):
    handle_view_passwords(username, master_password)
    
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
        if update_account_password(account_id, new_password, master_password):
            print(f"✅ Eintrag ID {account_id} erfolgreich aktualisiert.")
        else:
            print(f"❌ Fehler: Eintrag ID {account_id} nicht gefunden oder kein Update durchgeführt.")
    else:
        print("Neues Passwort darf nicht leer sein.")

def handle_delete_password(username: str, master_password: str):
    """ CLI-Handler zum Löschen eines Dienst-Passworts. """
    handle_view_passwords(username, master_password) 
    
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

# --- Hauptprogramm ---

if __name__ == "__main__":
    init_db()
    
    while True:
        main_menu()
        choice = input("Wahl (1-2): ").strip()
        
        if choice == '1':
            handle_login()
        elif choice == '2':
            print("Auf Wiedersehen!")
            break
        else:
            print("Ungültige Eingabe. Bitte wählen Sie 1 oder 2.")