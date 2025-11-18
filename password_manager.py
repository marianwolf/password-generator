import sqlite3
import bcrypt
import os
import getpass 
import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DB_FILE = 'password_manager.db' 

# --- KRYPTOGRAFIE ---
def derive_key_argon2(master_password: str, salt: bytes) -> bytes:
    pw_bytes = master_password.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend()
    )
    return kdf.derive(pw_bytes)

def derive_key(master_password: str, salt: bytes) -> bytes:
    return derive_key_argon2(master_password, salt)

# AES-256 GCM Verschlüsselung
def encrypt_password(key: bytes, plaintext: str) -> str:
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()) 
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(iv) 
    ciphertext_bytes = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
    tag = encryptor.tag
    return f"AES-GCM:{base64.b64encode(iv).decode()}:{base64.b64encode(tag).decode()}:{base64.b64encode(ciphertext_bytes).decode()}"

# AES-256 GCM Entschlüsselung
def decrypt_password(key: bytes, ciphertext: str) -> str:
    try:
        if not ciphertext.startswith("AES-GCM:"):
            return "FEHLER: Unbekanntes Chiffre-Format (Nicht AES-GCM)"
            
        parts = ciphertext.split(':')
        if len(parts) != 4:
            return "FEHLER: Ungültiges AES-GCM Format"
            
        _, iv_b64, tag_b64, cipher_b64 = parts
        
        iv = base64.b64decode(iv_b64)
        tag = base64.b64decode(tag_b64)
        ciphertext_bytes = base64.b64decode(cipher_b64)
        
        if len(iv) != 12:
            return "FEHLER: Ungültige IV-Länge"

        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        decryptor.authenticate_additional_data(iv) 

        plaintext_bytes = decryptor.update(ciphertext_bytes) + decryptor.finalize()
        return plaintext_bytes.decode('utf-8')
        
    except Exception as e:
        return f"❌ ENTSCHLÜSSELUNGSFEHLER: {e}"

# --- DATENBANK ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            hashed_password BLOB NOT NULL,
            argon2_salt BLOB NOT NULL -- Salt für Argon2-Schlüsselableitung
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY,
            user_id TEXT NOT NULL,
            service TEXT NOT NULL,
            encrypted_password TEXT NOT NULL,
            salt BLOB, 
            FOREIGN KEY(user_id) REFERENCES users(username)
        )
    ''')
    conn.commit()
    conn.close()

# --- HELFER-FUNKTIONEN ---
def check_password(password: str, hashed_password: bytes) -> bool:
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
    except ValueError:
        return False
       
def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))

# --- CRUD-Funktionen für User-Master-Passwort ---
def create_user(username: str, password: str) -> bool:
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        hashed_pw = hash_password(password)
        argon2_salt = os.urandom(16) 
        c.execute("INSERT INTO users (username, hashed_password, argon2_salt) VALUES (?, ?, ?)", 
                  (username, hashed_pw, argon2_salt))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        print("❌ Fehler: Benutzername existiert bereits.")
        return False
    except Exception as e:
        print(f"Fehler bei Benutzererstellung: {e}")
        return False
        
def authenticate_user(username: str, password: str) -> tuple[bool, bytes | None]:
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT hashed_password, argon2_salt FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()

    if result:
        hashed_pw_from_db, argon2_salt = result
        if check_password(password, hashed_pw_from_db):
            return True, argon2_salt
        else:
            return False, None
    else:
        return False, None

# --- CRUD-Funktionen für Accounts ---
def add_account(user_id: str, service: str, password_to_store: str, master_password: str, argon2_salt: bytes) -> bool:
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        
        dummy_salt = b'\x00' * 16 

        encryption_key = derive_key(master_password, argon2_salt)
        encrypted_password = encrypt_password(encryption_key, password_to_store)
        
        c.execute("INSERT INTO accounts (user_id, service, encrypted_password, salt) VALUES (?, ?, ?, ?)", 
                  (user_id, service, encrypted_password, dummy_salt))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Fehler beim Hinzufügen: {e}")
        return False

def get_accounts(user_id: str) -> list:
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, service, encrypted_password, salt FROM accounts WHERE user_id = ?", (user_id,))
    results = c.fetchall()
    conn.close()
    return results

def update_account_password(account_id: int, new_password: str, master_password: str, argon2_salt: bytes) -> bool:
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        
        c.execute("SELECT id FROM accounts WHERE id = ?", (account_id,))
        if not c.fetchone():
            conn.close()
            return False
            
        encryption_key = derive_key(master_password, argon2_salt)
        encrypted_password = encrypt_password(encryption_key, new_password)
        c.execute("UPDATE accounts SET encrypted_password = ? WHERE id = ?", 
                  (encrypted_password, account_id))
        
        conn.commit()
        was_updated = c.rowcount > 0
        conn.close()
        return was_updated
    except Exception as e:
        print(f"Update Fehler: {e}")
        return False

# --- NEU: Fehlende Funktion hinzugefügt ---
def delete_account(account_id: int) -> bool:
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        
        c.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
        
        conn.commit()
        was_deleted = c.rowcount > 0
        conn.close()
        return was_deleted
    except Exception as e:
        print(f"Lösch-Fehler: {e}")
        return False

def handle_login():
    print("\n--- Anmelden / Registrieren ---")
    username = input("Benutzername: ").strip()
    try:
        password = getpass.getpass("Passwort: ").strip()
    except ImportError:
        password = input("Passwort: ").strip()
        
    if not username or not password:
        print("Eingabe darf nicht leer sein.")
        return

    authenticated, argon2_salt = authenticate_user(username, password)
    
    if authenticated:
        print(f"\n🎉 Anmeldung erfolgreich! Willkommen, {username}.")
        if argon2_salt is not None:
            user_menu(username, password, argon2_salt) 
        else:
             print("❌ Fehler: Konnte Salt nicht abrufen. Bitte wenden Sie sich an den Support.")
    else:
        print("Anmeldung fehlgeschlagen. Versuche, neuen Benutzer zu registrieren...")
        if create_user(username, password):
             _, argon2_salt = authenticate_user(username, password)
             print(f"🎉 Registrierung erfolgreich! Willkommen, {username}.")
             if argon2_salt is not None:
                user_menu(username, password, argon2_salt)
             else:
                print("❌ Fehler: Konnte Salt nach Registrierung nicht abrufen.")
        else:
             print("❌ Registrierung/Anmeldung fehlgeschlagen.")

def user_menu(username: str, master_password: str, argon2_salt: bytes):
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
            handle_add_password(username, master_password, argon2_salt)
        elif choice == '2':
            handle_view_passwords(username, master_password, argon2_salt)
        elif choice == '3':
            handle_update_password(username, master_password, argon2_salt)
        elif choice == '4':
            handle_delete_password(username, master_password, argon2_salt) 
        elif choice == '5':
            print("Erfolgreich abgemeldet.")
            break
        else:
            print("Ungültige Eingabe.")

def handle_add_password(username: str, master_password: str, argon2_salt: bytes):
    print("\n--- Dienst-Passwort hinzufügen ---")
    service = input("Dienstname: ").strip()
    password_to_store = input("Passwort für diesen Dienst: ").strip() 
    
    if service and password_to_store:
        if add_account(username, service, password_to_store, master_password, argon2_salt):
            print(f"✅ Eintrag für '{service}' hinzugefügt.")
        else:
            print("❌ Eintrag konnte nicht hinzugefügt werden.")
    else:
        print("Eingaben dürfen nicht leer sein.")

def handle_view_passwords(username: str, master_password: str, argon2_salt: bytes):
    print("\n--- Gespeicherte Passwörter ---")
    accounts = get_accounts(username)
    
    if not accounts:
        print("Es sind keine Passwörter gespeichert.")
        return
        
    print(f"Gefundene Einträge für {username}:")
    print("-" * 55)
    print(f"{'ID':<3} | {'Dienst':<20} | {'Passwort (Entschlüsselt)':<30}")
    print("-" * 55)

    encryption_key = derive_key(master_password, argon2_salt)

    for acc_id, service, encrypted_password, salt in accounts: 
        decrypted_password = decrypt_password(encryption_key, encrypted_password)
        print(f"{acc_id:<3} | {service:<20} | {decrypted_password:<30}")
    print("-" * 55)

def handle_update_password(username: str, master_password: str, argon2_salt: bytes):
    handle_view_passwords(username, master_password, argon2_salt)
    
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
        if update_account_password(account_id, new_password, master_password, argon2_salt):
            print(f"✅ Eintrag ID {account_id} erfolgreich aktualisiert.")
        else:
            print(f"❌ Fehler: Eintrag ID {account_id} nicht gefunden oder kein Update durchgeführt.")
    else:
        print("Neues Passwort darf nicht leer sein.")

def handle_delete_password(username: str, master_password: str, argon2_salt: bytes):
    handle_view_passwords(username, master_password, argon2_salt)
    
    if not get_accounts(username):
        return
        
    print("\n--- Eintrag löschen ---")
    try:
        account_id = int(input("Geben Sie die ID des zu löschenden Eintrags ein: ").strip())
    except ValueError:
        print("❌ Ungültige ID-Eingabe.")
        return

    if delete_account(account_id):
        print(f"✅ Eintrag ID {account_id} erfolgreich gelöscht.")
    else:
        print(f"❌ Fehler: Eintrag ID {account_id} nicht gefunden.")


def main_menu():
    print("\n" + "="*40)
    print("🔑 Passwort Manager - Hauptmenü (SICHERE VERSION)")
    print("="*40)
    print("1. Anmelden")
    print("2. Beenden")
    print("="*40)

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