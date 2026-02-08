#!/usr/bin/env python3
"""
Passwort-Manager - Hauptanwendung
Ein sicherer Passwort-Manager mit SQLite-Datenbank und Verschlüsselung.
"""

import sys
import getpass
from database import DatabaseManager
from encryption import EncryptionManager


class PasswordManager:
    """Hauptklasse für den Passwort-Manager."""
    
    def __init__(self):
        """Initialisiert den Passwort-Manager."""
        self.db = DatabaseManager()
        self.encryption = None
        self.authenticated = False
    
    def setup_master_password(self):
        """Richtet das Master-Passwort ein (wenn noch keines existiert)."""
        salt = self.db.get_salt()
        if salt:
            print("Master-Passwort ist bereits eingerichtet.")
            return False
        
        print("=== Ersteinrichtung des Passwort-Managers ===")
        print("Bitte erstellen Sie ein Master-Passwort.")
        print("WICHTIG: Dieses Passwort kann nicht wiederhergestellt werden!")
        print()
        
        password1 = getpass.getpass("Master-Passwort: ")
        password2 = getpass.getpass("Master-Passwort bestätigen: ")
        
        if password1 != password2:
            print("Fehler: Passwörter stimmen nicht überein.")
            return False
        
        if len(password1) < 8:
            print("Fehler: Das Passwort muss mindestens 8 Zeichen lang sein.")
            return False
        
        password_hash = EncryptionManager.hash_password(password1)
        salt = EncryptionManager.hash_password(password1 + str(hash(password1)))[:32].encode()
        
        self.db.set_master_password_hash(password_hash, salt)
        print("Master-Passwort erfolgreich eingerichtet!")
        return True
    
    def authenticate(self) -> bool:
        """Authentifiziert den Benutzer mit dem Master-Passwort."""
        stored_hash = self.db.get_master_password_hash()
        if not stored_hash:
            if not self.setup_master_password():
                return False
        
        salt = self.db.get_salt()
        password = getpass.getpass("Master-Passwort: ")
        
        password_hash = EncryptionManager.hash_password(password)
        salt_bytes = salt if salt else EncryptionManager.hash_password(password + str(hash(password)))[:32].encode()
        
        self.encryption = EncryptionManager(password, salt_bytes)
        
        if password_hash == stored_hash:
            self.authenticated = True
            return True
        
        print("Fehler: Falsches Master-Passwort.")
        return False
    
    def add_password_entry(self):
        """Fügt einen neuen Passwort-Eintrag hinzu."""
        print("\n=== Neuen Passwort-Eintrag hinzufügen ===")
        
        title = input("Titel/Name: ").strip()
        if not title:
            print("Fehler: Titel ist erforderlich.")
            return
        
        username = input("Benutzername (optional): ").strip()
        email = input("E-Mail (optional): ").strip()
        website = input("Website (optional): ").strip()
        
        password = getpass.getpass("Passwort: ")
        if not password:
            print("Fehler: Passwort ist erforderlich.")
            return
        
        password_confirm = getpass.getpass("Passwort bestätigen: ")
        if password != password_confirm:
            print("Fehler: Passwörter stimmen nicht überein.")
            return
        
        notes = input("Notizen (optional): ").strip()
        
        categories = self.db.get_categories()
        if categories:
            print(f"\nVorhandene Kategorien: {', '.join(categories)}")
        category = input("Kategorie (Standard: 'Allgemein'): ").strip() or "Allgemein"
        
        encrypted_password = self.encryption.encrypt(password)
        
        password_id = self.db.add_password(
            title=title,
            encrypted_password=encrypted_password,
            username=username,
            email=email,
            website=website,
            notes=notes,
            category=category
        )
        
        print(f"Passwort-Eintrag '{title}' wurde erfolgreich gespeichert (ID: {password_id}).")
    
    def list_passwords(self, category: str = ""):
        """Listet alle Passwörter auf."""
        passwords = self.db.get_all_passwords(category)
        
        if not passwords:
            print("\nKeine Passwort-Einträge gefunden.")
            return
        
        print("\n=== Gespeicherte Passwörter ===")
        print(f"{'ID':<4} {'Titel':<25} {'Benutzername':<20} {'Kategorie':<15} {'Favorit'}")
        print("-" * 80)
        
        for pwd in passwords:
            favorite = "★" if pwd['favorite'] else ""
            username = pwd['username'] or ""
            category = pwd['category'] or ""
            print(f"{pwd['id']:<4} {pwd['title'][:25]:<25} {username[:20]:<20} {category:<15} {favorite}")
    
    def search_passwords(self):
        """Durchsucht die Passwörter."""
        query = input("\nSuchbegriff: ").strip()
        if not query:
            print("Fehler: Suchbegriff ist erforderlich.")
            return
        
        passwords = self.db.search_passwords(query)
        
        if not passwords:
            print("\nKeine Passwörter gefunden.")
            return
        
        print(f"\n=== Suchergebnisse für '{query}' ===")
        print(f"{'ID':<4} {'Titel':<25} {'Benutzername':<20} {'Kategorie':<15}")
        print("-" * 70)
        
        for pwd in passwords:
            username = pwd['username'] or ""
            print(f"{pwd['id']:<4} {pwd['title'][:25]:<25} {username[:20]:<20} {pwd['category']}")
    
    def show_password_details(self):
        """Zeigt die Details eines Passworts an."""
        try:
            password_id = int(input("\nPasswort-ID: "))
        except ValueError:
            print("Fehler: Ungültige ID.")
            return
        
        password = self.db.get_password(password_id)
        if not password:
            print("Fehler: Passwort nicht gefunden.")
            return
        
        try:
            decrypted_password = self.encryption.decrypt(password['encrypted_password'])
        except Exception:
            print("Fehler: Passwort konnte nicht entschlüsselt werden.")
            return
        
        print(f"\n=== Passwort-Details (ID: {password_id}) ===")
        print(f"Titel:      {password['title']}")
        print(f"Benutzername: {password['username'] or '-'}")
        print(f"E-Mail:     {password['email'] or '-'}")
        print(f"Website:    {password['website'] or '-'}")
        print(f"Kategorie: {password['category']}")
        print(f"Passwort:   {decrypted_password}")
        print(f"Notizen:    {password['notes'] or '-'}")
        print(f"Erstellt:   {password['created_at']}")
        print(f"Aktualisiert: {password['updated_at']}")
        print(f"Favorit:    {'Ja' if password['favorite'] else 'Nein'}")
    
    def update_password_entry(self):
        """Aktualisiert einen Passwort-Eintrag."""
        try:
            password_id = int(input("\nZu aktualisierende Passwort-ID: "))
        except ValueError:
            print("Fehler: Ungültige ID.")
            return
        
        password = self.db.get_password(password_id)
        if not password:
            print("Fehler: Passwort nicht gefunden.")
            return
        
        print(f"Aktueller Titel: {password['title']}")
        new_title = input("Neuer Titel (leer lassen für behalten): ").strip()
        if not new_title:
            new_title = password['title']
        
        current_username = password['username'] or ""
        new_username = input(f"Neuer Benutzername (aktuell: '{current_username}', leer lassen für behalten): ").strip()
        if not new_username:
            new_username = password['username']
        
        current_email = password['email'] or ""
        new_email = input(f"Neue E-Mail (aktuell: '{current_email}', leer lassen für behalten): ").strip()
        if not new_email:
            new_email = password['email']
        
        current_website = password['website'] or ""
        new_website = input(f"Neue Website (aktuell: '{current_website}', leer lassen für behalten): ").strip()
        if not new_website:
            new_website = password['website']
        
        new_notes = input("Neue Notizen (leer lassen für behalten): ").strip()
        if not new_notes:
            new_notes = password['notes']
        
        new_category = input(f"Neue Kategorie (aktuell: '{password['category']}', leer lassen für behalten): ").strip()
        if not new_category:
            new_category = password['category']
        
        self.db.update_password(
            password_id,
            title=new_title,
            username=new_username,
            email=new_email,
            website=new_website,
            notes=new_notes,
            category=new_category
        )
        
        print("Passwort-Eintrag wurde aktualisiert.")
    
    def delete_password_entry(self):
        """Löscht einen Passwort-Eintrag."""
        try:
            password_id = int(input("\nZu löschende Passwort-ID: "))
        except ValueError:
            print("Fehler: Ungültige ID.")
            return
        
        password = self.db.get_password(password_id)
        if not password:
            print("Fehler: Passwort nicht gefunden.")
            return
        
        confirm = input(f"Sind Sie sicher, dass Sie '{password['title']}' löschen möchten? (j/N): ").strip().lower()
        if confirm != 'j':
            print("Löschvorgang abgebrochen.")
            return
        
        if self.db.delete_password(password_id):
            print("Passwort-Eintrag wurde gelöscht.")
        else:
            print("Fehler: Passwort konnte nicht gelöscht werden.")
    
    def toggle_favorite(self):
        """Schaltet den Favoriten-Status um."""
        try:
            password_id = int(input("\nPasswort-ID: "))
        except ValueError:
            print("Fehler: Ungültige ID.")
            return
        
        if self.db.toggle_favorite(password_id):
            print("Favoriten-Status wurde geändert.")
        else:
            print("Fehler: Passwort nicht gefunden.")
    
    def show_statistics(self):
        """Zeigt Statistiken an."""
        total = self.db.count_passwords()
        categories = self.db.get_categories()
        
        print("\n=== Passwort-Manager Statistiken ===")
        print(f"Gesamtzahl der Einträge: {total}")
        print(f"Anzahl der Kategorien: {len(categories)}")
        print(f"Kategorien: {', '.join(categories) if categories else 'Keine'}")


def main():
    """Hauptfunktion für das CLI-Interface."""
    manager = PasswordManager()
    
    print("=== Passwort-Manager ===")
    print("Bitte melden Sie sich an.")
    
    if not manager.authenticate():
        print("Authentifizierung fehlgeschlagen.")
        sys.exit(1)
    
    print("\nWillkommen im Passwort-Manager!")
    
    while True:
        print("\n" + "=" * 50)
        print("1.  Passwort hinzufügen")
        print("2.  Alle Passwörter anzeigen")
        print("3.  Passwort suchen")
        print("4.  Passwort-Details anzeigen")
        print("5.  Passwort aktualisieren")
        print("6.  Passwort löschen")
        print("7.  Favorit umschalten")
        print("8.  Statistiken anzeigen")
        print("q.  Beenden")
        print("=" * 50)
        
        choice = input("\nIhre Wahl: ").strip().lower()
        
        if choice == '1':
            manager.add_password_entry()
        elif choice == '2':
            category = input("Nach Kategorie filtern (leer für alle): ").strip()
            manager.list_passwords(category if category else "")
        elif choice == '3':
            manager.search_passwords()
        elif choice == '4':
            manager.show_password_details()
        elif choice == '5':
            manager.update_password_entry()
        elif choice == '6':
            manager.delete_password_entry()
        elif choice == '7':
            manager.toggle_favorite()
        elif choice == '8':
            manager.show_statistics()
        elif choice == 'q':
            print("Auf Wiedersehen!")
            break
        else:
            print("Ungültige Eingabe. Bitte erneut versuchen.")


if __name__ == "__main__":
    main()
