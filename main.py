#!/usr/bin/env python3
"""
Passwort-Manager - Moderne GUI-Anwendung
Ein sicherer Passwort-Manager mit moderner grafischer Oberfläche.
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from typing import Optional
from database import DatabaseManager
from encryption import EncryptionManager


class ModernApp(tk.Tk):
    """Moderne App-Oberfläche für den Passwort-Manager."""

    def __init__(self):
        super().__init__()

        self.title("Passwort-Manager")
        self.geometry("1000x700")
        self.configure(bg='#2d2d2d')

        # Stil-Konfiguration
        self.setup_styles()

        # Datenbank und Verschlüsselung
        self.db = DatabaseManager()
        self.encryption = None
        self.authenticated = False

        # Haupt-Layout
        self.setup_ui()

        # Authentifizierung prüfen
        self.after(100, self.check_authentication)

    def setup_styles(self):
        """Konfiguriert moderne Styles."""
        style = ttk.Style()
        style.theme_use('clam')

        # Frame Styles
        style.configure('App.TFrame', background='#2d2d2d')
        style.configure('Sidebar.TFrame', background='#1e1e1e')

        # Label Styles
        style.configure('App.TLabel', background='#2d2d2d', foreground='#ffffff', font=('Segoe UI', 10))
        style.configure('Title.TLabel', background='#1e1e1e', foreground='#4ec9b0', font=('Segoe UI', 14, 'bold'))
        style.configure('Section.TLabel', background='#2d2d2d', foreground='#888888', font=('Segoe UI', 9))

        # Button Styles
        style.configure('App.TButton', background='#3d3d3d', foreground='#ffffff', borderwidth=1, font=('Segoe UI', 10))
        style.map('App.TButton', background=[('active', '#4d4d4d')])

        style.configure('Primary.TButton', background='#007acc', foreground='#ffffff', font=('Segoe UI', 10, 'bold'))
        style.map('Primary.TButton', background=[('active', '#005a9e')])

        style.configure('Danger.TButton', background='#c42b1c', foreground='#ffffff')
        style.map('Danger.TButton', background=[('active', '#a01f14')])

        # Treeview Styles
        style.configure('App.Treeview', background='#3d3d3d', foreground='#ffffff', fieldbackground='#3d3d3d', font=('Segoe UI', 10))
        style.configure('App.Treeview.Heading', background='#404040', foreground='#ffffff', font=('Segoe UI', 10, 'bold'))

        # Notebook Style
        style.configure('App.TNotebook', background='#2d2d2d', borderwidth=0)
        style.configure('App.TNotebook.Tab', background='#3d3d3d', foreground='#ffffff', padding=[10, 5], font=('Segoe UI', 10))

    def setup_ui(self):
        """Richtet die Benutzeroberfläche ein."""
        # Hauptcontainer
        main_container = ttk.Frame(self, style='App.TFrame')
        main_container.pack(fill=tk.BOTH, expand=True)

        # Sidebar (links)
        self.sidebar = ttk.Frame(main_container, style='Sidebar.TFrame', width=200)
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y)
        self.sidebar.pack_propagate(False)

        self.setup_sidebar()

        # Hauptbereich (rechts)
        self.main_content = ttk.Frame(main_container, style='App.TFrame')
        self.main_content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=20, pady=20)

        self.setup_main_content()

    def setup_sidebar(self):
        """Richtet die Sidebar ein."""
        # Logo/Titel
        title_label = ttk.Label(self.sidebar, text="🔐 Passwort-Manager", style='Title.TLabel', wraplength=180)
        title_label.pack(pady=(20, 10), padx=10)

        # Navigations-Buttons
        nav_buttons = [
            ("📋 Alle Passwörter", self.show_all_passwords),
            ("➕ Neues Passwort", self.add_password),
            ("🔍 Suchen", self.show_search),
            ("⭐ Favoriten", self.show_favorites),
            ("📊 Statistiken", self.show_stats),
        ]

        for text, command in nav_buttons:
            btn = ttk.Button(self.sidebar, text=text, style='App.TButton', command=command)
            btn.pack(fill=tk.X, padx=10, pady=5)

        # Abstand
        spacer = ttk.Frame(self.sidebar, style='Sidebar.TFrame')
        spacer.pack(fill=tk.BOTH, expand=True)

        # Beenden-Button
        ttk.Button(self.sidebar, text="❌ Beenden", style='App.TButton', command=self.quit).pack(fill=tk.X, padx=10, pady=10)

    def setup_main_content(self):
        """Richtet den Hauptinhalt ein."""
        # Header
        self.header_label = ttk.Label(self.main_content, text="Alle Passwörter", style='App.TLabel', font=('Segoe UI', 18, 'bold'))
        self.header_label.pack(anchor='w', pady=(0, 20))

        # Suchfeld
        search_frame = ttk.Frame(self.main_content, style='App.TFrame')
        search_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(search_frame, text="🔍", style='App.TLabel').pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_var.trace('w', self.on_search)
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var, font=('Segoe UI', 11), width=40)
        self.search_entry.pack(side=tk.LEFT, padx=(10, 0), fill=tk.X, expand=True)

        # Filter-ComboBox
        ttk.Label(search_frame, text="Kategorie:", style='App.TLabel').pack(side=tk.LEFT, padx=(20, 5))
        self.category_var = tk.StringVar()
        self.category_combo = ttk.Combobox(search_frame, textvariable=self.category_var, font=('Segoe UI', 10), width=15)
        self.category_combo.pack(side=tk.LEFT)
        self.category_combo.bind('<<ComboboxSelected>>', self.on_category_filter)

        # Treeview (Passwortliste)
        columns = ('id', 'title', 'username', 'category', 'favorite', 'created')
        self.tree = ttk.Treeview(self.main_content, columns=columns, show='headings', style='App.Treeview', height=20)

        self.tree.heading('id', text='ID')
        self.tree.heading('title', text='Titel')
        self.tree.heading('username', text='Benutzername')
        self.tree.heading('category', text='Kategorie')
        self.tree.heading('favorite', text='⭐')
        self.tree.heading('created', text='Erstellt')

        self.tree.column('id', width=50, anchor='center')
        self.tree.column('title', width=200)
        self.tree.column('username', width=150)
        self.tree.column('category', width=100)
        self.tree.column('favorite', width=40, anchor='center')
        self.tree.column('created', width=100, anchor='center')

        # Scrollbar
        scrollbar = ttk.Scrollbar(self.main_content, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Action Buttons
        action_frame = ttk.Frame(self.main_content, style='App.TFrame')
        action_frame.pack(fill=tk.X, pady=(15, 0))

        ttk.Button(action_frame, text="👁️ Anzeigen", style='Primary.TButton', command=self.show_password_details).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(action_frame, text="✏️ Bearbeiten", style='App.TButton', command=self.edit_password).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(action_frame, text="⭐ Favorit", style='App.TButton', command=self.toggle_favorite).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(action_frame, text="🗑️ Löschen", style='Danger.TButton', command=self.delete_password).pack(side=tk.LEFT)

        # Status-Bar
        self.status_label = ttk.Label(self.main_content, text="Bereit", style='Section.TLabel')
        self.status_label.pack(anchor='e', pady=(10, 0))

        # Event-Bindings
        self.tree.bind('<Double-1>', lambda e: self.show_password_details())
        self.tree.bind('<Return>', lambda e: self.show_password_details())

    def check_authentication(self):
        """Prüft die Authentifizierung."""
        salt = self.db.get_salt()
        if not salt:
            self.show_setup_master_dialog()
        else:
            self.show_login_dialog()

    def show_setup_master_dialog(self):
        """Zeigt den Dialog zur Einrichtung des Master-Passworts."""
        dialog = tk.Toplevel(self)
        dialog.title("Master-Passwort einrichten")
        dialog.geometry("400x280")
        dialog.configure(bg='#2d2d2d')
        dialog.transient(self)
        dialog.grab_set()

        ttk.Label(dialog, text="🔐 Ersteinrichtung", style='Title.TLabel', wraplength=380).pack(pady=20)

        ttk.Label(dialog, text="Master-Passwort erstellen:", style='App.TLabel').pack()
        password1_entry = ttk.Entry(dialog, show="*", width=35)
        password1_entry.pack(pady=5)

        ttk.Label(dialog, text="Master-Passwort bestätigen:", style='App.TLabel').pack()
        password2_entry = ttk.Entry(dialog, show="*", width=35)
        password2_entry.pack(pady=5)

        ttk.Label(dialog, text="⚠️ Das Passwort muss mindestens 8 Zeichen haben", style='Section.TLabel').pack(pady=5)

        def save_password():
            password1 = password1_entry.get()
            password2 = password2_entry.get()

            if password1 != password2:
                messagebox.showerror("Fehler", "Passwörter stimmen nicht überein.", parent=dialog)
                return

            if len(password1) < 8:
                messagebox.showerror("Fehler", "Das Passwort muss mindestens 8 Zeichen lang sein.", parent=dialog)
                return

            password_hash = EncryptionManager.hash_password(password1)
            salt = EncryptionManager.hash_password(password1 + str(hash(password1)))[:32].encode()

            self.db.set_master_password_hash(password_hash, salt)
            messagebox.showinfo("Erfolg", "Master-Passwort erfolgreich eingerichtet!", parent=dialog)
            dialog.destroy()
            self.show_login_dialog()

        ttk.Button(dialog, text="Speichern", style='Primary.TButton', command=save_password).pack(pady=20)
        password1_entry.focus_set()

    def show_login_dialog(self):
        """Zeigt den Anmeldedialog."""
        dialog = tk.Toplevel(self)
        dialog.title("Anmelden")
        dialog.geometry("350x200")
        dialog.configure(bg='#2d2d2d')
        dialog.transient(self)
        dialog.grab_set()

        ttk.Label(dialog, text="🔐 Anmeldung", style='Title.TLabel').pack(pady=20)

        ttk.Label(dialog, text="Master-Passwort:", style='App.TLabel').pack()
        password_entry = ttk.Entry(dialog, show="*", width=35)
        password_entry.pack(pady=10)

        def login():
            password = password_entry.get()
            stored_hash = self.db.get_master_password_hash()
            salt = self.db.get_salt()

            password_hash = EncryptionManager.hash_password(password)

            if password_hash == stored_hash:
                self.encryption = EncryptionManager(password, salt if salt else b"default")
                self.authenticated = True
                dialog.destroy()
                self.refresh_password_list()
            else:
                messagebox.showerror("Fehler", "Falsches Master-Passwort.", parent=dialog)

        ttk.Button(dialog, text="Anmelden", style='Primary.TButton', command=login).pack(pady=15)
        password_entry.bind('<Return>', lambda e: login())
        password_entry.focus_set()

    def refresh_password_list(self, category_filter=""):
        """Aktualisiert die Passwortliste."""
        # Alle Kinder löschen
        for item in self.tree.get_children():
            self.tree.delete(item)

        passwords = self.db.get_all_passwords(category_filter)
        for pwd in passwords:
            favorite = "⭐" if pwd['favorite'] else ""
            username = pwd['username'] or ""
            created = str(pwd['created_at'][:10]) if pwd['created_at'] else ""
            self.tree.insert('', tk.END, values=(
                pwd['id'],
                pwd['title'],
                username,
                pwd['category'] or '',
                favorite,
                created
            ))

        # Kategorien aktualisieren
        self.update_categories()

        # Status aktualisieren
        total = len(passwords)
        self.status_label.config(text=f"{total} Einträge")

    def update_categories(self):
        """Aktualisiert die Kategorien-Liste."""
        categories = ["Alle"] + self.db.get_categories()
        self.category_combo['values'] = categories
        if self.category_var.get():
            self.category_var.set(self.category_var.get())
        else:
            self.category_var.set("Alle")

    def on_search(self, *args):
        """Sucht Passwörter."""
        query = self.search_var.get().strip()
        category = self.category_var.get()

        if category == "Alle":
            category = ""

        if query:
            passwords = self.db.search_passwords(query)
        else:
            passwords = self.db.get_all_passwords(category)

        # Treeview aktualisieren
        for item in self.tree.get_children():
            self.tree.delete(item)

        for pwd in passwords:
            favorite = "⭐" if pwd['favorite'] else ""
            username = pwd['username'] or ""
            created = str(pwd['created_at'][:10]) if pwd['created_at'] else ""
            self.tree.insert('', tk.END, values=(
                pwd['id'],
                pwd['title'],
                username,
                pwd['category'] or '',
                favorite,
                created
            ))

    def on_category_filter(self, event):
        """Filtert nach Kategorie."""
        category = self.category_var.get()
        if category == "Alle":
            category = ""
        self.refresh_password_list(category)

    def show_all_passwords(self):
        """Zeigt alle Passwörter."""
        self.header_label.config(text="Alle Passwörter")
        self.category_var.set("Alle")
        self.refresh_password_list()

    def show_search(self):
        """Zeigt die Suche."""
        self.header_label.config(text="🔍 Suchen")
        self.search_entry.focus_set()

    def show_favorites(self):
        """Zeigt Favoriten."""
        self.header_label.config(text="⭐ Favoriten")

        for item in self.tree.get_children():
            self.tree.delete(item)

        # Alle Passwörter holen und nach Favoriten filtern
        all_passwords = self.db.get_all_passwords()
        favorites = [p for p in all_passwords if p['favorite']]

        for pwd in favorites:
            favorite = "⭐"
            username = pwd['username'] or ""
            created = str(pwd['created_at'][:10]) if pwd['created_at'] else ""
            self.tree.insert('', tk.END, values=(
                pwd['id'],
                pwd['title'],
                username,
                pwd['category'] or '',
                favorite,
                created
            ))

        self.status_label.config(text=f"{len(favorites)} Favoriten")

    def show_stats(self):
        """Zeigt Statistiken."""
        total = self.db.count_passwords()
        categories = self.db.get_categories()

        stats_text = f"""
📊 Statistiken
═══════════════

Gesamtzahl der Einträge: {total}
Anzahl der Kategorien: {len(categories)}

Kategorien:
{chr(10).join('• ' + c for c in categories) if categories else 'Keine Kategorien'}
"""

        messagebox.showinfo("Statistiken", stats_text.strip())

    def get_selected_password_id(self):
        """Gibt die ID des ausgewählten Passworts zurück."""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Auswahl", "Bitte wählen Sie einen Eintrag aus.")
            return None
        return int(self.tree.item(selected[0])['values'][0])

    def show_password_details(self):
        """Zeigt die Passwort-Details."""
        password_id = self.get_selected_password_id()
        if not password_id:
            return

        password = self.db.get_password(password_id)
        if not password:
            messagebox.showerror("Fehler", "Passwort nicht gefunden.")
            return

        try:
            decrypted_password = self.encryption.decrypt(password['encrypted_password'])
        except Exception:
            messagebox.showerror("Fehler", "Passwort konnte nicht entschlüsselt werden.")
            return

        details = f"""
📋 Passwort-Details
═══════════════════

Titel:      {password['title']}
Benutzername: {password['username'] or '-'}
E-Mail:     {password['email'] or '-'}
Website:    {password['website'] or '-'}
Passwort:   {decrypted_password}
Kategorie: {password['category']}
Notizen:    {password['notes'] or '-'}
Favorit:    {'Ja ⭐' if password['favorite'] else 'Nein'}
Erstellt:   {password['created_at']}
Aktualisiert: {password['updated_at']}
"""

        # Kopieren-Button hinzufügen
        dialog = tk.Toplevel(self)
        dialog.title(f"Passwort - {password['title']}")
        dialog.geometry("450x400")
        dialog.configure(bg='#2d2d2d')
        dialog.transient(self)

        ttk.Label(dialog, text=f"📋 {password['title']}", style='Title.TLabel').pack(pady=15)

        # Passwort anzeigen mit Kopieren-Button
        password_frame = ttk.Frame(dialog, style='App.TFrame')
        password_frame.pack(fill=tk.X, padx=20, pady=10)

        ttk.Label(password_frame, text="Passwort:", style='App.TLabel').pack(anchor='w')
        ttk.Label(password_frame, text=decrypted_password, style='App.TLabel', font=('Consolas', 12)).pack(anchor='w', pady=5)

        def copy_password():
            self.clipboard_clear()
            self.clipboard_append(decrypted_password)
            messagebox.showinfo("Kopiert", "Passwort in die Zwischenablage kopiert!", parent=dialog)

        ttk.Button(password_frame, text="📋 Kopieren", style='Primary.TButton', command=copy_password).pack(anchor='e')

        # Details
        details_frame = ttk.Frame(dialog, style='App.TFrame')
        details_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        info = [
            ("Benutzername:", password['username'] or '-'),
            ("E-Mail:", password['email'] or '-'),
            ("Website:", password['website'] or '-'),
            ("Kategorie:", password['category']),
            ("Notizen:", password['notes'] or '-'),
        ]

        for label, value in info:
            row = ttk.Frame(details_frame, style='App.TFrame')
            row.pack(fill=tk.X, pady=2)
            ttk.Label(row, text=label, style='Section.TLabel', width=12, anchor='e').pack(side=tk.LEFT)
            ttk.Label(row, text=value, style='App.TLabel').pack(side=tk.LEFT, padx=(10, 0))

        ttk.Button(dialog, text="Schließen", style='App.TButton', command=dialog.destroy).pack(pady=15)

    def add_password(self):
        """Fügt ein neues Passwort hinzu."""
        dialog = tk.Toplevel(self)
        dialog.title("Neues Passwort")
        dialog.geometry("450x450")
        dialog.configure(bg='#2d2d2d')
        dialog.transient(self)

        ttk.Label(dialog, text="➕ Neues Passwort", style='Title.TLabel').pack(pady=15)

        entries = {}
        fields = [
            ('Titel/Name:', True),
            ('Benutzername (optional):', False),
            ('E-Mail (optional):', False),
            ('Website (optional):', False),
            ('Passwort:', True),
            ('Notizen (optional):', False),
            ('Kategorie:', False),
        ]

        for label, required in fields:
            frame = ttk.Frame(dialog, style='App.TFrame')
            frame.pack(fill=tk.X, padx=20, pady=(10, 0))
            ttk.Label(frame, text=label, style='App.TLabel').pack(anchor='w')

            if 'Passwort' in label:
                entry = ttk.Entry(frame, show="*", width=40)
            else:
                entry = ttk.Entry(frame, width=40)
            entry.pack(fill=tk.X, pady=(5, 0))
            entries[label] = entry

        def save():
            title = entries['Titel/Name:'].get().strip()
            if not title:
                messagebox.showerror("Fehler", "Titel ist erforderlich.", parent=dialog)
                return

            password = entries['Passwort:'].get()
            if not password:
                messagebox.showerror("Fehler", "Passwort ist erforderlich.", parent=dialog)
                return

            encrypted_password = self.encryption.encrypt(password)

            category = entries['Kategorie:'].get().strip() or "Allgemein"

            password_id = self.db.add_password(
                title=title,
                encrypted_password=encrypted_password,
                username=entries['Benutzername (optional):'].get().strip(),
                email=entries['E-Mail (optional):'].get().strip(),
                website=entries['Website (optional):'].get().strip(),
                notes=entries['Notizen (optional):'].get().strip(),
                category=category
            )

            messagebox.showinfo("Erfolg", f"Passwort '{title}' wurde gespeichert!", parent=dialog)
            dialog.destroy()
            self.refresh_password_list()

        button_frame = ttk.Frame(dialog, style='App.TFrame')
        button_frame.pack(fill=tk.X, padx=20, pady=20)
        ttk.Button(button_frame, text="Speichern", style='Primary.TButton', command=save).pack(side=tk.RIGHT, padx=(10, 0))
        ttk.Button(button_frame, text="Abbrechen", style='App.TButton', command=dialog.destroy).pack(side=tk.RIGHT)

        entries['Titel/Name:'].focus_set()

    def edit_password(self):
        """Bearbeitet ein Passwort."""
        password_id = self.get_selected_password_id()
        if not password_id:
            return

        password = self.db.get_password(password_id)
        if not password:
            messagebox.showerror("Fehler", "Passwort nicht gefunden.")
            return

        dialog = tk.Toplevel(self)
        dialog.title(f"Passwort bearbeiten - {password['title']}")
        dialog.geometry("450x450")
        dialog.configure(bg='#2d2d2d')
        dialog.transient(self)

        ttk.Label(dialog, text=f"✏️ Bearbeiten: {password['title']}", style='Title.TLabel').pack(pady=15)

        entries = {}
        fields = [
            ('Titel:', password['title'] or ''),
            ('Benutzername:', password['username'] or ''),
            ('E-Mail:', password['email'] or ''),
            ('Website:', password['website'] or ''),
            ('Notizen:', password['notes'] or ''),
            ('Kategorie:', password['category'] or 'Allgemein'),
        ]

        for label, default in fields:
            frame = ttk.Frame(dialog, style='App.TFrame')
            frame.pack(fill=tk.X, padx=20, pady=(10, 0))
            ttk.Label(frame, text=label, style='App.TLabel').pack(anchor='w')
            entry = ttk.Entry(frame, width=40)
            entry.insert(0, default)
            entry.pack(fill=tk.X, pady=(5, 0))
            entries[label] = entry

        def save():
            self.db.update_password(
                password_id,
                title=entries['Titel:'].get().strip(),
                username=entries['Benutzername:'].get().strip(),
                email=entries['E-Mail:'].get().strip(),
                website=entries['Website:'].get().strip(),
                notes=entries['Notizen:'].get().strip(),
                category=entries['Kategorie:'].get().strip() or "Allgemein"
            )
            messagebox.showinfo("Erfolg", "Passwort wurde aktualisiert!", parent=dialog)
            dialog.destroy()
            self.refresh_password_list()

        button_frame = ttk.Frame(dialog, style='App.TFrame')
        button_frame.pack(fill=tk.X, padx=20, pady=20)
        ttk.Button(button_frame, text="Speichern", style='Primary.TButton', command=save).pack(side=tk.RIGHT, padx=(10, 0))
        ttk.Button(button_frame, text="Abbrechen", style='App.TButton', command=dialog.destroy).pack(side=tk.RIGHT)

    def toggle_favorite(self):
        """Schaltet den Favoriten-Status um."""
        password_id = self.get_selected_password_id()
        if not password_id:
            return

        if self.db.toggle_favorite(password_id):
            self.refresh_password_list()
            self.status_label.config(text="Favorit aktualisiert")

    def delete_password(self):
        """Löscht ein Passwort."""
        password_id = self.get_selected_password_id()
        if not password_id:
            return

        password = self.db.get_password(password_id)
        if not password:
            messagebox.showerror("Fehler", "Passwort nicht gefunden.")
            return

        confirm = messagebox.askyesno("Bestätigung", f"Sind Sie sicher, dass Sie '{password['title']}' löschen möchten?")
        if not confirm:
            return

        if self.db.delete_password(password_id):
            messagebox.showinfo("Erfolg", "Passwort wurde gelöscht.")
            self.refresh_password_list()
        else:
            messagebox.showerror("Fehler", "Passwort konnte nicht gelöscht werden.")


def main():
    """Hauptfunktion."""
    app = ModernApp()
    app.mainloop()


if __name__ == "__main__":
    main()
