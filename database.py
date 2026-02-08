"""
Datenbankmodul für den Passwort-Manager.
Verwendet SQLite für die lokale Speicherung.
"""

import sqlite3
import os
from datetime import datetime
from typing import Optional, List, Dict, Any


class DatabaseManager:
    """Verwaltet die SQLite-Datenbank für den Passwort-Manager."""
    
    def __init__(self, db_path: str = "passwords.db"):
        """
        Initialisiert den DatabaseManager.
        
        Args:
            db_path: Pfad zur SQLite-Datenbank
        """
        self.db_path = db_path
        self._init_db()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Gibt eine Verbindung zur Datenbank zurück."""
        return sqlite3.connect(self.db_path)
    
    def _init_db(self):
        """Initialisiert die Datenbank mit den erforderlichen Tabellen."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Tabelle für Master-Passwort-Hash
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')
        
        # Tabelle für Passwörter
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                username TEXT,
                email TEXT,
                encrypted_password TEXT NOT NULL,
                website TEXT,
                notes TEXT,
                category TEXT DEFAULT 'Allgemein',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                favorite INTEGER DEFAULT 0
            )
        ''')
        
        # Index für schnellere Suche
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_passwords_title 
            ON passwords(title)
        ''')
        
        conn.commit()
        conn.close()
    
    # Settings-Methoden
    def set_master_password_hash(self, password_hash: str, salt: bytes):
        """Speichert den Master-Passwort-Hash und Salt."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            'INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)',
            ('master_password_hash', password_hash)
        )
        cursor.execute(
            'INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)',
            ('salt', salt.hex())
        )
        conn.commit()
        conn.close()
    
    def get_master_password_hash(self) -> Optional[str]:
        """Gibt den gespeicherten Master-Passwort-Hash zurück."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            'SELECT value FROM settings WHERE key = ?',
            ('master_password_hash',)
        )
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None
    
    def get_salt(self) -> Optional[bytes]:
        """Gibt den gespeicherten Salt zurück."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            'SELECT value FROM settings WHERE key = ?',
            ('salt',)
        )
        result = cursor.fetchone()
        conn.close()
        return bytes.fromhex(result[0]) if result else None
    
    # Password-Methoden
    def add_password(self, title: str, encrypted_password: str,
                     username: str = "", email: str = "",
                     website: str = "", notes: str = "",
                     category: str = "Allgemein", favorite: int = 0) -> int:
        """
        Fügt ein neues Passwort hinzu.
        
        Returns:
            Die ID des neuen Eintrags
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO passwords (title, username, email, encrypted_password, 
                                   website, notes, category, favorite)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (title, username, email, encrypted_password, website, 
              notes, category, favorite))
        password_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return password_id
    
    def get_password(self, password_id: int) -> Optional[Dict[str, Any]]:
        """Holt ein Passwort anhand der ID."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM passwords WHERE id = ?', (password_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                'id': row[0],
                'title': row[1],
                'username': row[2],
                'email': row[3],
                'encrypted_password': row[4],
                'website': row[5],
                'notes': row[6],
                'category': row[7],
                'created_at': row[8],
                'updated_at': row[9],
                'favorite': row[10]
            }
        return None
    
    def update_password(self, password_id: int, **kwargs) -> bool:
        """Aktualisiert ein bestehendes Passwort."""
        if not kwargs:
            return False
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        allowed_fields = ['title', 'username', 'email', 'encrypted_password',
                          'website', 'notes', 'category', 'favorite']
        updates = []
        values = []
        
        for field, value in kwargs.items():
            if field in allowed_fields:
                updates.append(f"{field} = ?")
                values.append(value)
        
        if not updates:
            return False
        
        values.append(password_id)
        query = f'''
            UPDATE passwords SET {', '.join(updates)}, 
            updated_at = CURRENT_TIMESTAMP WHERE id = ?
        '''
        cursor.execute(query, values)
        conn.commit()
        conn.close()
        return cursor.rowcount > 0
    
    def delete_password(self, password_id: int) -> bool:
        """Löscht ein Passwort."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM passwords WHERE id = ?', (password_id,))
        conn.commit()
        conn.close()
        return cursor.rowcount > 0
    
    def get_all_passwords(self, category: str = "") -> List[Dict[str, Any]]:
        """Holt alle Passwörter, optional gefiltert nach Kategorie."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        if category:
            cursor.execute('SELECT * FROM passwords WHERE category = ? ORDER BY favorite DESC, title', (category,))
        else:
            cursor.execute('SELECT * FROM passwords ORDER BY favorite DESC, title')
        
        rows = cursor.fetchall()
        conn.close()
        
        passwords = []
        for row in rows:
            passwords.append({
                'id': row[0],
                'title': row[1],
                'username': row[2],
                'email': row[3],
                'encrypted_password': row[4],
                'website': row[5],
                'notes': row[6],
                'category': row[7],
                'created_at': row[8],
                'updated_at': row[9],
                'favorite': row[10]
            })
        return passwords
    
    def search_passwords(self, query: str) -> List[Dict[str, Any]]:
        """Durchsucht Passwörter nach Titel, Benutzername oder Website."""
        conn = self._get_connection()
        cursor = conn.cursor()
        search_term = f'%{query}%'
        cursor.execute('''
            SELECT * FROM passwords 
            WHERE title LIKE ? OR username LIKE ? OR website LIKE ?
            ORDER BY favorite DESC, title
        ''', (search_term, search_term, search_term))
        
        rows = cursor.fetchall()
        conn.close()
        
        passwords = []
        for row in rows:
            passwords.append({
                'id': row[0],
                'title': row[1],
                'username': row[2],
                'email': row[3],
                'encrypted_password': row[4],
                'website': row[5],
                'notes': row[6],
                'category': row[7],
                'created_at': row[8],
                'updated_at': row[9],
                'favorite': row[10]
            })
        return passwords
    
    def get_categories(self) -> List[str]:
        """Gibt alle vorhandenen Kategorien zurück."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT DISTINCT category FROM passwords')
        categories = [row[0] for row in cursor.fetchall()]
        conn.close()
        return categories
    
    def toggle_favorite(self, password_id: int) -> bool:
        """Schaltet den Favoriten-Status um."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE passwords SET favorite = NOT favorite, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
            (password_id,)
        )
        conn.commit()
        conn.close()
        return cursor.rowcount > 0
    
    def count_passwords(self) -> int:
        """Gibt die Anzahl der gespeicherten Passwörter zurück."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM passwords')
        count = cursor.fetchone()[0]
        conn.close()
        return count
