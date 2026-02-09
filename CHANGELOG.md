# Changelog

Alle bemerkenswerten Änderungen werden hier dokumentiert.

## [1.1.0] - 2024-02-09

### Neu hinzugefügt

#### Secure Vault System
- **Vault-Implementierung** (`backend/vault.py`): Neues Modul für sicheres Speichern von sensiblen Konfigurationen
- **Verschlüsselung**: AES-256-GCM für sichere Verschlüsselung auf der Festplatte
- **Vault-Migration**: Automatische Migration von .env-Dateien in den Vault
- **Audit-Logging**: Sicheres Logging aller Vault-Zugriffe ohne sensible Daten
- **Fallback-Strategie**: Robuste Fehlerbehandlung bei Vault-Unverfügbarkeit
- **Master-Key-Rotation**: Möglichkeit zur Rotation des Master-Verschlüsselungsschlüssels

#### Flask-Integration
- Vault wird beim Systemstart initialisiert
- Konfiguration wird aus dem Vault geladen
- Fallback auf Umgebungsvariablen bei Vault-Fehlern

### Aktualisiert

#### Frontend
- React: 18.2.0 → 18.3.1
- react-router-dom: 6.20.0 → 6.22.0
- axios: 1.6.2 → 1.7.7
- lucide-react: 0.294.0 → 0.451.0
- date-fns: 2.30.0 → 3.6.0
- @testing-library/react: 14.1.0 → 14.2.0
- @testing-library/jest-dom: 6.1.5 → 6.4.0
- eslint: 8.55.0 → 8.57.0

#### Backend
- Flask: 3.0.0 → 3.0.3
- Flask-CORS: 4.0.0 → 4.0.1
- SQLAlchemy: 2.0.23 → 2.0.25
- SQLAlchemy-Utils: 0.41.1 → 0.41.2
- PyJWT: 2.8.0 → 2.9.0
- cryptography: 41.0.7 → 43.0.1
- pytest: 7.4.3 → 7.4.4
- gunicorn: 21.2.0 → 22.0.0
- python-dotenv: 1.0.0 → 1.0.1

### Sicherheit
- **Vault**: Verschlüsselter Speicher für alle sensiblen Daten
- Keine Credentials in .env-Dateien (werden in Vault migriert)
- Sensible Daten niemals in Logs
- Automatische .env-Löschung nach Migration
- PBKDF2-Hash für Master-Passwort (480.000 Iterationen)

### Konfiguration
- Neue `.env.example` mit vollständigen Umgebungsvariablen
- `REACT_APP_API_URL` Umgebungsvariable für Frontend
- VAULT_MASTER_PASSWORD für Vault-Initialisierung

### Bekannte Probleme
- react-scripts 5.0.1 hat noch bekannte Sicherheitsrisiken (requires major update zu Create React App 6)

## [1.0.0] - 2024-01-XX

### Hinzugefügt
- Initial Release
- Benutzerauthentifizierung mit JWT
- Passwort-Verschlüsselung mit AES-256
- Passwort-Generator
- Kategorisierung von Passwörtern
- Favoriten-System
- Audit-Logging
- Dark Mode Support
- Responsive Design
- Docker-Support mit Multi-Stage Builds
- RESTful API
- Import/Export-Funktionalität
- Session-Management mit Timeout

### Sicherheit
- Passwort-Hashing mit bcrypt
- Verschlüsselungsschlüssel nie auf dem Server gespeichert
- SQL-Injection-Schutz
- CORS-Konfiguration
- Security Headers

### Technisch
- Flask Backend mit SQLAlchemy
- React Frontend
- SQLite für Datenbank
- Gunicorn als WSGI-Server
- Nginx als Reverse Proxy

## Roadmap

- [ ] Zwei-Faktor-Authentifizierung (2FA)
- [ ] Browser-Erweiterung
- [ ] Mobile App
- [ ] Cloud-Synchronisation
- [ ] PostgreSQL-Support
- [ ] Mehrbenutzer-Support mit Teams
