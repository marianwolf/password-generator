# Changelog

Alle bemerkenswerten Änderungen werden hier dokumentiert.

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
