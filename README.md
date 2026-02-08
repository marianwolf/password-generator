# Password Vault

Eine sichere, Docker-basierte Passwort-Verwaltungsanwendung mit modernem Frontend und robustem Backend.

## Features

- **Sichere Verschlüsselung**: Alle Passwörter werden mit AES-256 verschlüsselt
- **Master-Passwort**: Der Benutzer stellt den Verschlüsselungsschlüssel bereit
- **JWT-Authentifizierung**: Sichere API-Authentifizierung mit Token-Refresh
- **Audit-Logging**: Vollständige Nachverfolgung aller Aktionen
- **Passwort-Generator**: Starke, zufällige Passwörter generieren
- **Dark Mode**: Modernes, augenschonendes Design
- **Responsive Design**: Funktioniert auf Desktop und Mobile
- **Docker-ready**: Einfaches Deployment mit Docker Compose

## Schnellstart

### Voraussetzungen

- Docker & Docker Compose
- Git

### Installation

1. Repository klonen:
```bash
git clone https://github.com/your-username/password-generator.git
cd password-generator
```

2. Umgebungsvariablen konfigurieren:
```bash
cp .env.example .env
# Bearbeiten Sie die .env-Datei mit sicheren Werten
```

3. Anwendung starten:
```bash
docker-compose up -d
```

4. Im Browser öffnen:
```
http://localhost:3000
```

## Konfiguration

### Umgebungsvariablen

| Variable | Beschreibung | Standard |
|----------|--------------|----------|
| `SECRET_KEY` | Flask Secret Key | Auto-generiert |
| `JWT_SECRET_KEY` | JWT Signatur-Schlüssel | Auto-generiert |
| `ENCRYPTION_KEY` | AES-Verschlüsselungsschlüssel | Auto-generiert |
| `DATABASE_PATH` | Pfad zur SQLite-Datenbank | `/app/data/vault.db` |

### Docker Compose

Die `docker-compose.yml` enthält drei Services:

- **backend**: Flask API auf Port 5000
- **frontend**: Nginx mit React-App auf Port 3000
- **db**: Alpine-Basis für Datenpersistenz

## Entwicklung

### Lokale Entwicklung

```bash
# Backend starten
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py

# Frontend starten
cd frontend
npm install
npm start
```

### Tests ausführen

```bash
# Backend Tests
cd backend
pytest

# Frontend Tests
cd frontend
npm test
```

## Sicherheit

### Empfehlungen

1. **Master-Passwort**: Wählen Sie ein starkes, einzigartiges Master-Passwort
2. **Umgebungsvariablen**: Überschreiben Sie alle Auto-generierten Schlüssel in Produktion
3. **SSL/TLS**: Aktivieren Sie HTTPS für alle Verbindungen
4. **Regelmäßige Backups**: Exportieren Sie Ihre Daten regelmäßig

### Verschlüsselung

- Passwörter werden mit Fernet (symmetrische AES-128-Verschlüsselung) gespeichert
- Der Verschlüsselungsschlüssel wird aus dem Master-Passwort abgeleitet
- Alle Übertragungen erfolgen über HTTPS

## Lizenz

MIT License - see [LICENSE](LICENSE) for details.

## Beitrag

Beiträge sind willkommen! Bitte lesen Sie [CONTRIBUTING.md](CONTRIBUTING.md).
