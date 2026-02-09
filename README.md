# Password Vault

Eine sichere, Docker-basierte Passwort-Verwaltungsanwendung mit modernem Frontend und robustem Backend. Verwalten Sie Ihre Passwörter, Logins und sensiblen Daten mit militärischer AES-256-Verschlüsselung und einem mehrschichtigen Sicherheitskonzept.

## Inhaltsverzeichnis

1. [Überblick](#überblick)
2. [Features](#features)
3. [Technologie-Stack](#technologie-stack)
4. [Schnellstart](#schnellstart)
5. [Architektur](#architektur)
6. [API-Dokumentation](#api-dokumentation)
7. [Frontend-Dokumentation](#frontend-dokumentation)
8. [Konfiguration](#konfiguration)
9. [Sicherheit](#sicherheit)
10. [Entwicklung](#entwicklung)
11. [Deployment](#deployment)
12. [Fehlerbehebung](#fehlerbehebung)
13. [Lizenz](#lizenz)
14. [Beitrag](#beitrag)

---

## Überblick

Password Vault ist eine vollständige Passwort-Management-Lösung, die entwickelt wurde, um Benutzern eine sichere und benutzerfreundliche Möglichkeit zu bieten, ihre digitalen Zugangsdaten zu verwalten. Die Anwendung basiert auf dem Zero-Knowledge-Prinzip, bei dem Ihre Daten nur mit Ihrem Master-Passwort entschlüsselt werden können.

### Warum Password Vault?

- **Sicherheit an erster Stelle**: AES-256-Verschlüsselung, sichere Passwort-Hashing und umfassendes Audit-Logging
- **Benutzerfreundlich**: Modernes, intuitives Interface mit Dark Mode und Responsive Design
- **Flexibilität**: Docker-Ready für einfaches Deployment, aber auch für lokale Entwicklung geeignet
- **Transparenz**: Vollständige Nachverfolgung aller Aktionen und Zugriffe

### Zielgruppe

- Privatpersonen, die ihre persönlichen Passwörter sicher verwalten möchten
- Kleine Teams, die gemeinsame Zugangsdaten sicher teilen müssen
- Entwickler, die eine sichere Passwort-Management-Lösung in ihre Projekte integrieren möchten

---

## Features

### Kernfunktionen

| Feature | Beschreibung |
|---------|--------------|
| **Sichere Verschlüsselung** | Alle Passwörter werden mit AES-256 (Fernet) verschlüsselt, bevor sie gespeichert werden. Die Verschlüsselung erfolgt auf dem Server, aber nur mit dem Master-Passwort können die Daten entschlüsselt werden. |
| **Master-Passwort** | Der Benutzer stellt den Verschlüsselungsschlüssel bereit. Dieses Passwort wird niemals auf dem Server gespeichert und verlässt niemals das Gerät des Benutzers in unverschlüsselter Form. |
| **JWT-Authentifizierung** | Sichere API-Authentifizierung mit Access- und Refresh-Tokens. Tokens haben eine konfigurierbare Lebensdauer und können bei Bedarf widerrufen werden. |
| **Passwort-Generator** | Generieren Sie starke, zufällige Passwörter mit anpassbarer Länge und Komplexität. Der Generator verwendet kryptographisch sichere Zufallszahlen. |
| **Audit-Logging** | Vollständige Nachverfolgung aller Aktionen, einschließlich Anmeldungen, Passwort-Zugriffe, Änderungen und mehr. Jeder Zugriff wird mit Zeitstempel, IP-Adresse und User-Agent protokolliert. |
| **Session-Management** | Automatische Session-Invalidierung nach Inaktivität (Standard: 30 Minuten). Alle aktiven Sessions können eingesehen und bei Bedarf widerrufen werden. |

### Benutzerinterface

| Feature | Beschreibung |
|---------|--------------|
| **Dark Mode** | Modernes, augenschonendes Design für komfortables Arbeiten bei verschiedenen Lichtverhältnissen. Die Einstellung wird automatisch im Browser gespeichert. |
| **Responsive Design** | Funktioniert nahtlos auf Desktop, Tablet und Mobile. Die Oberfläche passt sich automatisch an verschiedene Bildschirmgrößen an. |
| **Passwort-Stärke** | Echtzeit-Analyse der Passwortstärke mit dem zxcvbn-Algorithmus. Visualisierung von Schwachstellen und Verbesserungsvorschlägen. |
| **Kategorisierung** | Organisieren Sie Ihre Passwörter in Kategorien wie Login, Kreditkarte, Identität, sichere Notizen und andere. |
| **Favoriten** | Markieren Sie häufig verwendete Passwörter als Favoriten für schnellen Zugriff. |
| **Suchfunktion** | Durchsuchen Sie Ihre gesamte Passwort-Datenbank nach Titel, Benutzername, URL oder Notizen. |

### Sicherheitsfunktionen

- **Verschlüsselung im Ruhezustand**: Alle Passwörter werden verschlüsselt in der Datenbank gespeichert
- **Sichere Passwort-Hashing**: Verwendung von Werkzeug.security für sicheres Passwort-Hashing
- **Zwei-Faktor-Authentifizierung (vorbereitet)**: Unterstützung für 2FA ist in der Datenbank vorbereitet
- **SQL-Injection-Schutz**: SQLAlchemy ORM und SQLite-Pragmas für maximale Sicherheit
- **CORS-Schutz**: Konfigurierbare Cross-Origin Resource Sharing-Richtlinien
- **Rate Limiting**: Schutz vor Brute-Force-Angriffen durch Session-Management

### Datenschutz

- **Zero-Knowledge-Architektur**: Der Server kennt niemals das Master-Passwort des Benutzers
- **Minimale Datensammlung**: Es werden nur die absolut notwendigen Daten erfasst
- **Lokale Verarbeitung**: Alle Verschlüsselungsoperationen können lokal erfolgen
- **Export/Import**: Möglichkeit zur vollständigen Datenextraktion in verschlüsseltem Format

---

## Technologie-Stack

### Backend

| Technologie | Version | Beschreibung |
|-------------|---------|--------------|
| **Python** | 3.11+ | Moderne, lesbare Programmiersprache mit starker Unterstützung für Sicherheit und Kryptographie |
| **Flask** | 2.3+ | Leichtgewichtiges Web-Framework mit modularer Architektur |
| **Flask-SQLAlchemy** | 3.1+ | ORM für sichere Datenbankinteraktionen |
| **Flask-JWT-Extended** | 4.6+ | Erweiterte JWT-Unterstützung mit Refresh-Tokens |
| **Flask-CORS** | 4.0+ | Cross-Origin Resource Sharing-Unterstützung |
| **Cryptography** | 41.0+ | Industriestandard-Bibliothek für Verschlüsselung |
| **Marshmallow** | 3.20+ | Schema-basierte Datenvalidierung |
| **Fernet** | Teil von cryptography | Symmetrische AES-128-Verschlüsselung |

### Frontend

| Technologie | Version | Beschreibung |
|-------------|---------|--------------|
| **React** | 18.3+ | Moderne UI-Bibliothek für interaktive Benutzeroberflächen |
| **React Router** | 6.22+ | Clientseitiges Routing für Single-Page-Application |
| **Axios** | 1.7+ | HTTP-Client für API-Kommunikation |
| **zxcvbn** | 4.4+ | Passwort-Stärke-Analyse |
| **Lucide React** | 0.451+ | Moderne Icon-Bibliothek |
| **date-fns** | 3.6+ | Datumsformatierung und -manipulation |
| **CSS3** | - | Moderne Styling-Techniken mit CSS Variables |

### Infrastructure

| Technologie | Beschreibung |
|-------------|--------------|
| **Docker** | Containerisierung für konsistente Umgebungen |
| **Docker Compose** | Multi-Container-Orchestrierung |
| **Nginx** | Webserver und Reverse-Proxy für das Frontend |
| **SQLite** | Leichte, serverlose Datenbank |
| **Gunicorn** | WSGI-Server für Flask-Produktionsdeployment |

---

## Schnellstart

### Voraussetzungen

Bevor Sie beginnen, stellen Sie sicher, dass die folgenden Voraussetzungen erfüllt sind:

| Voraussetzung | Empfohlene Version | Hinweis |
|---------------|-------------------|---------|
| **Docker** | 20.10+ | [Installationsanleitung](https://docs.docker.com/get-docker/) |
| **Docker Compose** | 2.0+ | [Installationsanleitung](https://docs.docker.com/compose/install/) |
| **Git** | 2.0+ | Für das Klonen des Repositories |

### Installation mit Docker (empfohlen)

Die schnellste Methode, Password Vault einzurichten, ist die Verwendung von Docker Compose:

**Schritt 1: Repository klonen**

```bash
git clone https://github.com/marianwolf/password-generator.git
cd password-generator
```

**Schritt 2: Umgebungsvariablen konfigurieren**

Erstellen Sie die Umgebungsvariablen-Datei aus dem Beispiel:

```bash
cp .env.example .env
```

Bearbeiten Sie die `.env`-Datei mit sicheren Werten:

```bash
# Flask Secret Key (mindestens 32 Zeichen)
SECRET_KEY=dein_geheimer_schluessel_hier

# JWT Signatur-Schlüssel
JWT_SECRET_KEY=dein_jwt_schluessel_hier

# AES-Verschlüsselungsschlüssel (Fernet-Key, 44 Zeichen)
ENCRYPTION_KEY=dein_verschluesselungsschluessel_hier

# Datenbankpfad
DATABASE_PATH=/app/data/vault.db

# Token-Gültigkeitsdauer
JWT_ACCESS_TOKEN_EXPIRES_HOURS=1
JWT_REFRESH_TOKEN_EXPIRES_DAYS=7
```

**Schritt 3: Anwendung starten**

```bash
docker-compose up -d
```

Dieser Befehl startet alle drei Services:
- **Backend**: Flask API auf Port 5000
- **Frontend**: Nginx mit React-App auf Port 3000
- **Datenpersistenz**: Alpine-Basis für Datenbankdateien

**Schritt 4: Im Browser öffnen**

Öffnen Sie Ihren Browser und navigieren Sie zu:
```
http://localhost:3000
```

Sie sollten nun die Password Vault-Anwendung sehen und sich registrieren können.

### Lokale Entwicklung ohne Docker

Für die Entwicklung können Sie die Anwendung auch lokal ausführen:

**Backend einrichten:**

```bash
cd backend
python -m venv venv
source venv/bin/activate  # Unter Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

**Frontend einrichten:**

```bash
cd frontend
npm install
npm start
```

Das Frontend wird dann unter `http://localhost:3000` und das Backend unter `http://localhost:5000` verfügbar sein.

---

## Architektur

### Systemarchitektur

```
┌─────────────────────────────────────────────────────────────────┐
│                        Benutzer Browser                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Nginx Reverse Proxy                         │
│                   (Port 3000 für Frontend)                      │
└─────────────────────────────────────────────────────────────────┘
                              │
            ┌─────────────────┴─────────────────┐
            ▼                                   ▼
┌─────────────────────┐           ┌─────────────────────────────┐
│    React Frontend   │           │      Flask Backend          │
│   (Single Page App) │           │      (Port 5000)            │
│                     │           │                             │
│  - AuthContext      │◄─────────►│  - REST API                 │
│  - ThemeContext     │   JWT     │  - JWT Authentication       │
│  - Components       │           │  - AES-256 Encryption       │
│  - API Services     │           │  - SQLite Database          │
└─────────────────────┘           └─────────────────────────────┘
                                          │
                                          ▼
                               ┌─────────────────────┐
                               │    Secure Vault    │
                               │  (vault.py)        │
                               │                     │
                               │  - AES-256-GCM     │
                               │  - PBKDF2 Key Der. │
                               │  - Audit Logging   │
                               └─────────────────────┘
```

### Datenbankmodell

Die Anwendung verwendet die folgenden Datenbankmodelle:

#### User (Benutzer)
- `id`: Primärschlüssel
- `email`: Eindeutige E-Mail-Adresse (indiziert)
- `password_hash`: Gehashtes Login-Passwort
- `master_password_hash`: Gehashtes Master-Passwort
- `two_factor_enabled`: 2FA-Status
- `two_factor_secret`: 2FA-Geheimnis
- `created_at`: Erstellungszeitpunkt
- `last_login`: Letzter Login-Zeitpunkt
- `is_active`: Kontostatus

#### UserSession (Benutzersitzung)
- `id`: Primärschlüssel
- `user_id`: Fremdschlüssel zum Benutzer
- `session_token`: Eindeutiger Session-Token (indiziert)
- `device_info`: Browser-/Geräteinformationen
- `ip_address`: IP-Adresse
- `created_at`: Erstellungszeitpunkt
- `last_activity`: Letzte Aktivität
- `expires_at`: Ablaufdatum
- `is_active`: Session-Status

#### PasswordEntry (Passworteintrag)
- `id`: Primärschlüssel
- `user_id`: Fremdschlüssel zum Benutzer
- `title`: Titel des Eintrags
- `username`: Benutzername (optional)
- `encrypted_password**: Verschlüsseltes Passwort
- `website_url`: Website-URL (optional)
- `notes`: Zusätzliche Notizen (optional)
- `category`: Kategorie (login, credit_card, identity, secure_note, other)
- `is_favorite`: Favoritenstatus
- `password_strength`: Passwortstärke-Score
- `expiry_date`: Ablaufdatum (optional)

#### AuditLog (Prüfprotokoll)
- `id`: Primärschlüssel
- `user_id`: Fremdschlüssel zum Benutzer (optional für system actions)
- `action`: Aktionstyp
- `resource_type`: Ressourcentyp
- `resource_id`: Ressourcen-ID
- `ip_address`: IP-Adresse
- `user_agent`: User-Agent-String
- `details`: Zusätzliche Details
- `timestamp`: Zeitstempel

### Verschlüsselungsarchitektur

Die Verschlüsselung erfolgt in mehreren Schichten:

1. **Master-Passwort-Derivation**: Das Master-Passwort wird mit PBKDF2-HMAC-SHA256 (480.000 Iterationen) und einem zufälligen Salt in einen 256-Bit-Schlüssel umgewandelt.

2. **Fernet-Verschlüsselung**: Passwörter werden mit Fernet (AES-128 im CBC-Modus mit PKCS7-Padding und HMAC für Authentifizierung) verschlüsselt.

3. **Vault-Verschlüsselung**: Sensible Konfigurationen werden mit AES-256-GCM verschlüsselt, einem authentifizierten Verschlüsselungsmodus.

4. **Transit-Verschlüsselung**: Alle API-Kommunikation erfolgt über HTTPS mit TLS 1.3.

---

## API-Dokumentation

Die REST-API bietet die folgenden Endpunkte:

### Gesundheitsprüfung

| Methode | Endpunkt | Beschreibung |
|---------|----------|--------------|
| GET | `/health` | Gesundheitsprüfung des Servers |

**Antwort:**
```json
{
    "status": "healthy",
    "timestamp": "2024-01-15T10:30:00Z"
}
```

### Authentifizierung

| Methode | Endpunkt | Beschreibung |
|---------|----------|--------------|
| POST | `/api/v1/auth/register` | Neuen Benutzer registrieren |
| POST | `/api/v1/auth/login` | Benutzer anmelden |
| POST | `/api/v1/auth/logout` | Benutzer abmelden |
| POST | `/api/v1/auth/refresh` | Access-Token erneuern |
| GET | `/api/v1/auth/me` | Aktuellen Benutzer abrufen |

#### Registrierung

**Anfrage:**
```json
{
    "email": "benutzer@beispiel.de",
    "password": "sicheresPasswort123",
    "master_password": "masterPasswort456"
}
```

**Antwort (Erfolg):**
```json
{
    "message": "Registration successful",
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "user": {
        "id": 1,
        "email": "benutzer@beispiel.de",
        "two_factor_enabled": false,
        "created_at": "2024-01-15T10:30:00Z"
    }
}
```

**Antwort (Fehler):**
```json
{
    "error": "Email already registered"
}
```

#### Anmeldung

**Anfrage:**
```json
{
    "email": "benutzer@beispiel.de",
    "password": "sicheresPasswort123"
}
```

### Passwörter

| Methode | Endpunkt | Beschreibung |
|---------|----------|--------------|
| GET | `/api/v1/passwords` | Alle Passwörter auflisten |
| POST | `/api/v1/passwords` | Neues Passwort erstellen |
| GET | `/api/v1/passwords/<id>` | Passwort abrufen |
| PUT | `/api/v1/passwords/<id>` | Passwort aktualisieren |
| DELETE | `/api/v1/passwords/<id>` | Passwort löschen |
| POST | `/api/v1/passwords/generate` | Passwort generieren |

#### Passwort erstellen

**Anfrage:**
```json
{
    "title": "Google Account",
    "username": "benutzer@gmail.com",
    "password": "sicheresPasswort123",
    "website_url": "https://google.com",
    "notes": "Primary Google Account",
    "category": "login",
    "is_favorite": false
}
```

**Antwort (Erfolg):**
```json
{
    "id": 1,
    "title": "Google Account",
    "username": "benutzer@gmail.com",
    "website_url": "https://google.com",
    "notes": "Primary Google Account",
    "category": "login",
    "is_favorite": false,
    "created_at": "2024-01-15T10:30:00Z",
    "updated_at": "2024-01-15T10:30:00Z",
    "password_strength": 85
}
```

#### Passwort generieren

**Anfrage:**
```json
{
    "length": 20,
    "use_uppercase": true,
    "use_numbers": true,
    "use_symbols": true
}
```

**Antwort:**
```json
{
    "password": "Ab3$7kL9!pQ2@mN5xW8",
    "strength": 95,
    "strength_label": "Very Strong"
}
```

### Audit-Logs

| Methode | Endpunkt | Beschreibung |
|---------|----------|--------------|
| GET | `/api/v1/audit` | Audit-Logs abrufen |
| GET | `/api/v1/audit/<id>` | Bestimmten Audit-Log abrufen |

### Sessions

| Methode | Endpunkt | Beschreibung |
|---------|----------|--------------|
| GET | `/api/v1/sessions` | Alle aktiven Sessions abrufen |
| DELETE | `/api/v1/sessions/<id>` | Session widerrufen |
| DELETE | `/api/v1/sessions` | Alle Sessions widerrufen |

### Backup & Export

| Methode | Endpunkt | Beschreibung |
|---------|----------|--------------|
| POST | `/api/v1/backup/export` | Daten exportieren |
| POST | `/api/v1/backup/import` | Daten importieren |

### Fehlercodes

| Code | Beschreibung |
|------|--------------|
| 200 | Erfolg |
| 201 | Erstellt |
| 400 | Ungültige Anfrage |
| 401 | Nicht autorisiert |
| 403 | Verboten |
| 404 | Nicht gefunden |
| 409 | Konflikt |
| 500 | Interner Serverfehler |

---

## Frontend-Dokumentation

### Projektstruktur

```
frontend/
├── public/
│   └── index.html
├── src/
│   ├── components/
│   │   ├── AuditLogs.js      # Audit-Log-Anzeige
│   │   ├── Dashboard.js       # Hauptübersicht
│   │   ├── Layout.js          # Hauptlayout mit Navigation
│   │   ├── Login.js           # Anmeldeformular
│   │   ├── PasswordForm.js    # Passwort-Formular
│   │   ├── PasswordGenerator.js  # Passwort-Generator
│   │   ├── PasswordList.js    # Passwort-Liste
│   │   ├── Register.js        # Registrierungsformular
│   │   └── Settings.js        # Einstellungen
│   ├── context/
│   │   ├── AuthContext.js    # Authentifizierungskontext
│   │   └── ThemeContext.js    # Theme-Kontext (Dark Mode)
│   ├── services/
│   │   └── api.js            # API-Service
│   ├── App.js
│   ├── App.css
│   ├── index.js
│   └── index.css
├── package.json
└── Dockerfile
```

### Komponenten

#### AuthContext

Der AuthContext verwaltet den gesamten Authentifizierungszustand der Anwendung:

```javascript
// Verwendung
const { user, login, logout, isAuthenticated } = useAuth();
```

**Funktionen:**
- `login(email, password)`: Anmeldung
- `logout()`: Abmeldung
- `register(email, password, masterPassword)`: Registrierung
- `refreshToken()`: Token erneuern
- `isAuthenticated`: Boolean-Status

#### ThemeContext

Der ThemeContext verwaltet das Design der Anwendung:

```javascript
// Verwendung
const { theme, toggleTheme } = useTheme();
```

**Funktionen:**
- `theme`: 'light' oder 'dark'
- `toggleTheme()`: Theme umschalten
- `prefersDarkMode`: Systempräferenz erkennen

#### Dashboard

Das Dashboard zeigt eine Übersicht über alle Passwörter:

- Statistiken (Gesamtzahl, Kategorien, Favoriten)
- Zuletzt verwendete Passwörter
- Passwortstärke-Übersicht
- Schnellaktionen

#### PasswordList

Die Passwort-Liste zeigt alle gespeicherten Passwörter:

- Durchsuchbare Liste
- Filter nach Kategorie
- Sortierung nach Name, Datum, Stärke
- Favoriten-Filter
- Bulk-Aktionen

#### PasswordGenerator

Der Passwort-Generator erstellt sichere Passwörter:

- Anpassbare Länge (8-128 Zeichen)
- Großbuchstaben ein/aus
- Zahlen ein/aus
- Sonderzeichen ein/aus
- Echtzeit-Stärkeanalyse
- Ein-Klick-Kopie

#### AuditLogs

Die Audit-Log-Anzeige zeigt alle protokollierten Aktionen:

- Filter nach Aktionstyp
- Filter nach Zeitraum
- Export-Funktion
- Detailansicht

### API-Service

Der API-Service (api.js) bietet eine zentrale Schnittstelle zur Backend-API:

```javascript
import api from './services/api';

// Konfiguration
api.defaults.baseURL = 'http://localhost:5000';
api.defaults.headers.common['Authorization'] = `Bearer ${token}`;

// Anfragen
const response = await api.get('/api/v1/passwords');
const response = await api.post('/api/v1/auth/login', credentials);
```

**Funktionen:**
- `api.get(url)`: GET-Anfrage
- `api.post(url, data)`: POST-Anfrage
- `api.put(url, data)`: PUT-Anfrage
- `api.delete(url)`: DELETE-Anfrage
- `api.interceptors`: Anfrage-/Antwort-Interceptors

---

## Konfiguration

### Umgebungsvariablen

| Variable | Beschreibung | Standard | Erforderlich |
|----------|--------------|----------|--------------|
| `SECRET_KEY` | Flask Secret Key für Session-Signierung | Auto-generiert (32 Hex-Zeichen) | Nein* |
| `JWT_SECRET_KEY` | JWT Signatur-Schlüssel | Auto-generiert | Nein* |
| `JWT_ACCESS_TOKEN_EXPIRES_HOURS` | Gültigkeitsdauer des Access-Tokens in Stunden | 1 | Nein |
| `JWT_REFRESH_TOKEN_EXPIRES_DAYS` | Gültigkeitsdauer des Refresh-Tokens in Tagen | 7 | Nein |
| `ENCRYPTION_KEY` | AES-Verschlüsselungsschlüssel (Fernet-Key) | Auto-generiert | Nein* |
| `DATABASE_PATH` | Pfad zur SQLite-Datenbank | `data/vault.db` | Nein |
| `VAULT_MASTER_PASSWORD` | Master-Passwort für den Vault | - | Nein |
| `ALLOWED_ORIGINS` | Erlaubte CORS-Origins (kommagetrennt) | `*` | Nein |
| `FLASK_ENV` | Flask-Umgebung (development/production) | `production` | Nein |

*In Produktion sollten diese Werte unbedingt manuell gesetzt werden!

### Docker Compose

Die `docker-compose.yml` enthält die folgenden Services:

#### Backend Service

```yaml
backend:
  build: ./backend
  ports:
    - "5000:5000"
  volumes:
    - backend_data:/app/data
    - ./backend/logs:/app/logs
  environment:
    - SECRET_KEY=${SECRET_KEY}
    - JWT_SECRET_KEY=${JWT_SECRET_KEY}
    - ENCRYPTION_KEY=${ENCRYPTION_KEY}
    - DATABASE_PATH=/app/data/vault.db
  depends_on:
    - db
  restart: unless-stopped
```

#### Frontend Service

```yaml
frontend:
  build: ./frontend
  ports:
    - "3000:80"
  depends_on:
    - backend
  restart: unless-stopped
```

#### Database Service

```yaml
db:
  image: alpine:latest
  volumes:
    - backend_data:/app/data
  command: ["sh", "-c", "mkdir -p /app/data && touch /app/data/vault.db"]
  restart: unless-stopped
```

### Vault-Konfiguration

Password Vault verwendet einen sicheren Vault für die Speicherung sensibler Konfigurationen:

**Vault-Funktionen:**
- Verschlüsselung aller Secrets auf der Festplatte
- Nur entschlüsselt im Arbeitsspeicher
- Automatische .env-Migration
- Sicheres Audit-Logging
- Fallback-Strategie bei Nichtverfügbarkeit

**Vault-Befehle:**
```bash
# Vault mit interaktiver Eingabe entsperren
python -c "from vault import Vault; v = Vault(); v.unlock()"

# Vault-Status prüfen
python -c "from vault import Vault; v = Vault(); print(f'Initialized: {v._is_initialized}, Unlocked: {v._is_unlocked}')"
```

---

## Sicherheit

### Verschlüsselungsdetails

#### Master-Passwort-Derivation

Das Master-Passwort wird mit PBKDF2-HMAC-SHA256 deriviert:

```python
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,  # 256-Bit-Schlüssel
    salt=secrets.token_bytes(16),  # 128-Bit-Salt
    iterations=480000,  # OWASP-Empfehlung
)
key = kdf.derive(password.encode())
```

#### Passwort-Verschlüsselung

Passwörter werden mit Fernet verschlüsselt:

```python
from cryptography.fernet import Fernet

# Schlüsselgenerierung
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Verschlüsselung
encrypted = cipher_suite.encrypt(password.encode())

# Entschlüsselung
decrypted = cipher_suite.decrypt(encrypted)
```

#### Vault-Verschlüsselung

Sensitive Konfigurationen werden mit AES-256-GCM verschlüsselt:

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Verschlüsselung
nonce = secrets.token_bytes(12)  # 96-Bit-Nonce
encrypted = cipher.encrypt(nonce, data.encode(), None)

# Entschlüsselung
decrypted = cipher.decrypt(nonce, encrypted, None)
```

### Sicherheitsempfehlungen

#### Für die Produktion

1. **Master-Passwort**: Wählen Sie ein starkes, einzigartiges Master-Passwort mit mindestens 16 Zeichen, das Groß- und Kleinbuchstaben, Zahlen sowie Sonderzeichen enthält.

2. **Umgebungsvariablen**: Überschreiben Sie alle auto-generierten Schlüssel in der `.env`-Datei. Verwenden Sie keine Standardwerte.

3. **SSL/TLS**: Aktivieren Sie HTTPS für alle Verbindungen. In Docker können Sie Let's Encrypt mit Nginx verwenden.

4. **Regelmäßige Backups**: Exportieren Sie Ihre Daten regelmäßig und speichern Sie Backups an einem sicheren, separaten Ort.

5. **Firewall**: Konfigurieren Sie eine Firewall, die nur die erforderlichen Ports (80, 443) zulässt.

6. **Monitoring**: Implementieren Sie Logging und Monitoring, um verdächtige Aktivitäten zu erkennen.

7. **Updates**: Halten Sie alle Komponenten auf dem neuesten Stand, insbesondere die Verschlüsselungsbibliotheken.

#### Passwort-Richtlinien

- **Master-Passwort**: Mindestens 16 Zeichen, keine Wörterbuchwörter, regelmäßig ändern
- **Login-Passwort**: Mindestens 8 Zeichen, aber verwenden Sie den Passwort-Generator
- **Verschlüsselungsschlüssel**: 44-Zeichen-Fernet-Key (Base64-codiert)

### Sicherheitsüberprüfungen

Die Anwendung implementiert die folgenden Sicherheitsmaßnahmen:

| Maßnahme | Implementierung |
|----------|-----------------|
| SQL-Injection | SQLAlchemy ORM mit parametrisierten Queries |
| XSS-Schutz | React's automatische Escaping |
| CSRF-Schutz | SameSite-Cookies, JWT in Headers |
| Rate Limiting | Session-Management mit automatischer Sperrung |
| Input-Validierung | Marshmallow-Schemas |
| Audit-Logging | Vollständige Nachverfolgung aller Aktionen |
| Sichere Cookies | HttpOnly, Secure, SameSite |
| Verschlüsselung | AES-256, PBKDF2, HMAC |

### Zero-Knowledge-Architektur

Password Vault implementiert das Zero-Knowledge-Prinzip:

1. Das Master-Passwort wird niemals auf dem Server gespeichert
2. Alle Verschlüsselung erfolgt auf dem Client oder im verschlüsselten Vault
3. Der Server kann die gespeicherten Passwörter nicht lesen
4. Selbst bei einem Datenbank-Diebstahl sind alle Passwörter sicher

---

## Entwicklung

### Lokale Entwicklung

#### Backend-Setup

```bash
# Virtuelle Umgebung erstellen
cd backend
python -m venv venv

# Aktivieren (Linux/Mac)
source venv/bin/activate

# Aktivieren (Windows)
venv\Scripts\activate

# Abhängigkeiten installieren
pip install -r requirements.txt

# Anwendung starten
python app.py
```

#### Frontend-Setup

```bash
# Abhängigkeiten installieren
cd frontend
npm install

# Entwicklungssserver starten
npm start
```

### Tests ausführen

#### Backend-Tests

```bash
cd backend
pytest -v
pytest --cov=app  # Mit Code-Coverage
pytest -k "test_password"  # Bestimmte Tests ausführen
```

#### Frontend-Tests

```bash
cd frontend
npm test
npm test -- --coverage  # Mit Code-Coverage
npm test -- --watchAll=false  # Einmalig ausführen
```

### Code-Qualität

#### Linting

```bash
# Backend (mit flake8)
cd backend
flake8 app.py --max-line-length=100 --ignore=E501,W503

# Frontend (mit ESLint)
cd frontend
npm run lint
```

#### Formatierung

```bash
# Backend (mit black)
cd backend
black app.py

# Frontend (mit Prettier)
cd frontend
npx prettier --write src/
```

### Entwicklungstools

- **Flask Debug Toolbar**: Für Backend-Debugging
- **React DevTools**: Für Frontend-Debugging
- **Browser DevTools**: Für Netzwerk- und Console-Analyse
- **Postman/Insomnia**: Für API-Tests

---

## Deployment

### Docker Deployment (empfohlen)

#### Produktions-Build

```bash
# Alle Services bauen und starten
docker-compose -f docker-compose.prod.yml up -d

# Mit Docker Swarm
docker stack deploy -c docker-compose.yml password-vault
```

#### Umgebung für Produktion

Erstellen Sie eine `docker-compose.prod.yml`:

```yaml
version: '3.8'

services:
  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    ports:
      - "5000:5000"
    environment:
      - FLASK_ENV=production
      - SECRET_KEY=${SECRET_KEY}
      - JWT_SECRET_KEY=${JWT_SECRET_KEY}
      - ENCRYPTION_KEY=${ENCRYPTION_KEY}
    volumes:
      - backend_data:/app/data
      - backend_logs:/app/logs
    restart: always
    
  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    ports:
      - "80:80"
    depends_on:
      - backend
    restart: always
    
  db:
    image: alpine:latest
    volumes:
      - backend_data:/app/data
    command: ["sh", "-c", "mkdir -p /app/data"]
    restart: always

volumes:
  backend_data:
  backend_logs:
```

### Cloud Deployment

#### AWS

1. **EC2**: Installieren Sie Docker und führen Sie docker-compose aus
2. **ECS**: Verwenden Sie Fargate für serverloses Deployment
3. **RDS**: Erwägen Sie PostgreSQL für Produktionsdatenbanken
4. **S3**: Für Backup-Speicherung
5. **CloudFront**: Für CDN-Unterstützung

#### Google Cloud Platform

1. **Cloud Run**: Serverloses Container-Deployment
2. **Cloud SQL**: Verwaltete PostgreSQL-Datenbank
3. **Secret Manager**: Für sichere Konfiguration

#### DigitalOcean

1. **Droplet**: Docker-optimiertes Droplet
2. **App Platform**: Für automatisiertes Deployment
3. **Managed Databases**: Für Datenbank-Hosting

### Nginx-Konfiguration für HTTPS

```nginx
server {
    listen 80;
    server_name password-vault.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name password-vault.example.com;
    
    ssl_certificate /etc/letsencrypt/live/password-vault.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/password-vault.example.com/privkey.pem;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_protocols TLSv1.2 TLSv1.3;
    
    location / {
        root /var/www/html;
        try_files $uri $uri/ /index.html;
    }
    
    location /api {
        proxy_pass http://backend:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

### Backup-Strategie

#### Automatische Backups

```bash
# Cron-Job für tägliche Backups
0 2 * * * docker exec password-vault-backend-1 python -c "from app import export_data; export_data()" >> /var/log/backup.log 2>&1
```

#### Backup-Skript

```python
#!/usr/bin/env python3
import os
import datetime
from app import app, db

def export_data():
    with app.app_context():
        # Export all passwords (encrypted)
        passwords = PasswordEntry.query.all()
        data = {
            'export_date': datetime.datetime.now().isoformat(),
            'passwords': [p.to_dict() for p in passwords]
        }
        
        # Save to file
        filename = f"backup_{datetime.date.today()}.json.enc"
        with open(filename, 'w') as f:
            json.dump(data, f)
        
        return filename
```

---

## Fehlerbehebung

### Häufige Probleme

#### Docker-Probleme

**Problem**: Container startet nicht
```bash
# Logs anzeigen
docker-compose logs backend

# Container-Neustart
docker-compose restart backend

# Alle Container stoppen und neu starten
docker-compose down && docker-compose up -d
```

**Problem**: Port bereits belegt
```bash
# Port 5000 prüfen
netstat -tulpn | grep :5000

# docker-compose.yml anpassen
ports:
  - "5001:5000"  # Anderen Port verwenden
```

#### Datenbankprobleme

**Problem**: Datenbank-Fehler
```bash
# Datenbank reparieren
cd backend
sqlite3 instance/data/vault.db ".recover"
```

**Problem**: Migrationsfehler
```bash
# Datenbank löschen und neu erstellen (alle Daten gehen verloren!)
rm instance/data/vault.db
docker-compose restart backend
```

#### Authentifizierungsprobleme

**Problem**: JWT-Token-Fehler
```bash
# Token manuell überprüfen
python -c "import jwt; print(jwt.decode('token', 'secret', algorithms=['HS256']))"
```

**Problem**: Session abgelaufen
- Melden Sie sich ab und erneut an
- Prüfen Sie die Systemzeit auf Ihrem Server

#### Performance-Probleme

**Problem**: Langsame Ladezeiten
- Aktivieren Sie Caching im Browser
- Verwenden Sie einen CDN für statische Assets
- Optimieren Sie die Datenbank mit Indizes

### Logs

| Log-Datei | Beschreibung |
|-----------|--------------|
| `backend/logs/vault.log` | Hauptanwendungs-Logs |
| `backend/logs/vault_audit.log` | Vault-Audit-Logs |
| `docker-compose logs backend` | Docker-Container-Logs |

### Debug-Modus

Aktivieren Sie den Debug-Modus für detaillierte Fehlermeldungen:

```yaml
# docker-compose.yml
backend:
  environment:
    - FLASK_ENV=development
    - FLASK_DEBUG=1
```

**Warnung**: Aktivieren Sie den Debug-Modus niemals in der Produktion!

---

## Lizenz

Password Vault ist unter der MIT-Lizenz lizenziert - see [LICENSE](LICENSE) for details.

### MIT-Lizenz (Kurzfassung)

Diese Lizenz erlaubt Ihnen:
- Die Software kostenlos zu nutzen
- Die Software zu modifizieren
- Die Software zu verteilen
- Kommerzielle Nutzung

Die Lizenz erfordert lediglich:
- Eine Kopie der Lizenz beilegen
- Urheberrechtshinweis beibehalten

---

## Beitrag

Beiträge sind willkommen! Bitte lesen Sie [CONTRIBUTING.md](CONTRIBUTING.md) für detaillierte Informationen.

### Möglichkeiten zur Mitarbeit

- **Fehler melden**: Nutzen Sie GitHub Issues
- **Funktionsvorschläge**: Diskutieren Sie neue Features in Discussions
- **Code beitragen**: Pull Requests willkommen
- **Dokumentation verbessern**: README, Code-Kommentare
- **Übersetzungen**: Sprachunterstützung erweitern

### Entwicklungsrichtlinien

1. Fork erstellen
2. Feature-Branch erstellen (`git checkout -b feature/amazing-feature`)
3. Änderungen committen (`git commit -m 'Add amazing feature'`)
4. Branch pushen (`git push origin feature/amazing-feature`)
5. Pull Request öffnen

### Coding-Standards

- **Python**: PEP 8, Type Hints verwenden
- **JavaScript**: ES6+, Prettier-Formatierung
- **Commits**: Conventional Commits verwenden
- **Tests**: Mindestens 80% Code-Coverage

---

## Support

### Hilfe erhalten

- **Dokumentation**: Lesen Sie diese README und die Wiki
- **Issues**: Suchen Sie nach ähnlichen Problemen
- **FAQ**: Häufige Fragen werden hier beantwortet
- **Diskussion**: Stellen Sie Fragen in GitHub Discussions

### Kontakt

- **GitHub Issues**: Für Fehlerberichte und Feature-Anfragen
- **Discussions**: Für Fragen und Diskussionen
- **Security**: Sicherheitsprobleme bitte privat melden

---

**Letzte Aktualisierung**: Januar 2024
