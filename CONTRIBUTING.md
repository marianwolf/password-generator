# Beitrag zu Password Vault

Wir freuen uns über Beiträge zur Verbesserung dieser Anwendung! Bitte befolgen Sie diese Richtlinien.

## Einstieg

1. Forken Sie das Repository
2. Erstellen Sie einen Feature-Branch: `git checkout -b feature/ihre-feature`
3. Committen Sie Ihre Änderungen: `git commit -m 'Feature hinzufügen'`
4. Pushen Sie den Branch: `git push origin feature/ihre-feature`
5. Erstellen Sie einen Pull Request

## Coding-Standards

### Python (Backend)
- Folgen Sie PEP 8
- Nutzen Sie type hints
- Fügen Sie docstrings für alle Funktionen hinzu
- Führen Sie `flake8` und `pylint` aus

### JavaScript/React (Frontend)
- Folgen Sie ESLint-Konfiguration
- Nutzen Sie functional components mit hooks
- Fügen Sie PropTypes hinzu
- Schreiben Sie Tests für neue Komponenten

## Tests

Stellen Sie sicher, dass alle Tests bestehen:

```bash
# Backend
cd backend
pytest --cov=app

# Frontend
cd frontend
npm test -- --coverage
```

## Sicherheit

- Fügen Sie niemals sensible Daten (Passwörter, Keys) zum Repository hinzu
- Melden Sie Sicherheitsprobleme privat über security@beispiel.com
- Validieren Sie alle Benutzereingaben
- Nutzen Sie parameterisierte Queries

## Git Commit Messages

- Nutzen Sie die Gegenwartsform ("Add feature" nicht "Added feature")
- Beschreiben Sie den Grund für die Änderung
- Maximieren Sie 50 Zeichen in der Betreffzeile
- Referenzieren Sie Issues mit `#123`

## Code-Review

- Alle Pull Requests müssen von mindestens einem Maintainer genehmigt werden
- Automatische CI/CD-Checks müssen bestehen
- Dokumentation muss aktualisiert werden
