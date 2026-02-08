import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import { sessionApi, exportApi } from '../services/api';
import { format } from 'date-fns';
import { de } from 'date-fns/locale';
import { Moon, Sun, Download, Trash2, AlertTriangle, Check, X } from 'lucide-react';

export default function Settings() {
    const { user } = useAuth();
    const { theme, toggleTheme, isDark } = useTheme();
    const [sessions, setSessions] = useState([]);
    const [loading, setLoading] = useState(true);
    const [toast, setToast] = useState(null);

    useEffect(() => {
        loadSessions();
    }, []);

    const loadSessions = async () => {
        try {
            const response = await sessionApi.getSessions();
            setSessions(response.data.sessions);
        } catch (error) {
            console.error('Failed to load sessions:', error);
        } finally {
            setLoading(false);
        }
    };

    const showToast = (message, type = 'success') => {
        setToast({ message, type });
        setTimeout(() => setToast(null), 3000);
    };

    const revokeSession = async (id) => {
        try {
            await sessionApi.revokeSession(id);
            showToast('Sitzung beendet');
            loadSessions();
        } catch (error) {
            showToast('Sitzung konnte nicht beendet werden', 'error');
        }
    };

    const handleExport = async () => {
        try {
            const response = await exportApi.export();
            const blob = new Blob([JSON.stringify(response.data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `password-vault-export-${format(new Date(), 'yyyy-MM-dd')}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            showToast('Daten exportiert');
        } catch (error) {
            showToast('Export fehlgeschlagen', 'error');
        }
    };

    const handleImport = async (e) => {
        const file = e.target.files[0];
        if (!file) return;

        try {
            const text = await file.text();
            const data = JSON.parse(text);
            await exportApi.import(data);
            showToast('Daten importiert');
        } catch (error) {
            showToast('Import fehlgeschlagen', 'error');
        }
    };

    if (loading) {
        return (
            <div className="loading-container">
                <div className="loading-spinner"></div>
                <p>Wird geladen...</p>
            </div>
        );
    }

    return (
        <div className="animate-fade-in">
            <h1 className="page-title" style={{ marginBottom: '1.5rem' }}>
                Einstellungen
            </h1>

            {/* Appearance */}
            <div className="settings-section">
                <h3>Erscheinungsbild</h3>
                <div className="settings-row">
                    <div>
                        <div className="settings-label">Design</div>
                        <div className="settings-description">
                            Wählen Sie zwischen hellem und dunklem Modus
                        </div>
                    </div>
                    <button
                        className="btn btn-secondary"
                        onClick={toggleTheme}
                    >
                        {isDark ? <Sun size={18} /> : <Moon size={18} />}
                        {isDark ? 'Heller Modus' : 'Dunkler Modus'}
                    </button>
                </div>
            </div>

            {/* Profile */}
            <div className="settings-section">
                <h3>Profil</h3>
                <div className="settings-row">
                    <div>
                        <div className="settings-label">E-Mail-Adresse</div>
                        <div className="settings-description">{user?.email}</div>
                    </div>
                </div>
                <div className="settings-row">
                    <div>
                        <div className="settings-label">Zwei-Faktor-Authentifizierung</div>
                        <div className="settings-description">
                            {user?.two_factor_enabled ? 'Aktiviert' : 'Deaktiviert'}
                        </div>
                    </div>
                    <button className="btn btn-secondary">
                        {user?.two_factor_enabled ? 'Deaktivieren' : 'Aktivieren'}
                    </button>
                </div>
            </div>

            {/* Sessions */}
            <div className="settings-section">
                <h3>Aktive Sitzungen</h3>
                {sessions.length === 0 ? (
                    <p style={{ color: 'var(--text-secondary)' }}>Keine aktiven Sitzungen</p>
                ) : (
                    <div>
                        {sessions.map((session) => (
                            <div key={session.id} className="settings-row">
                                <div>
                                    <div className="settings-label">{session.device_info || 'Unbekanntes Gerät'}</div>
                                    <div className="settings-description">
                                        Zuletzt aktiv: {format(new Date(session.last_activity), 'PPp', { locale: de })}
                                    </div>
                                </div>
                                <button
                                    className="btn btn-danger btn-icon"
                                    onClick={() => revokeSession(session.id)}
                                    title="Sitzung beenden"
                                >
                                    <Trash2 size={16} />
                                </button>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {/* Data Management */}
            <div className="settings-section">
                <h3>Datenverwaltung</h3>
                <div className="settings-row">
                    <div>
                        <div className="settings-label">Daten exportieren</div>
                        <div className="settings-description">
                            Alle Passwörter als JSON-Datei herunterladen
                        </div>
                    </div>
                    <button className="btn btn-secondary" onClick={handleExport}>
                        <Download size={18} />
                        Exportieren
                    </button>
                </div>
                <div className="settings-row">
                    <div>
                        <div className="settings-label">Daten importieren</div>
                        <div className="settings-description">
                            Passwörter aus einer JSON-Datei importieren
                        </div>
                    </div>
                    <label className="btn btn-secondary" style={{ cursor: 'pointer' }}>
                        <Download size={18} />
                        Importieren
                        <input
                            type="file"
                            accept=".json"
                            style={{ display: 'none' }}
                            onChange={handleImport}
                        />
                    </label>
                </div>
            </div>

            {/* Security Info */}
            <div className="settings-section" style={{
                backgroundColor: 'rgba(241, 196, 15, 0.1)',
                border: '1px solid rgba(241, 196, 15, 0.3)'
            }}>
                <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <AlertTriangle size={20} style={{ color: 'var(--accent-warning)' }} />
                    Sicherheitshinweise
                </h3>
                <ul style={{ margin: '1rem 0 0', paddingLeft: '1.25rem', color: 'var(--text-secondary)' }}>
                    <li style={{ marginBottom: '0.5rem' }}>Ihr Master-Passwort wird niemals auf dem Server gespeichert</li>
                    <li style={{ marginBottom: '0.5rem' }}>Alle Passwörter werden mit AES-256 verschlüsselt</li>
                    <li style={{ marginBottom: '0.5rem' }}>Sitzungen werden nach 30 Minuten Inaktivität automatisch beendet</li>
                    <li>Aktivieren Sie die Zwei-Faktor-Authentifizierung für zusätzlichen Schutz</li>
                </ul>
            </div>

            {toast && (
                <div className={`toast ${toast.type}`}>
                    {toast.message}
                </div>
            )}
        </div>
    );
}
