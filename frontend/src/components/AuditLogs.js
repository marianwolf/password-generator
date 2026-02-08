import React, { useState, useEffect } from 'react';
import { auditApi } from '../services/api';
import { format } from 'date-fns';
import { de } from 'date-fns/locale';
import { FileText, User, LogIn, LogOut, Plus, Trash2, Edit, Download, Upload } from 'lucide-react';

export default function AuditLogs() {
    const [logs, setLogs] = useState([]);
    const [loading, setLoading] = useState(true);
    const [page, setPage] = useState(1);
    const [totalPages, setTotalPages] = useState(1);

    useEffect(() => {
        loadLogs();
    }, [page]);

    const loadLogs = async () => {
        try {
            const response = await auditApi.getLogs({ page, per_page: 50 });
            setLogs(response.data.logs);
            setTotalPages(response.data.pages);
        } catch (error) {
            console.error('Failed to load audit logs:', error);
        } finally {
            setLoading(false);
        }
    };

    const getActionIcon = (action) => {
        const actionIcons = {
            LOGIN_SUCCESS: LogIn,
            LOGIN_FAILED: LogIn,
            LOGOUT: LogOut,
            PASSWORD_CREATED: Plus,
            PASSWORD_ACCESSED: FileText,
            PASSWORD_UPDATED: Edit,
            PASSWORD_DELETED: Trash2,
            EXPORT_REQUESTED: Download,
            IMPORT_COMPLETED: Upload,
            USER_REGISTERED: User
        };
        return actionIcons[action] || FileText;
    };

    const getActionColor = (action) => {
        const actionColors = {
            LOGIN_SUCCESS: 'var(--accent-success)',
            LOGIN_FAILED: 'var(--accent-danger)',
            LOGOUT: 'var(--text-secondary)',
            PASSWORD_CREATED: 'var(--accent-success)',
            PASSWORD_DELETED: 'var(--accent-danger)'
        };
        return actionColors[action] || 'var(--accent-primary)';
    };

    const getActionLabel = (action) => {
        const actionLabels = {
            LOGIN_SUCCESS: 'Erfolgreiche Anmeldung',
            LOGIN_FAILED: 'Fehlgeschlagene Anmeldung',
            LOGOUT: 'Abmeldung',
            PASSWORD_CREATED: 'Passwort erstellt',
            PASSWORD_ACCESSED: 'Passwort aufgerufen',
            PASSWORD_UPDATED: 'Passwort aktualisiert',
            PASSWORD_DELETED: 'Passwort gelöscht',
            FAVORITE_ADDED: 'Favorit hinzugefügt',
            FAVORITE_REMOVED: 'Favorit entfernt',
            EXPORT_REQUESTED: 'Export durchgeführt',
            IMPORT_COMPLETED: 'Import durchgeführt',
            USER_REGISTERED: 'Benutzer registriert',
            SESSION_REVOKED: 'Sitzung beendet',
            PROFILE_UPDATED: 'Profil aktualisiert',
            PASSWORD_GENERATED: 'Passwort generiert'
        };
        return actionLabels[action] || action;
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
                Audit-Protokoll
            </h1>

            <div className="card">
                <div style={{ overflowX: 'auto' }}>
                    <table style={{
                        width: '100%',
                        borderCollapse: 'collapse',
                        fontSize: '0.875rem'
                    }}>
                        <thead>
                            <tr style={{ borderBottom: '2px solid var(--border-color)' }}>
                                <th style={{
                                    textAlign: 'left',
                                    padding: '0.75rem 1rem',
                                    color: 'var(--text-secondary)',
                                    fontWeight: 500
                                }}>
                                    Aktion
                                </th>
                                <th style={{
                                    textAlign: 'left',
                                    padding: '0.75rem 1rem',
                                    color: 'var(--text-secondary)',
                                    fontWeight: 500
                                }}>
                                    Zeitstempel
                                </th>
                                <th style={{
                                    textAlign: 'left',
                                    padding: '0.75rem 1rem',
                                    color: 'var(--text-secondary)',
                                    fontWeight: 500,
                                    display: 'none'
                                }}>
                                    IP-Adresse
                                </th>
                                <th style={{
                                    textAlign: 'left',
                                    padding: '0.75rem 1rem',
                                    color: 'var(--text-secondary)',
                                    fontWeight: 500
                                }}>
                                    Details
                                </th>
                            </tr>
                        </thead>
                        <tbody>
                            {logs.map((log) => {
                                const Icon = getActionIcon(log.action);
                                const color = getActionColor(log.action);

                                return (
                                    <tr
                                        key={log.id}
                                        style={{
                                            borderBottom: '1px solid var(--border-color)',
                                            transition: 'background-color 0.2s'
                                        }}
                                        onMouseEnter={(e) => {
                                            e.currentTarget.style.backgroundColor = 'var(--bg-tertiary)';
                                        }}
                                        onMouseLeave={(e) => {
                                            e.currentTarget.style.backgroundColor = 'transparent';
                                        }}
                                    >
                                        <td style={{ padding: '0.75rem 1rem' }}>
                                            <div style={{
                                                display: 'flex',
                                                alignItems: 'center',
                                                gap: '0.5rem'
                                            }}>
                                                <Icon size={16} style={{ color }} />
                                                <span>{getActionLabel(log.action)}</span>
                                            </div>
                                        </td>
                                        <td style={{
                                            padding: '0.75rem 1rem',
                                            color: 'var(--text-secondary)',
                                            whiteSpace: 'nowrap'
                                        }}>
                                            {format(new Date(log.timestamp), 'PPp', { locale: de })}
                                        </td>
                                        <td style={{
                                            padding: '0.75rem 1rem',
                                            color: 'var(--text-secondary)',
                                            display: 'none'
                                        }}>
                                            {log.ip_address || '-'}
                                        </td>
                                        <td style={{
                                            padding: '0.75rem 1rem',
                                            color: 'var(--text-secondary)'
                                        }}>
                                            {log.details || '-'}
                                        </td>
                                    </tr>
                                );
                            })}
                        </tbody>
                    </table>
                </div>

                {logs.length === 0 && (
                    <div style={{
                        textAlign: 'center',
                        padding: '3rem',
                        color: 'var(--text-secondary)'
                    }}>
                        <FileText size={48} style={{ marginBottom: '1rem', opacity: 0.5 }} />
                        <p>Keine Audit-Einträge gefunden</p>
                    </div>
                )}

                {/* Pagination */}
                {totalPages > 1 && (
                    <div style={{
                        display: 'flex',
                        justifyContent: 'center',
                        gap: '0.5rem',
                        marginTop: '1.5rem',
                        paddingTop: '1rem',
                        borderTop: '1px solid var(--border-color)'
                    }}>
                        <button
                            className="btn btn-secondary"
                            disabled={page === 1}
                            onClick={() => setPage(p => p - 1)}
                        >
                            Zurück
                        </button>
                        <span style={{
                            display: 'flex',
                            alignItems: 'center',
                            padding: '0 1rem',
                            color: 'var(--text-secondary)'
                        }}>
                            Seite {page} von {totalPages}
                        </span>
                        <button
                            className="btn btn-secondary"
                            disabled={page === totalPages}
                            onClick={() => setPage(p => p + 1)}
                        >
                            Weiter
                        </button>
                    </div>
                )}
            </div>
        </div>
    );
}
