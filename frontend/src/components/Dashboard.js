import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { statsApi } from '../services/api';
import { Key, Star, Shield, AlertTriangle } from 'lucide-react';

export default function Dashboard() {
    const [stats, setStats] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        loadStats();
    }, []);

    const loadStats = async () => {
        try {
            const response = await statsApi.getStats();
            setStats(response.data);
        } catch (error) {
            console.error('Failed to load stats:', error);
        } finally {
            setLoading(false);
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

    const statCards = [
        {
            icon: Key,
            label: 'Gespeicherte Passwörter',
            value: stats?.total_passwords || 0,
            color: 'primary'
        },
        {
            icon: Star,
            label: 'Favoriten',
            value: stats?.favorite_count || 0,
            color: 'warning'
        },
        {
            icon: Shield,
            label: 'Sichere Passwörter',
            value: stats?.strength_distribution?.strong || 0,
            color: 'success'
        },
        {
            icon: AlertTriangle,
            label: 'Schwache Passwörter',
            value: stats?.strength_distribution?.weak || 0,
            color: 'danger'
        }
    ];

    return (
        <div className="animate-fade-in">
            <h1 className="page-title" style={{ marginBottom: '1.5rem' }}>
                Dashboard
            </h1>

            {/* Stats Grid */}
            <div className="dashboard-grid">
                {statCards.map(({ icon: Icon, label, value, color }) => (
                    <div key={label} className="stat-card">
                        <div className={`stat-icon ${color}`}>
                            <Icon size={24} />
                        </div>
                        <div className="stat-content">
                            <div className="stat-value">{value}</div>
                            <div className="stat-label">{label}</div>
                        </div>
                    </div>
                ))}
            </div>

            {/* Category Breakdown */}
            {stats?.category_breakdown && Object.keys(stats.category_breakdown).length > 0 && (
                <div className="card" style={{ marginTop: '1.5rem' }}>
                    <h3 style={{ marginBottom: '1rem' }}>Passwörter nach Kategorie</h3>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem' }}>
                        {Object.entries(stats.category_breakdown).map(([category, count]) => (
                            <span key={category} className="badge" style={{ fontSize: '0.875rem', padding: '0.5rem 1rem' }}>
                                {category}: {count}
                            </span>
                        ))}
                    </div>
                </div>
            )}

            {/* Quick Actions */}
            <div className="card" style={{ marginTop: '1.5rem' }}>
                <h3 style={{ marginBottom: '1rem' }}>Schnellaktionen</h3>
                <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
                    <Link to="/passwords/new" className="btn btn-primary">
                        <Key size={18} />
                        Neues Passwort hinzufügen
                    </Link>
                    <Link to="/generator" className="btn btn-secondary">
                        Passwort-Generator
                    </Link>
                    <Link to="/passwords" className="btn btn-secondary">
                        Alle Passwörter anzeigen
                    </Link>
                </div>
            </div>

            {/* Security Tips */}
            <div className="card" style={{ marginTop: '1.5rem', backgroundColor: 'rgba(67, 97, 238, 0.05)' }}>
                <h3 style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <Shield size={20} style={{ color: 'var(--accent-primary)' }} />
                    Sicherheitstipps
                </h3>
                <ul style={{ margin: 0, paddingLeft: '1.25rem', color: 'var(--text-secondary)' }}>
                    <li style={{ marginBottom: '0.5rem' }}>Verwenden Sie für jeden Dienst ein eindeutiges Passwort</li>
                    <li style={{ marginBottom: '0.5rem' }}>Aktivieren Sie die Zwei-Faktor-Authentifizierung</li>
                    <li style={{ marginBottom: '0.5rem' }}>Ändern Sie regelmäßig Ihre Passwörter</li>
                    <li>Nutzen Sie den integrierten Passwort-Generator für starke Passwörter</li>
                </ul>
            </div>
        </div>
    );
}
