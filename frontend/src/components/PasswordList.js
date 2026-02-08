import React, { useState, useEffect, useCallback } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { passwordApi } from '../services/api';
import { Search, Plus, Star, StarOff, Copy, Trash2, Edit, Globe, Key } from 'lucide-react';

export default function PasswordList() {
    const [passwords, setPasswords] = useState([]);
    const [loading, setLoading] = useState(true);
    const [search, setSearch] = useState('');
    const [category, setCategory] = useState('');
    const [favoritesOnly, setFavoritesOnly] = useState(false);
    const [toast, setToast] = useState(null);
    const navigate = useNavigate();

    const loadPasswords = useCallback(async () => {
        try {
            const params = {};
            if (search) params.search = search;
            if (category) params.category = category;
            if (favoritesOnly) params.favorites = 'true';

            const response = await passwordApi.list(params);
            setPasswords(response.data.passwords);
        } catch (error) {
            console.error('Failed to load passwords:', error);
            showToast('Fehler beim Laden der Passwörter', 'error');
        } finally {
            setLoading(false);
        }
    }, [search, category, favoritesOnly]);

    useEffect(() => {
        loadPasswords();
    }, [loadPasswords]);

    const showToast = (message, type = 'success') => {
        setToast({ message, type });
        setTimeout(() => setToast(null), 3000);
    };

    const handleCopy = async (password) => {
        try {
            await navigator.clipboard.writeText(password);
            showToast('Passwort in Zwischenablage kopiert');
        } catch (error) {
            showToast('Kopieren fehlgeschlagen', 'error');
        }
    };

    const handleDelete = async (id) => {
        if (!window.confirm('Möchten Sie diesen Eintrag wirklich löschen?')) return;

        try {
            await passwordApi.delete(id);
            showToast('Eintrag gelöscht');
            loadPasswords();
        } catch (error) {
            showToast('Löschen fehlgeschlagen', 'error');
        }
    };

    const toggleFavorite = async (id) => {
        try {
            await passwordApi.toggleFavorite(id);
            loadPasswords();
        } catch (error) {
            showToast('Aktion fehlgeschlagen', 'error');
        }
    };

    const getStrengthColor = (strength) => {
        if (strength <= 40) return 'var(--accent-danger)';
        if (strength <= 70) return 'var(--accent-warning)';
        return 'var(--accent-success)';
    };

    const categories = ['login', 'credit_card', 'identity', 'secure_note', 'other'];

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
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
                <h1 className="page-title">Passwörter</h1>
                <Link to="/passwords/new" className="btn btn-primary">
                    <Plus size={18} />
                    Neues Passwort
                </Link>
            </div>

            {/* Toolbar */}
            <div className="password-toolbar">
                <div className="search-box">
                    <Search size={18} className="search-icon" />
                    <input
                        type="text"
                        className="search-input"
                        placeholder="Passwörter durchsuchen..."
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                    />
                </div>

                <div className="filter-tabs">
                    <button
                        className={`filter-tab ${!category && !favoritesOnly ? 'active' : ''}`}
                        onClick={() => { setCategory(''); setFavoritesOnly(false); }}
                    >
                        Alle
                    </button>
                    <button
                        className={`filter-tab ${favoritesOnly ? 'active' : ''}`}
                        onClick={() => setFavoritesOnly(!favoritesOnly)}
                    >
                        <Star size={14} style={{ marginRight: '0.25rem' }} />
                        Favoriten
                    </button>
                    {categories.map((cat) => (
                        <button
                            key={cat}
                            className={`filter-tab ${category === cat ? 'active' : ''}`}
                            onClick={() => setCategory(cat)}
                        >
                            {cat}
                        </button>
                    ))}
                </div>
            </div>

            {/* Password Grid */}
            {passwords.length === 0 ? (
                <div className="empty-state">
                    <Key size={80} />
                    <h3>Keine Passwörter gefunden</h3>
                    <p>
                        {search || category ? 'Versuchen Sie andere Suchkriterien' : 'Fügen Sie Ihr erstes Passwort hinzu'}
                    </p>
                    <Link to="/passwords/new" className="btn btn-primary" style={{ marginTop: '1rem' }}>
                        <Plus size={18} />
                        Passwort hinzufügen
                    </Link>
                </div>
            ) : (
                <div className="password-grid">
                    {passwords.map((entry) => (
                        <div
                            key={entry.id}
                            className="password-card"
                            onClick={() => navigate(`/passwords/${entry.id}`)}
                        >
                            <div className="password-card-header">
                                <div className="password-title">
                                    {entry.is_favorite && (
                                        <Star size={16} style={{ color: 'var(--accent-warning)', fill: 'var(--accent-warning)' }} />
                                    )}
                                    {entry.title}
                                </div>
                                <div style={{ display: 'flex', gap: '0.25rem' }}>
                                    <button
                                        className="btn-icon btn-ghost"
                                        onClick={(e) => { e.stopPropagation(); toggleFavorite(entry.id); }}
                                        aria-label={entry.is_favorite ? 'Von Favoriten entfernen' : 'Zu Favoriten hinzufügen'}
                                    >
                                        {entry.is_favorite ? <Star size={16} fill="var(--accent-warning)" /> : <StarOff size={16} />}
                                    </button>
                                </div>
                            </div>

                            {entry.username && (
                                <div className="password-username">{entry.username}</div>
                            )}

                            {entry.website_url && (
                                <div style={{
                                    display: 'flex',
                                    alignItems: 'center',
                                    gap: '0.25rem',
                                    fontSize: '0.75rem',
                                    color: 'var(--text-muted)',
                                    marginBottom: '0.5rem'
                                }}>
                                    <Globe size={12} />
                                    <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                        {entry.website_url}
                                    </span>
                                </div>
                            )}

                            <div className="password-meta">
                                <span className="password-category">{entry.category}</span>
                                {entry.password_strength && (
                                    <div style={{
                                        width: '40px',
                                        height: '4px',
                                        backgroundColor: 'var(--bg-tertiary)',
                                        borderRadius: '2px',
                                        overflow: 'hidden'
                                    }}>
                                        <div style={{
                                            width: `${entry.password_strength}%`,
                                            height: '100%',
                                            backgroundColor: getStrengthColor(entry.password_strength),
                                            borderRadius: '2px'
                                        }} />
                                    </div>
                                )}
                            </div>

                            <div style={{
                                display: 'flex',
                                gap: '0.5rem',
                                marginTop: '0.75rem',
                                paddingTop: '0.75rem',
                                borderTop: '1px solid var(--border-color)'
                            }}>
                                <button
                                    className="btn btn-ghost btn-icon"
                                    onClick={(e) => { e.stopPropagation(); }}
                                    title="Kopieren"
                                >
                                    <Copy size={16} />
                                </button>
                                <button
                                    className="btn btn-ghost btn-icon"
                                    onClick={(e) => { e.stopPropagation(); navigate(`/passwords/${entry.id}`); }}
                                    title="Bearbeiten"
                                >
                                    <Edit size={16} />
                                </button>
                                <button
                                    className="btn btn-ghost btn-icon"
                                    onClick={(e) => { e.stopPropagation(); handleDelete(entry.id); }}
                                    title="Löschen"
                                    style={{ marginLeft: 'auto' }}
                                >
                                    <Trash2 size={16} />
                                </button>
                            </div>
                        </div>
                    ))}
                </div>
            )}

            {/* Toast */}
            {toast && (
                <div className={`toast ${toast.type}`}>
                    {toast.message}
                </div>
            )}
        </div>
    );
}
