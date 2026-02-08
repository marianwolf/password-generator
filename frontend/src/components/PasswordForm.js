import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { passwordApi } from '../services/api';
import { Eye, EyeOff, RefreshCw, Copy } from 'lucide-react';

export default function PasswordForm() {
    const { id } = useParams();
    const navigate = useNavigate();
    const isEditing = !!id;

    const [formData, setFormData] = useState({
        title: '',
        username: '',
        password: '',
        website_url: '',
        notes: '',
        category: 'login',
        is_favorite: false
    });
    const [loading, setLoading] = useState(isEditing);
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [toast, setToast] = useState(null);

    useEffect(() => {
        if (isEditing) {
            loadPassword();
        }
    }, [id]);

    const loadPassword = async () => {
        try {
            const response = await passwordApi.get(id);
            const { password, ...data } = response.data.entry;
            setFormData({ ...data, password: password || '' });
        } catch (error) {
            console.error('Failed to load password:', error);
            setError('Passwort konnte nicht geladen werden');
        } finally {
            setLoading(false);
        }
    };

    const showToast = (message, type = 'success') => {
        setToast({ message, type });
        setTimeout(() => setToast(null), 3000);
    };

    const handleChange = (e) => {
        const { name, value, type, checked } = e.target;
        setFormData(prev => ({
            ...prev,
            [name]: type === 'checkbox' ? checked : value
        }));
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setSaving(true);

        try {
            if (isEditing) {
                await passwordApi.update(id, formData);
                showToast('Passwort aktualisiert');
            } else {
                await passwordApi.create(formData);
                showToast('Passwort erstellt');
            }
            navigate('/passwords');
        } catch (error) {
            setError(error.response?.data?.error || 'Speichern fehlgeschlagen');
        } finally {
            setSaving(false);
        }
    };

    const generatePassword = async () => {
        try {
            const response = await passwordApi.generate({ length: 20 });
            setFormData(prev => ({ ...prev, password: response.data.password }));
        } catch (error) {
            setError('Passwort-Generator nicht verfügbar');
        }
    };

    const copyToClipboard = async () => {
        try {
            await navigator.clipboard.writeText(formData.password);
            showToast('Passwort kopiert');
        } catch (error) {
            showToast('Kopieren fehlgeschlagen', 'error');
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
            <div className="form-container">
                <h1 className="page-title" style={{ marginBottom: '1.5rem' }}>
                    {isEditing ? 'Passwort bearbeiten' : 'Neues Passwort'}
                </h1>

                <form onSubmit={handleSubmit}>
                    {error && (
                        <div style={{
                            padding: '0.75rem 1rem',
                            backgroundColor: 'rgba(231, 76, 60, 0.1)',
                            borderRadius: 'var(--radius-md)',
                            color: 'var(--accent-danger)',
                            marginBottom: '1.5rem',
                            fontSize: '0.875rem'
                        }}>
                            {error}
                        </div>
                    )}

                    <div className="form-group">
                        <label className="form-label" htmlFor="title">Titel *</label>
                        <input
                            id="title"
                            name="title"
                            type="text"
                            className="form-input"
                            placeholder="z.B. E-Mail-Account"
                            value={formData.title}
                            onChange={handleChange}
                            required
                        />
                    </div>

                    <div className="form-group">
                        <label className="form-label" htmlFor="username">Benutzername</label>
                        <input
                            id="username"
                            name="username"
                            type="text"
                            className="form-input"
                            placeholder="ihre@email.de"
                            value={formData.username}
                            onChange={handleChange}
                        />
                    </div>

                    <div className="form-group">
                        <label className="form-label" htmlFor="password">Passwort *</label>
                        <div style={{ position: 'relative' }}>
                            <input
                                id="password"
                                name="password"
                                type={showPassword ? 'text' : 'password'}
                                className="form-input"
                                style={{ paddingRight: '2.75rem' }}
                                placeholder="Ihr Passwort"
                                value={formData.password}
                                onChange={handleChange}
                                required
                            />
                            <button
                                type="button"
                                onClick={() => setShowPassword(!showPassword)}
                                style={{
                                    position: 'absolute',
                                    right: '2.75rem',
                                    top: '50%',
                                    transform: 'translateY(-50%)',
                                    background: 'none',
                                    border: 'none',
                                    cursor: 'pointer',
                                    color: 'var(--text-muted)'
                                }}
                            >
                                {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                            </button>
                            <button
                                type="button"
                                onClick={generatePassword}
                                style={{
                                    position: 'absolute',
                                    right: '1rem',
                                    top: '50%',
                                    transform: 'translateY(-50%)',
                                    background: 'none',
                                    border: 'none',
                                    cursor: 'pointer',
                                    color: 'var(--accent-primary)'
                                }}
                                title="Passwort generieren"
                            >
                                <RefreshCw size={18} />
                            </button>
                        </div>
                    </div>

                    <div className="form-group">
                        <label className="form-label" htmlFor="website_url">Website-URL</label>
                        <input
                            id="website_url"
                            name="website_url"
                            type="url"
                            className="form-input"
                            placeholder="https://example.com"
                            value={formData.website_url}
                            onChange={handleChange}
                        />
                    </div>

                    <div className="form-group">
                        <label className="form-label" htmlFor="category">Kategorie</label>
                        <select
                            id="category"
                            name="category"
                            className="form-input"
                            value={formData.category}
                            onChange={handleChange}
                        >
                            <option value="login">Login</option>
                            <option value="credit_card">Kreditkarte</option>
                            <option value="identity">Identität</option>
                            <option value="secure_note">Sichere Notiz</option>
                            <option value="other">Sonstiges</option>
                        </select>
                    </div>

                    <div className="form-group">
                        <label className="form-label" htmlFor="notes">Notizen</label>
                        <textarea
                            id="notes"
                            name="notes"
                            className="form-input"
                            rows="4"
                            placeholder="Zusätzliche Informationen..."
                            value={formData.notes}
                            onChange={handleChange}
                        />
                    </div>

                    <div className="form-group">
                        <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                            <input
                                type="checkbox"
                                name="is_favorite"
                                checked={formData.is_favorite}
                                onChange={handleChange}
                            />
                            <span>Als Favorit markieren</span>
                        </label>
                    </div>

                    <div className="form-actions">
                        <button
                            type="button"
                            className="btn btn-secondary"
                            onClick={() => navigate('/passwords')}
                        >
                            Abbrechen
                        </button>
                        <button
                            type="submit"
                            className="btn btn-primary"
                            disabled={saving}
                        >
                            {saving ? 'Wird gespeichert...' : (isEditing ? 'Aktualisieren' : 'Erstellen')}
                        </button>
                    </div>
                </form>
            </div>

            {toast && (
                <div className={`toast ${toast.type}`}>
                    {toast.message}
                </div>
            )}
        </div>
    );
}
