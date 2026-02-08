import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Key, Eye, EyeOff, Mail, Lock, Shield } from 'lucide-react';

export default function Register() {
    const [formData, setFormData] = useState({
        email: '',
        password: '',
        masterPassword: '',
        confirmMasterPassword: ''
    });
    const [showPasswords, setShowPasswords] = useState({
        password: false,
        masterPassword: false
    });
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const { register, clearError } = useAuth();
    const navigate = useNavigate();

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData(prev => ({ ...prev, [name]: value }));
    };

    const validateForm = () => {
        if (formData.password.length < 8) {
            return 'Das Passwort muss mindestens 8 Zeichen lang sein';
        }
        if (formData.masterPassword.length < 8) {
            return 'Das Master-Passwort muss mindestens 8 Zeichen lang sein';
        }
        if (formData.masterPassword !== formData.confirmMasterPassword) {
            return 'Die Master-Passwörter stimmen nicht überein';
        }
        return null;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        clearError();
        setError('');

        const validationError = validateForm();
        if (validationError) {
            setError(validationError);
            return;
        }

        setLoading(true);

        const result = await register(
            formData.email,
            formData.password,
            formData.masterPassword
        );

        if (result.success) {
            navigate('/dashboard');
        } else {
            setError(result.error);
        }

        setLoading(false);
    };

    return (
        <div className="auth-container">
            <div className="auth-card animate-fade-in" style={{ maxWidth: '480px' }}>
                <div className="auth-header">
                    <div className="auth-logo">
                        <Key size={32} />
                        <span>Password Vault</span>
                    </div>
                    <h1 className="auth-title">Konto erstellen</h1>
                    <p className="auth-subtitle">
                        Erstellen Sie Ihr sicheres Passwort-Tresor-Konto
                    </p>
                </div>

                <div style={{
                    backgroundColor: 'rgba(67, 97, 238, 0.1)',
                    padding: '1rem',
                    borderRadius: 'var(--radius-md)',
                    marginBottom: '1.5rem',
                    display: 'flex',
                    gap: '0.75rem',
                    alignItems: 'flex-start'
                }}>
                    <Shield size={20} style={{ color: 'var(--accent-primary)', flexShrink: 0, marginTop: '2px' }} />
                    <p style={{
                        fontSize: '0.875rem',
                        color: 'var(--text-secondary)',
                        margin: 0
                    }}>
                        <strong>Wichtig:</strong> Ihr Master-Passwort wird zur Verschlüsselung aller Ihrer Daten verwendet.
                        Es kann nicht wiederhergestellt werden. Merken Sie es sich gut!
                    </p>
                </div>

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
                        <label className="form-label" htmlFor="email">E-Mail-Adresse</label>
                        <div style={{ position: 'relative' }}>
                            <Mail size={18} style={{
                                position: 'absolute',
                                left: '1rem',
                                top: '50%',
                                transform: 'translateY(-50%)',
                                color: 'var(--text-muted)'
                            }} />
                            <input
                                id="email"
                                type="email"
                                name="email"
                                className="form-input"
                                style={{ paddingLeft: '2.75rem' }}
                                placeholder="ihre@email.de"
                                value={formData.email}
                                onChange={handleChange}
                                required
                                autoComplete="email"
                            />
                        </div>
                    </div>

                    <div className="form-group">
                        <label className="form-label" htmlFor="password">Master-Passwort</label>
                        <div style={{ position: 'relative' }}>
                            <Lock size={18} style={{
                                position: 'absolute',
                                left: '1rem',
                                top: '50%',
                                transform: 'translateY(-50%)',
                                color: 'var(--text-muted)'
                            }} />
                            <input
                                id="masterPassword"
                                name="masterPassword"
                                type={showPasswords.masterPassword ? 'text' : 'password'}
                                className="form-input"
                                style={{ paddingLeft: '2.75rem', paddingRight: '2.75rem' }}
                                placeholder="Ihr Master-Passwort"
                                value={formData.masterPassword}
                                onChange={handleChange}
                                required
                                autoComplete="new-password"
                            />
                            <button
                                type="button"
                                onClick={() => setShowPasswords(prev => ({
                                    ...prev,
                                    masterPassword: !prev.masterPassword
                                }))}
                                style={{
                                    position: 'absolute',
                                    right: '1rem',
                                    top: '50%',
                                    transform: 'translateY(-50%)',
                                    background: 'none',
                                    border: 'none',
                                    cursor: 'pointer',
                                    color: 'var(--text-muted)'
                                }}
                                aria-label={showPasswords.masterPassword ? 'Master-Passwort verbergen' : 'Master-Passwort anzeigen'}
                            >
                                {showPasswords.masterPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                            </button>
                        </div>
                        <small style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                            Mindestens 8 Zeichen
                        </small>
                    </div>

                    <div className="form-group">
                        <label className="form-label" htmlFor="confirmMasterPassword">Master-Passwort bestätigen</label>
                        <div style={{ position: 'relative' }}>
                            <Lock size={18} style={{
                                position: 'absolute',
                                left: '1rem',
                                top: '50%',
                                transform: 'translateY(-50%)',
                                color: 'var(--text-muted)'
                            }} />
                            <input
                                id="confirmMasterPassword"
                                name="confirmMasterPassword"
                                type={showPasswords.masterPassword ? 'text' : 'password'}
                                className="form-input"
                                style={{ paddingLeft: '2.75rem' }}
                                placeholder="Master-Passwort wiederholen"
                                value={formData.confirmMasterPassword}
                                onChange={handleChange}
                                required
                                autoComplete="new-password"
                            />
                        </div>
                    </div>

                    <button
                        type="submit"
                        className="btn btn-primary"
                        style={{ width: '100%', marginTop: '0.5rem' }}
                        disabled={loading}
                    >
                        {loading ? 'Wird registriert...' : 'Konto erstellen'}
                    </button>
                </form>

                <div className="auth-footer">
                    <p>
                        Bereits ein Konto?{' '}
                        <Link to="/login">Hier anmelden</Link>
                    </p>
                </div>
            </div>
        </div>
    );
}
