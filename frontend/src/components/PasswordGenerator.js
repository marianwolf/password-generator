import React, { useState, useEffect, useCallback } from 'react';
import { generatorApi } from '../services/api';
import { Copy, RefreshCw, Check } from 'lucide-react';

export default function PasswordGenerator() {
    const [password, setPassword] = useState('');
    const [length, setLength] = useState(20);
    const [options, setOptions] = useState({
        uppercase: true,
        lowercase: true,
        numbers: true,
        symbols: true
    });
    const [strength, setStrength] = useState(0);
    const [copied, setCopied] = useState(false);
    const [loading, setLoading] = useState(true);
    const [toast, setToast] = useState(null);

    const generatePassword = useCallback(async () => {
        try {
            const response = await generatorApi.generate({
                length,
                uppercase: options.uppercase,
                numbers: options.numbers,
                symbols: options.symbols
            });
            setPassword(response.data.password);
        } catch (error) {
            console.error('Failed to generate password:', error);
            // Fallback to local generation
            const localPassword = generateLocalPassword();
            setPassword(localPassword);
        }
    }, [length, options]);

    const generateLocalPassword = () => {
        const chars = {
            lowercase: 'abcdefghijklmnopqrstuvwxyz',
            uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            numbers: '0123456789',
            symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?'
        };
        
        let allChars = '';
        if (options.lowercase) allChars += chars.lowercase;
        if (options.uppercase) allChars += chars.uppercase;
        if (options.numbers) allChars += chars.numbers;
        if (options.symbols) allChars += chars.symbols;
        
        if (!allChars) allChars = chars.lowercase;
        
        let result = '';
        // Ensure at least one character from each selected category
        if (options.lowercase) result += chars.lowercase[Math.floor(Math.random() * chars.lowercase.length)];
        if (options.uppercase) result += chars.uppercase[Math.floor(Math.random() * chars.uppercase.length)];
        if (options.numbers) result += chars.numbers[Math.floor(Math.random() * chars.numbers.length)];
        if (options.symbols) result += chars.symbols[Math.floor(Math.random() * chars.symbols.length)];
        
        // Fill remaining length
        for (let i = result.length; i < length; i++) {
            result += allChars[Math.floor(Math.random() * allChars.length)];
        }
        
        // Shuffle
        return result.split('').sort(() => Math.random() - 0.5).join('');
    };

    useEffect(() => {
        generatePassword();
    }, [generatePassword]);

    useEffect(() => {
        // Calculate strength
        let score = 0;
        if (password.length >= 8) score += 1;
        if (password.length >= 12) score += 1;
        if (password.length >= 16) score += 1;
        if (options.uppercase && /[A-Z]/.test(password)) score += 1;
        if (options.numbers && /\d/.test(password)) score += 1;
        if (options.symbols && /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password)) score += 1;
        setStrength(Math.min(score * 16, 100));
    }, [password, options]);

    const copyToClipboard = async () => {
        try {
            await navigator.clipboard.writeText(password);
            setCopied(true);
            setToast('Passwort in Zwischenablage kopiert');
            setTimeout(() => setCopied(false), 2000);
        } catch (error) {
            setToast('Kopieren fehlgeschlagen', 'error');
        }
    };

    const getStrengthLabel = () => {
        if (strength <= 33) return 'Schwach';
        if (strength <= 66) return 'Mittel';
        return 'Stark';
    };

    const getStrengthColor = () => {
        if (strength <= 33) return 'var(--accent-danger)';
        if (strength <= 66) return 'var(--accent-warning)';
        return 'var(--accent-success)';
    };

    return (
        <div className="animate-fade-in">
            <h1 className="page-title" style={{ marginBottom: '1.5rem' }}>
                Passwort-Generator
            </h1>

            <div className="card" style={{ maxWidth: '600px', margin: '0 auto' }}>
                {/* Generated Password */}
                <div style={{ marginBottom: '1.5rem' }}>
                    <label className="form-label">Generiertes Passwort</label>
                    <div style={{
                        display: 'flex',
                        gap: '0.5rem',
                        backgroundColor: 'var(--bg-tertiary)',
                        borderRadius: 'var(--radius-md)',
                        padding: '0.75rem',
                        fontFamily: 'monospace',
                        fontSize: '1.125rem',
                        wordBreak: 'break-all'
                    }}>
                        <span style={{ flex: 1 }}>{password}</span>
                        <button
                            className="btn btn-ghost btn-icon"
                            onClick={copyToClipboard}
                            title="Kopieren"
                        >
                            {copied ? <Check size={18} style={{ color: 'var(--accent-success)' }} /> : <Copy size={18} />}
                        </button>
                        <button
                            className="btn btn-ghost btn-icon"
                            onClick={generatePassword}
                            title="Neues Passwort"
                        >
                            <RefreshCw size={18} />
                        </button>
                    </div>

                    {/* Strength indicator */}
                    {password && (
                        <div style={{ marginTop: '0.75rem' }}>
                            <div style={{
                                display: 'flex',
                                justifyContent: 'space-between',
                                marginBottom: '0.25rem'
                            }}>
                                <span style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
                                    Stärke:
                                </span>
                                <span style={{
                                    fontSize: '0.875rem',
                                    fontWeight: 500,
                                    color: getStrengthColor()
                                }}>
                                    {getStrengthLabel()}
                                </span>
                            </div>
                            <div className="strength-bar">
                                <div
                                    className="strength-fill"
                                    style={{
                                        width: `${strength}%`,
                                        backgroundColor: getStrengthColor()
                                    }}
                                />
                            </div>
                        </div>
                    )}
                </div>

                {/* Options */}
                <div style={{ marginBottom: '1.5rem' }}>
                    <label className="form-label">Optionen</label>
                    
                    <div style={{ marginBottom: '1rem' }}>
                        <label className="form-label" style={{ marginBottom: '0.5rem' }}>
                            Länge: {length}
                        </label>
                        <input
                            type="range"
                            min="8"
                            max="64"
                            value={length}
                            onChange={(e) => setLength(parseInt(e.target.value))}
                            style={{ width: '100%' }}
                        />
                        <div style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            fontSize: '0.75rem',
                            color: 'var(--text-muted)',
                            marginTop: '0.25rem'
                        }}>
                            <span>8</span>
                            <span>64</span>
                        </div>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.75rem' }}>
                        <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                            <input
                                type="checkbox"
                                checked={options.uppercase}
                                onChange={(e) => setOptions(prev => ({ ...prev, uppercase: e.target.checked }))}
                            />
                            <span>Großbuchstaben (A-Z)</span>
                        </label>
                        <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                            <input
                                type="checkbox"
                                checked={options.lowercase}
                                onChange={(e) => setOptions(prev => ({ ...prev, lowercase: e.target.checked }))}
                            />
                            <span>Kleinbuchstaben (a-z)</span>
                        </label>
                        <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                            <input
                                type="checkbox"
                                checked={options.numbers}
                                onChange={(e) => setOptions(prev => ({ ...prev, numbers: e.target.checked }))}
                            />
                            <span>Zahlen (0-9)</span>
                        </label>
                        <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                            <input
                                type="checkbox"
                                checked={options.symbols}
                                onChange={(e) => setOptions(prev => ({ ...prev, symbols: e.target.checked }))}
                            />
                            <span>Symbole (!@#$...)</span>
                        </label>
                    </div>
                </div>

                <button
                    className="btn btn-primary"
                    onClick={generatePassword}
                    style={{ width: '100%' }}
                >
                    <RefreshCw size={18} />
                    Neues Passwort generieren
                </button>
            </div>

            {/* Tips */}
            <div className="card" style={{ maxWidth: '600px', margin: '1.5rem auto 0' }}>
                <h3 style={{ marginBottom: '1rem' }}>Tipps für sichere Passwörter</h3>
                <ul style={{ margin: 0, paddingLeft: '1.25rem', color: 'var(--text-secondary)' }}>
                    <li style={{ marginBottom: '0.5rem' }}>Verwenden Sie mindestens 12 Zeichen</li>
                    <li style={{ marginBottom: '0.5rem' }}>Kombinieren Sie verschiedene Zeichenarten</li>
                    <li style={{ marginBottom: '0.5rem' }}>Vermeiden Sie persönliche Informationen</li>
                    <li>Nutzen Sie für jeden Dienst ein eindeutiges Passwort</li>
                </ul>
            </div>

            {toast && (
                <div className={`toast ${toast.type || ''}`}>
                    {toast}
                </div>
            )}
        </div>
    );
}
