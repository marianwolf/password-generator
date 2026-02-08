import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import api from '../services/api';

const AuthContext = createContext(null);

export function useAuth() {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
}

export function AuthProvider({ children }) {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [sessionToken, setSessionToken] = useState(null);

    // Check for existing session on mount
    useEffect(() => {
        const initAuth = async () => {
            const token = localStorage.getItem('accessToken');
            const storedSessionToken = localStorage.getItem('sessionToken');

            if (token) {
                try {
                    api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
                    if (storedSessionToken) {
                        api.defaults.headers.common['X-Session-Token'] = storedSessionToken;
                    }

                    const response = await api.get('/auth/profile');
                    setUser(response.data.user);
                    setSessionToken(storedSessionToken);
                } catch (err) {
                    console.error('Auth initialization failed:', err);
                    localStorage.removeItem('accessToken');
                    localStorage.removeItem('sessionToken');
                    delete api.defaults.headers.common['Authorization'];
                    delete api.defaults.headers.common['X-Session-Token'];
                }
            }
            setLoading(false);
        };

        initAuth();
    }, []);

    const login = useCallback(async (email, password) => {
        setError(null);
        try {
            const response = await api.post('/auth/login', { email, password });
            const { access_token, refresh_token, session_token, user: userData } = response.data;

            localStorage.setItem('accessToken', access_token);
            localStorage.setItem('sessionToken', session_token);
            localStorage.setItem('refreshToken', refresh_token);

            api.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
            api.defaults.headers.common['X-Session-Token'] = session_token;

            setUser(userData);
            setSessionToken(session_token);

            return { success: true };
        } catch (err) {
            const message = err.response?.data?.error || 'Login fehlgeschlagen';
            setError(message);
            return { success: false, error: message };
        }
    }, []);

    const register = useCallback(async (email, password, masterPassword) => {
        setError(null);
        try {
            const response = await api.post('/auth/register', {
                email,
                password,
                master_password: masterPassword
            });
            const { access_token, refresh_token, session_token, user: userData } = response.data;

            localStorage.setItem('accessToken', access_token);
            localStorage.setItem('sessionToken', session_token);
            localStorage.setItem('refreshToken', refresh_token);

            api.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
            api.defaults.headers.common['X-Session-Token'] = session_token;

            setUser(userData);
            setSessionToken(session_token);

            return { success: true };
        } catch (err) {
            const message = err.response?.data?.error || 'Registrierung fehlgeschlagen';
            setError(message);
            return { success: false, error: message };
        }
    }, []);

    const logout = useCallback(async () => {
        try {
            await api.post('/auth/logout');
        } catch (err) {
            console.error('Logout error:', err);
        } finally {
            localStorage.removeItem('accessToken');
            localStorage.removeItem('sessionToken');
            localStorage.removeItem('refreshToken');

            delete api.defaults.headers.common['Authorization'];
            delete api.defaults.headers.common['X-Session-Token'];

            setUser(null);
            setSessionToken(null);
        }
    }, []);

    const refreshAuthToken = useCallback(async () => {
        const refreshToken = localStorage.getItem('refreshToken');
        if (!refreshToken) {
            return false;
        }

        try {
            api.defaults.headers.common['Authorization'] = `Bearer ${refreshToken}`;
            const response = await api.post('/auth/refresh');
            const { access_token } = response.data;

            localStorage.setItem('accessToken', access_token);
            api.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;

            return true;
        } catch (err) {
            logout();
            return false;
        }
    }, [logout]);

    const value = {
        user,
        sessionToken,
        isAuthenticated: !!user,
        loading,
        error,
        login,
        register,
        logout,
        refreshAuthToken,
        clearError: () => setError(null)
    };

    return (
        <AuthContext.Provider value={value}>
            {children}
        </AuthContext.Provider>
    );
}
