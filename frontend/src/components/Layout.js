import React, { useState, useEffect } from 'react';
import { Outlet, NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import {
    LayoutDashboard,
    Key,
    Settings,
    FileText,
    LogOut,
    Menu,
    X,
    Moon,
    Sun
} from 'lucide-react';

export default function Layout() {
    const [sidebarOpen, setSidebarOpen] = useState(false);
    const { user, logout } = useAuth();
    const { theme, toggleTheme, isDark } = useTheme();
    const navigate = useNavigate();

    const handleLogout = async () => {
        await logout();
        navigate('/login');
    };

    const navItems = [
        { path: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
        { path: '/passwords', icon: Key, label: 'Passwörter' },
        { path: '/generator', icon: FileText, label: 'Generator' },
        { path: '/settings', icon: Settings, label: 'Einstellungen' },
        { path: '/audit-logs', icon: FileText, label: 'Audit-Logs' }
    ];

    return (
        <div className="app-layout">
            {/* Mobile sidebar overlay */}
            {sidebarOpen && (
                <div
                    className="sidebar-overlay"
                    onClick={() => setSidebarOpen(false)}
                />
            )}

            {/* Sidebar */}
            <aside className={`sidebar ${sidebarOpen ? 'open' : ''}`}>
                <div className="sidebar-header">
                    <div className="sidebar-logo">
                        <Key size={28} />
                        <span>Password Vault</span>
                    </div>
                </div>

                <nav className="sidebar-nav">
                    {navItems.map(({ path, icon: Icon, label }) => (
                        <NavLink
                            key={path}
                            to={path}
                            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
                            onClick={() => setSidebarOpen(false)}
                        >
                            <Icon size={20} />
                            <span>{label}</span>
                        </NavLink>
                    ))}
                </nav>

                <div className="sidebar-footer">
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
                        <span style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
                            {user?.email}
                        </span>
                        <button
                            className="btn-icon btn-ghost"
                            onClick={toggleTheme}
                            aria-label={isDark ? 'Zum hellen Modus wechseln' : 'Zum dunklen Modus wechseln'}
                        >
                            {isDark ? <Sun size={18} /> : <Moon size={18} />}
                        </button>
                    </div>
                    <button
                        className="btn btn-ghost"
                        onClick={handleLogout}
                        style={{ width: '100%' }}
                    >
                        <LogOut size={18} />
                        <span>Abmelden</span>
                    </button>
                </div>
            </aside>

            {/* Main Content */}
            <main className="main-content">
                <header className="page-header">
                    <button
                        className="btn btn-ghost btn-icon mobile-menu-btn"
                        onClick={() => setSidebarOpen(true)}
                        aria-label="Menü öffnen"
                        style={{ display: 'none' }}
                    >
                        <Menu size={24} />
                    </button>
                </header>

                <div className="page-content">
                    <Outlet />
                </div>
            </main>

            <style>{`
                .sidebar-overlay {
                    display: none;
                    position: fixed;
                    inset: 0;
                    background-color: rgba(0, 0, 0, 0.5);
                    z-index: 99;
                }

                @media (max-width: 1024px) {
                    .sidebar-overlay {
                        display: block;
                    }

                    .mobile-menu-btn {
                        display: flex !important;
                    }
                }
            `}</style>
        </div>
    );
}
