import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { initializeApp } from 'firebase/app';
import { getAuth, signInAnonymously, signInWithCustomToken, onAuthStateChanged, signOut } from 'firebase/auth';
import { getFirestore, doc, setDoc, deleteDoc, onSnapshot, collection, query, serverTimestamp, addDoc, updateDoc } from 'firebase/firestore';
import {
  Key,
  User,
  Lock,
  Unlock,
  Plus,
  Edit,
  Trash2,
  Eye,
  EyeOff,
  Copy,
  Search,
  LogOut,
  Settings,
  X,
  ShieldCheck,
  Zap,
  ChevronRight,
  ClipboardCheck,
  Clipboard
} from 'lucide-react';

// --- Konfiguration und Initialisierung (Globale Variablen) ---
// Die globalen Variablen __app_id, __firebase_config und __initial_auth_token
// werden von der Laufzeitumgebung bereitgestellt.

const appId = typeof __app_id !== 'undefined' ? __app_id : 'default-app-id';
const firebaseConfig = typeof __firebase_config !== 'undefined' ? JSON.parse(__firebase_config) : {};
const initialAuthToken = typeof __initial_auth_token !== 'undefined' ? __initial_auth_token : null;

// Initialisiere Firebase
let app, db, auth;
try {
  app = initializeApp(firebaseConfig);
  db = getFirestore(app);
  auth = getAuth(app);
  // Optional: Setze den Loglevel für Firestore auf Debug, um Probleme besser zu sehen
  // setLogLevel('debug'); 
} catch (e) {
  console.error("Firebase Initialisierung fehlgeschlagen:", e);
}

// --- Kryptographie-Helfer (Web Crypto API) ---

// Salz für die Master-Key-Ableitung
const SALT = new TextEncoder().encode("SecureVaultSaltV1");
const ENCRYPTION_ALGO = 'AES-GCM';
const IV_LENGTH = 16;
const KEY_LENGTH = 256;

/**
 * Leitet einen kryptografischen Schlüssel aus dem Master-Passwort ab.
 * @param {string} masterPassword - Das vom Benutzer eingegebene Master-Passwort.
 * @returns {Promise<CryptoKey>} - Der abgeleitete Schlüssel.
 */
const getKeyFromMaster = async (masterPassword) => {
  const masterKey = await window.crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(masterPassword),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: SALT,
      iterations: 100000,
      hash: 'SHA-256',
    },
    masterKey,
    { name: ENCRYPTION_ALGO, length: KEY_LENGTH },
    false,
    ['encrypt', 'decrypt']
  );
};

/**
 * Verschlüsselt einen String.
 * @param {string} text - Der zu verschlüsselnde Klartext.
 * @param {CryptoKey} key - Der Verschlüsselungsschlüssel.
 * @returns {Promise<string>} - Der Base64-kodierte, verschlüsselte String (IV + Ciphertext).
 */
const encrypt = async (text, key) => {
  const iv = window.crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const encoded = new TextEncoder().encode(text);
  
  const encrypted = await window.crypto.subtle.encrypt(
    { name: ENCRYPTION_ALGO, iv },
    key,
    encoded
  );

  const fullArray = new Uint8Array(iv.length + encrypted.byteLength);
  fullArray.set(iv, 0);
  fullArray.set(new Uint8Array(encrypted), iv.length);
  
  return btoa(String.fromCharCode.apply(null, fullArray));
};

/**
 * Entschlüsselt einen Base64-String.
 * @param {string} encryptedBase64 - Der Base64-kodierte, verschlüsselte String.
 * @param {CryptoKey} key - Der Entschlüsselungsschlüssel.
 * @returns {Promise<string|null>} - Der entschlüsselte Klartext oder null bei Fehler.
 */
const decrypt = async (encryptedBase64, key) => {
  try {
    const binaryStr = atob(encryptedBase64);
    const fullArray = Uint8Array.from(binaryStr, c => c.charCodeAt(0));
    
    if (fullArray.length < IV_LENGTH) {
      console.error("Daten sind zu kurz für IV");
      return null;
    }

    const iv = fullArray.slice(0, IV_LENGTH);
    const ciphertext = fullArray.slice(IV_LENGTH);

    const decrypted = await window.crypto.subtle.decrypt(
      { name: ENCRYPTION_ALGO, iv },
      key,
      ciphertext
    );
    
    return new TextDecoder().decode(decrypted);

  } catch (error) {
    // Fehler beim Entschlüsseln (wahrscheinlich falscher Master-Key)
    console.error("Entschlüsselungsfehler:", error);
    return null;
  }
};


// --- UI-Komponenten ---

/**
 * Kleine Komponente zum Anzeigen von Kopierstatus.
 */
const CopyButton = ({ textToCopy }) => {
    const [copied, setCopied] = useState(false);

    const handleCopy = () => {
        // execCommand('copy') ist robuster in iFrames
        const el = document.createElement('textarea');
        el.value = textToCopy;
        document.body.appendChild(el);
        el.select();
        document.execCommand('copy');
        document.body.removeChild(el);

        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
    };

    return (
        <button 
            onClick={handleCopy}
            className={`transition-all duration-300 p-1 rounded-full ${copied ? 'bg-green-500 text-white' : 'hover:bg-gray-200 text-gray-500'}`}
            title={copied ? "Kopiert!" : "Kopieren"}
        >
            {copied ? <ClipboardCheck className="w-4 h-4" /> : <Clipboard className="w-4 h-4" />}
        </button>
    );
};

/**
 * Karte für einen einzelnen Passwort-Eintrag.
 */
const PasswordCard = ({ entry, decryptedKey, onEdit, onRequestDelete }) => {
    const [isPasswordVisible, setIsPasswordVisible] = useState(false);
    const [decryptedValues, setDecryptedValues] = useState({ password: '***', username: '***' });
    const [isDecrypted, setIsDecrypted] = useState(false);

    // Entschlüsselt die Daten, wenn der Schlüssel bereit ist
    useEffect(() => {
        const loadDecrypted = async () => {
            if (!decryptedKey) return;
            try {
                const pass = await decrypt(entry.encryptedPassword, decryptedKey);
                const user = await decrypt(entry.encryptedUsername, decryptedKey);
                setDecryptedValues({ 
                    password: pass || '[Entschlüsselungsfehler]', 
                    username: user || '[Entschlüsselungsfehler]' 
                });
                setIsDecrypted(true);
            } catch (e) {
                console.error("Fehler beim Entschlüsseln der Kartendaten:", e);
                setDecryptedValues({ password: '[Fehler]', username: '[Fehler]' });
                setIsDecrypted(false);
            }
        };

        loadDecrypted();
    }, [entry, decryptedKey]);

    const displayPassword = isDecrypted ? (isPasswordVisible ? decryptedValues.password : '••••••••••••••••') : decryptedValues.password;
    const displayUsername = isDecrypted ? decryptedValues.username : decryptedValues.username;

    return (
        <div className="bg-white p-6 rounded-xl shadow-xl transition-all duration-300 hover:shadow-2xl flex flex-col justify-between">
            <div>
                <div className="flex items-center justify-between mb-3 border-b pb-2">
                    <h3 className="text-xl font-bold text-gray-800 truncate">{entry.serviceName}</h3>
                    <div className="flex space-x-2">
                        <button onClick={() => onEdit(entry)} className="p-2 text-blue-600 hover:text-blue-800 transition-colors rounded-full hover:bg-blue-50" title="Bearbeiten">
                            <Edit className="w-4 h-4" />
                        </button>
                        <button onClick={() => onRequestDelete(entry)} className="p-2 text-red-600 hover:text-red-800 transition-colors rounded-full hover:bg-red-50" title="Löschen">
                            <Trash2 className="w-4 h-4" />
                        </button>
                    </div>
                </div>

                <div className="space-y-3 text-sm">
                    {/* Benutzername */}
                    <div className="flex items-center justify-between bg-gray-50 p-3 rounded-lg">
                        <div className="flex items-center">
                            <User className="w-4 h-4 text-gray-400 mr-3" />
                            <span className="font-medium text-gray-600 mr-2">Benutzername:</span>
                            <span className="text-gray-800 font-mono truncate max-w-[120px] sm:max-w-full">{displayUsername}</span>
                        </div>
                        <CopyButton textToCopy={decryptedValues.username} />
                    </div>

                    {/* Passwort */}
                    <div className="flex items-center justify-between bg-gray-50 p-3 rounded-lg">
                        <div className="flex items-center">
                            <Key className="w-4 h-4 text-gray-400 mr-3" />
                            <span className="font-medium text-gray-600 mr-2">Passwort:</span>
                            <span className="text-gray-800 font-mono truncate max-w-[120px] sm:max-w-full">{displayPassword}</span>
                        </div>
                        <div className="flex space-x-2 items-center">
                            <button 
                                onClick={() => setIsPasswordVisible(!isPasswordVisible)} 
                                className="p-1 text-gray-500 hover:text-gray-700 rounded-full hover:bg-gray-200"
                                title={isPasswordVisible ? "Verbergen" : "Anzeigen"}
                                disabled={!isDecrypted}
                            >
                                {isPasswordVisible ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                            </button>
                            <CopyButton textToCopy={decryptedValues.password} />
                        </div>
                    </div>
                    
                    {/* URL */}
                    {entry.url && (
                        <div className="flex items-center bg-gray-50 p-3 rounded-lg">
                            <ChevronRight className="w-4 h-4 text-gray-400 mr-3" />
                            <a href={entry.url.startsWith('http') ? entry.url : `https://${entry.url}`} target="_blank" rel="noopener noreferrer" className="text-blue-500 hover:underline truncate">
                                {entry.url}
                            </a>
                        </div>
                    )}
                </div>
            </div>
            
            <p className="text-xs text-right text-gray-400 mt-4">
                ID: {entry.id.substring(0, 8)}...
            </p>
        </div>
    );
};

/**
 * Modal zum Hinzufügen oder Bearbeiten eines Eintrags.
 */
const AddEditModal = ({ isOpen, onClose, onSave, entry, isLoading }) => {
    const [serviceName, setServiceName] = useState('');
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [url, setUrl] = useState('');
    const [isPasswordVisible, setIsPasswordVisible] = useState(false);
    const [error, setError] = useState('');

    useEffect(() => {
        if (entry) {
            // Wenn ein Eintrag zum Bearbeiten vorhanden ist, fülle die Felder aus
            setServiceName(entry.serviceName || '');
            // ACHTUNG: Die entschlüsselten Werte müssen von der übergeordneten Komponente bereitgestellt werden!
            // Da wir in der VaultManager-Komponente die Entschlüsselung in der PasswordCard durchgeführt haben,
            // ist es für die Bearbeitung notwendig, die entschlüsselten Werte vom Benutzer neu eingeben zu lassen
            // oder eine Funktion bereitzustellen, die die aktuellen entschlüsselten Werte abruft.
            // Vereinfachung: Für die Bearbeitung zeigen wir Platzhalter, und der Benutzer MUSS sie neu eingeben.
            setUsername('[Wird neu eingegeben]');
            setPassword('[Wird neu eingegeben]');
            setUrl(entry.url || '');
        } else {
            // Neuer Eintrag
            setServiceName('');
            setUsername('');
            setPassword('');
            setUrl('');
        }
        setError('');
    }, [entry, isOpen]);
    
    // Einfache Funktion zur Passwort-Generierung
    const generatePassword = () => {
        const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
        let newPassword = '';
        for (let i = 0; i < 16; i++) {
            newPassword += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        setPassword(newPassword);
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        if (!serviceName || !username || !password) {
            setError('Bitte Dienstname, Benutzername und Passwort eingeben.');
            return;
        }

        const dataToSave = {
            id: entry ? entry.id : null,
            serviceName,
            username: username === '[Wird neu eingegeben]' ? '' : username, // Leere String, wenn nicht geändert
            password: password === '[Wird neu eingegeben]' ? '' : password,
            url
        };
        
        onSave(dataToSave, entry); // Sende das ursprüngliche Eintragsobjekt mit, um die Encrypted-Daten beizubehalten, falls nicht neu eingegeben

        onClose();
    };

    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex justify-center items-center p-4" onClick={onClose}>
            <div className="bg-white rounded-xl shadow-2xl w-full max-w-lg p-6 md:p-8 relative" onClick={e => e.stopPropagation()}>
                <button onClick={onClose} className="absolute top-4 right-4 text-gray-400 hover:text-gray-600 p-1 transition-colors">
                    <X className="w-6 h-6" />
                </button>
                
                <h2 className="text-2xl font-bold text-gray-800 mb-6 border-b pb-2">{entry ? 'Eintrag bearbeiten' : 'Neuen Eintrag hinzufügen'}</h2>

                <form onSubmit={handleSubmit} className="space-y-4">
                    <div className="space-y-2">
                        <label htmlFor="serviceName" className="block text-sm font-medium text-gray-700">Dienstname</label>
                        <input
                            id="serviceName"
                            type="text"
                            value={serviceName}
                            onChange={(e) => setServiceName(e.target.value)}
                            className="w-full p-3 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
                            required
                            disabled={isLoading}
                        />
                    </div>
                    
                    <div className="space-y-2">
                        <label htmlFor="username" className="block text-sm font-medium text-gray-700">Benutzername (oder E-Mail)</label>
                        <input
                            id="username"
                            type="text"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            className="w-full p-3 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
                            required
                            disabled={isLoading}
                        />
                    </div>
                    
                    <div className="space-y-2">
                        <label htmlFor="password" className="block text-sm font-medium text-gray-700">Passwort</label>
                        <div className="relative">
                            <input
                                id="password"
                                type={isPasswordVisible ? 'text' : 'password'}
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                className="w-full p-3 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 pr-10"
                                required
                                disabled={isLoading}
                            />
                            <button
                                type="button"
                                onClick={() => setIsPasswordVisible(!isPasswordVisible)}
                                className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-500 hover:text-gray-700"
                                title={isPasswordVisible ? "Verbergen" : "Anzeigen"}
                            >
                                {isPasswordVisible ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                            </button>
                        </div>
                        <button
                            type="button"
                            onClick={generatePassword}
                            className="flex items-center text-blue-600 hover:text-blue-800 text-sm font-medium mt-1 transition-colors"
                            disabled={isLoading}
                        >
                            <Zap className="w-4 h-4 mr-1" /> Passwort generieren
                        </button>
                    </div>

                    <div className="space-y-2">
                        <label htmlFor="url" className="block text-sm font-medium text-gray-700">URL (optional)</label>
                        <input
                            id="url"
                            type="url"
                            placeholder="https://beispiel.de"
                            value={url}
                            onChange={(e) => setUrl(e.target.value)}
                            className="w-full p-3 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
                            disabled={isLoading}
                        />
                    </div>

                    {error && (
                        <p className="text-red-500 text-sm">{error}</p>
                    )}

                    <button
                        type="submit"
                        className="w-full bg-blue-600 text-white p-3 rounded-lg font-semibold hover:bg-blue-700 transition-colors flex items-center justify-center disabled:opacity-50"
                        disabled={isLoading}
                    >
                        {isLoading ? (
                            <Settings className="w-5 h-5 animate-spin mr-2" />
                        ) : (
                            <Plus className="w-5 h-5 mr-2" />
                        )}
                        {entry ? 'Speichern' : 'Hinzufügen'}
                    </button>
                </form>
            </div>
        </div>
    );
};

/**
 * Modal zur Bestätigung des Löschvorgangs.
 */
const DeleteConfirmationModal = ({ isOpen, onClose, entry, onConfirm }) => {
    if (!isOpen || !entry) return null;

    const handleConfirm = () => {
        onConfirm(entry.id);
        onClose();
    };

    return (
        <div className="fixed inset-0 bg-black bg-opacity-50 z-50 flex justify-center items-center p-4" onClick={onClose}>
            <div className="bg-white rounded-xl shadow-2xl w-full max-w-md p-6 relative" onClick={e => e.stopPropagation()}>
                <h2 className="text-xl font-bold text-red-600 mb-4">Löschung bestätigen</h2>
                <p className="text-gray-700 mb-6">
                    Sind Sie sicher, dass Sie den Eintrag für <strong>{entry.serviceName}</strong> dauerhaft löschen möchten? Diese Aktion kann nicht rückgängig gemacht werden.
                </p>

                <div className="flex justify-end space-x-3">
                    <button 
                        onClick={onClose} 
                        className="px-4 py-2 bg-gray-200 text-gray-800 rounded-lg hover:bg-gray-300 transition-colors font-medium"
                    >
                        Abbrechen
                    </button>
                    <button 
                        onClick={handleConfirm} 
                        className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors font-medium flex items-center"
                    >
                        <Trash2 className="w-4 h-4 mr-2" /> Löschen
                    </button>
                </div>
            </div>
        </div>
    );
};


/**
 * Hauptkomponente des Vault-Managers.
 */
const VaultManager = () => {
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [userId, setUserId] = useState(null);
    const [isAuthReady, setIsAuthReady] = useState(false);
    
    // Vault-Zustand
    const [isLocked, setIsLocked] = useState(true);
    const [vaultEntries, setVaultEntries] = useState([]);
    const [decryptedKey, setDecryptedKey] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const [unlockError, setUnlockError] = useState('');

    // UI-Zustand
    const [filter, setFilter] = useState('');
    const [showAddEditModal, setShowAddEditModal] = useState(false);
    const [currentEntry, setCurrentEntry] = useState(null);
    const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
    const [entryToDelete, setEntryToDelete] = useState(null);


    // --- Firebase Auth & Init ---
    useEffect(() => {
        if (!auth) return;

        // 1. Authentifizierung mit Initial-Token oder anonym
        const signIn = async () => {
            try {
                if (initialAuthToken) {
                    await signInWithCustomToken(auth, initialAuthToken);
                } else {
                    await signInAnonymously(auth);
                }
            } catch (error) {
                console.error("Fehler bei der Firebase-Anmeldung:", error);
            }
        };

        // 2. Auth State Listener
        const unsubscribe = onAuthStateChanged(auth, (user) => {
            if (user) {
                setIsAuthenticated(true);
                setUserId(user.uid);
            } else {
                setIsAuthenticated(false);
                setUserId(null);
            }
            setIsAuthReady(true);
        });

        signIn();
        return () => unsubscribe();
    }, []);

    // --- Firestore Data Listener ---
    useEffect(() => {
        if (!db || !userId || !isAuthReady) return;
        
        // Pfad: /artifacts/{appId}/users/{userId}/vault_entries
        const collectionPath = `artifacts/${appId}/users/${userId}/vault_entries`;
        const q = query(collection(db, collectionPath));
        
        // onSnapshot liefert Echtzeit-Updates
        const unsubscribe = onSnapshot(q, (snapshot) => {
            const entries = [];
            snapshot.forEach((doc) => {
                entries.push({ id: doc.id, ...doc.data() });
            });
            // Sortiere nach Erstellungsdatum (wenn vorhanden)
            entries.sort((a, b) => (b.createdAt?.toMillis() || 0) - (a.createdAt?.toMillis() || 0));
            setVaultEntries(entries);
        }, (error) => {
            console.error("Fehler beim Abrufen der Vault-Einträge:", error);
        });

        return () => unsubscribe();
    }, [db, userId, isAuthReady]);


    // --- Vault-Logik ---

    /**
     * Entsperrt den Vault mit dem Master-Passwort.
     * @param {string} masterPassword 
     */
    const handleUnlock = async (masterPassword) => {
        if (!masterPassword) {
            setUnlockError('Bitte Master-Passwort eingeben.');
            return;
        }

        setIsLoading(true);
        setUnlockError('');

        try {
            // 1. Schlüssel ableiten
            const key = await getKeyFromMaster(masterPassword);
            
            // 2. Test-Entschlüsselung (optional, aber gut zur Validierung des Keys)
            // Wenn es bereits Einträge gibt, versuche, den ersten zu entschlüsseln
            if (vaultEntries.length > 0) {
                const testEntry = vaultEntries[0];
                const decryptedTest = await decrypt(testEntry.encryptedPassword, key);
                
                if (!decryptedTest) {
                    // Entschlüsselung fehlgeschlagen -> falsches Passwort
                    setUnlockError('Falsches Master-Passwort.');
                    setIsLoading(false);
                    return;
                }
            }

            // 3. Vault entsperren
            setDecryptedKey(key);
            setIsLocked(false);
            
        } catch (e) {
            console.error("Fehler beim Entsperren:", e);
            setUnlockError('Ein unerwarteter Fehler ist aufgetreten.');
        } finally {
            setIsLoading(false);
        }
    };

    /**
     * Sperrt den Vault und löscht den Schlüssel aus dem Speicher.
     */
    const handleLock = () => {
        setDecryptedKey(null);
        setIsLocked(true);
        setFilter('');
        // Hinweis: Der Garbage Collector kümmert sich um den gelöschten CryptoKey
    };
    
    /**
     * Verarbeitet das Speichern eines neuen oder bearbeiteten Eintrags.
     */
    const handleSaveEntry = async (data, oldEntry) => {
        if (!decryptedKey || !userId) return;

        setIsLoading(true);
        try {
            const collectionRef = collection(db, `artifacts/${appId}/users/${userId}/vault_entries`);
            
            let encryptedUsername = oldEntry?.encryptedUsername;
            let encryptedPassword = oldEntry?.encryptedPassword;

            // Verschlüssle nur, wenn der Benutzername/Passwort neu eingegeben wurde
            if (data.username) {
                encryptedUsername = await encrypt(data.username, decryptedKey);
            }
            if (data.password) {
                encryptedPassword = await encrypt(data.password, decryptedKey);
            }

            const entryData = {
                serviceName: data.serviceName,
                url: data.url || '',
                encryptedUsername,
                encryptedPassword,
                updatedAt: serverTimestamp(),
            };

            if (data.id) {
                // Eintrag bearbeiten
                const docRef = doc(db, collectionRef, data.id);
                await updateDoc(docRef, entryData);
            } else {
                // Neuen Eintrag hinzufügen
                await addDoc(collectionRef, {
                    ...entryData,
                    createdAt: serverTimestamp(),
                });
            }

        } catch (e) {
            console.error("Fehler beim Speichern des Eintrags:", e);
            alert("Fehler beim Speichern. Bitte Konsole prüfen."); // Ersatz für alert
        } finally {
            setIsLoading(false);
            setCurrentEntry(null);
        }
    };

    /**
     * Löscht einen Eintrag.
     */
    const handleDeleteEntry = async (id) => {
        if (!userId) return;

        setIsLoading(true);
        try {
            const docRef = doc(db, `artifacts/${appId}/users/${userId}/vault_entries`, id);
            await deleteDoc(docRef);
        } catch (e) {
            console.error("Fehler beim Löschen des Eintrags:", e);
            alert("Fehler beim Löschen. Bitte Konsole prüfen."); // Ersatz für alert
        } finally {
            setIsLoading(false);
        }
    };
    
    // --- UI-Helfer ---
    
    const requestEdit = useCallback((entry) => {
        setCurrentEntry(entry);
        setShowAddEditModal(true);
    }, []);

    const requestDelete = useCallback((entry) => {
        setEntryToDelete(entry);
        setShowDeleteConfirm(true);
    }, []);


    // Filtert die Einträge basierend auf dem Suchstring
    const filteredVault = useMemo(() => {
        if (!filter) return vaultEntries;
        const lowerCaseFilter = filter.toLowerCase();
        
        // Wir können nur nach nicht-verschlüsselten Feldern filtern, also nur den Dienstnamen und die URL.
        // Für eine vollständige Suche müsste die Entschlüsselung im Hintergrund laufen, was aber
        // einen sehr hohen Rechenaufwand bedeuten würde.
        return vaultEntries.filter(entry => 
            entry.serviceName.toLowerCase().includes(lowerCaseFilter) ||
            entry.url.toLowerCase().includes(lowerCaseFilter)
        );
    }, [vaultEntries, filter]);

    // --- Render-Logik ---

    if (!isAuthReady) {
        return (
            <div className="flex items-center justify-center min-h-screen bg-gray-50 p-4">
                <div className="bg-white p-10 rounded-2xl text-center text-gray-500 shadow-lg">
                    <Settings className="w-10 h-10 mx-auto animate-spin text-blue-500 mb-4" />
                    <p className="text-xl font-medium">Lade Anwendung und Authentifizierung...</p>
                </div>
            </div>
        );
    }
    
    if (isLocked) {
        return (
            <div className="flex items-center justify-center min-h-screen bg-gray-100 p-4">
                <div className="bg-white p-8 md:p-12 rounded-2xl shadow-2xl w-full max-w-md text-center">
                    <Lock className="w-12 h-12 mx-auto text-blue-600 mb-4" />
                    <h1 className="text-2xl font-bold text-gray-800 mb-6">Vault gesperrt</h1>
                    
                    <form onSubmit={(e) => { e.preventDefault(); handleUnlock(e.target.masterPassword.value); }} className="space-y-4">
                        <div className="relative">
                            <input
                                id="masterPassword"
                                name="masterPassword"
                                type="password"
                                placeholder="Master-Passwort"
                                className="w-full p-3 border-2 border-gray-300 rounded-xl focus:border-blue-500 pr-10"
                                required
                                disabled={isLoading}
                            />
                            <ShieldCheck className="w-5 h-5 absolute right-3 top-3.5 text-gray-400" />
                        </div>
                        
                        {unlockError && (
                            <p className="text-red-500 text-sm font-medium">{unlockError}</p>
                        )}

                        <button
                            type="submit"
                            className="w-full bg-blue-600 text-white p-3 rounded-xl font-semibold hover:bg-blue-700 transition-colors flex items-center justify-center disabled:opacity-50"
                            disabled={isLoading}
                        >
                            {isLoading ? (
                                <Settings className="w-5 h-5 animate-spin mr-2" />
                            ) : (
                                <Unlock className="w-5 h-5 mr-2" />
                            )}
                            Vault entsperren
                        </button>
                    </form>
                    
                    <p className="mt-6 text-xs text-gray-400">Aktuelle User ID: {userId}</p>
                </div>
            </div>
        );
    }

    // Entsperrter Zustand
    return (
        <div className="min-h-screen bg-gray-100 p-4 sm:p-6 md:p-8 font-sans">
            <header className="flex flex-col md:flex-row justify-between items-center mb-6 p-4 bg-white rounded-xl shadow-md">
                <h1 className="text-3xl font-extrabold text-gray-900 flex items-center mb-4 md:mb-0">
                    <ShieldCheck className="w-8 h-8 text-blue-600 mr-3" />
                    Mein Krypto-Vault
                </h1>
                
                <div className="flex items-center space-x-3 w-full md:w-auto">
                    <button 
                        onClick={() => setShowAddEditModal(true)} 
                        className="flex items-center bg-green-600 text-white p-3 rounded-xl font-semibold hover:bg-green-700 transition-colors text-sm shadow-lg"
                        title="Neuen Eintrag hinzufügen"
                    >
                        <Plus className="w-4 h-4 mr-2" /> Eintrag
                    </button>
                    <button 
                        onClick={handleLock} 
                        className="p-3 bg-red-500 text-white rounded-xl hover:bg-red-600 transition-colors shadow-lg"
                        title="Vault sperren"
                    >
                        <Lock className="w-5 h-5" />
                    </button>
                    <button 
                        onClick={() => signOut(auth)} 
                        className="p-3 bg-gray-300 text-gray-800 rounded-xl hover:bg-gray-400 transition-colors shadow-lg"
                        title="Abmelden"
                    >
                        <LogOut className="w-5 h-5" />
                    </button>
                </div>
            </header>

            <div className="mb-6">
                <div className="relative">
                    <Search className="w-5 h-5 text-gray-400 absolute left-3 top-1/2 transform -translate-y-1/2" />
                    <input
                        type="text"
                        placeholder="Einträge nach Dienstnamen oder URL filtern..."
                        value={filter}
                        onChange={(e) => setFilter(e.target.value)}
                        className="w-full p-3 pl-10 border border-gray-300 rounded-xl focus:ring-blue-500 focus:border-blue-500 shadow-sm"
                    />
                </div>
            </div>

            {/* Raster der Passwort-Karten */}
            <div className={`grid gap-6 ${filteredVault.length > 0 ? 'grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4' : ''}`}>
                {isLoading ? (
                    <div className="md:col-span-2 lg:col-span-3 xl:col-span-4 bg-white p-10 rounded-2xl text-center text-gray-500 shadow-lg">
                        <Settings className="w-10 h-10 mx-auto animate-spin text-blue-500 mb-4" />
                        <p className="text-xl font-medium">Lade Vault-Daten...</p>
                    </div>
                ) : filteredVault.length > 0 ? (
                    filteredVault.map(entry => (
                        <PasswordCard 
                            key={entry.id} 
                            entry={entry} 
                            decryptedKey={decryptedKey} // Schlüssel für die Entschlüsselung bereitstellen
                            onEdit={requestEdit} 
                            onRequestDelete={requestDelete} 
                        />
                    ))
                ) : (
                    <div className="md:col-span-2 lg:col-span-3 xl:col-span-4 bg-white p-10 rounded-2xl text-center text-gray-500 shadow-lg">
                        {filter ? (
                            <p className="text-xl font-medium">Keine Einträge gefunden, die "<strong>{filter}</strong>" enthalten.</p>
                        ) : (
                            <p className="text-xl font-medium">Dieses Konto ist leer. Fügen Sie oben Ihren ersten Eintrag hinzu!</p>
                        )}
                        
                    </div>
                )}
            </div>

            {/* Modals für den entsperrten Zustand */}
            <AddEditModal
                isOpen={showAddEditModal}
                onClose={() => { setShowAddEditModal(false); setCurrentEntry(null); }}
                onSave={handleSaveEntry}
                entry={currentEntry}
                isLoading={isLoading}
            />
            
            <DeleteConfirmationModal
                isOpen={showDeleteConfirm}
                onClose={() => setShowDeleteConfirm(false)}
                entry={entryToDelete}
                onConfirm={handleDeleteEntry}
            />
        </div>
    );
};

export default VaultManager;