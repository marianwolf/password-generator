import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { initializeApp } from 'firebase/app';
import { getAuth, signInAnonymously, signInWithCustomToken, onAuthStateChanged } from 'firebase/auth';
import { getFirestore, doc, setDoc, deleteDoc, onSnapshot, collection, query, serverTimestamp } from 'firebase/firestore';

// --- Konfiguration und Initialisierung ---
// Die globalen Variablen __app_id, __firebase_config und __initial_auth_token
// werden von der Laufzeitumgebung bereitgestellt.

const appId = typeof __app_id !== 'undefined' ? __app_id : 'default-app-id';
const firebaseConfig = typeof __firebase_config !== 'undefined' ? JSON.parse(__firebase_config) : {};
const initialAuthToken = typeof __initial_auth_token !== 'undefined' ? __initial_auth_token : null;

// Initialisiere Firebase (wird nur einmal ausgeführt)
let app, db, auth;
try {
  app = initializeApp(firebaseConfig);
  db = getFirestore(app);
  auth = getAuth(app);
} catch (e) {
  console.error("Firebase Initialisierung fehlgeschlagen:", e);
}

// --- Kryptographie-Helfer (Web Crypto API) ---

const SALT_LENGTH = 16;
const IV_LENGTH = 12; // Für AES-GCM

/**
 * Erzeugt einen zufälligen Salt.
 * @returns {Uint8Array}
 */
const generateSalt = () => window.crypto.getRandomValues(new Uint8Array(SALT_LENGTH));

/**
 * Erzeugt eine zufällige Initialization Vector (IV).
 * @returns {Uint8Array}
 */
const generateIv = () => window.crypto.getRandomValues(new Uint8Array(IV_LENGTH));

/**
 * Leitet einen symmetrischen Schlüssel (AES-GCM) aus dem Master-Passwort ab.
 * @param {string} masterPassword Das Master-Passwort des Benutzers.
 * @param {Uint8Array} salt Der Salt, der für die Schlüsselableitung verwendet wird.
 * @returns {Promise<CryptoKey>} Der abgeleitete Schlüssel.
 */
const deriveKey = async (masterPassword, salt) => {
  const enc = new TextEncoder();
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    enc.encode(masterPassword),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
};

/**
 * Verschlüsselt Text mit einem abgeleiteten Schlüssel und speichert Salt und IV.
 * @param {CryptoKey} key Der AES-GCM-Schlüssel.
 * @param {string} plaintext Der zu verschlüsselnde Text (z.B. das Passwort).
 * @returns {Promise<{ciphertext: string, iv: string, salt: string}>}
 */
const encryptText = async (key, plaintext) => {
  const salt = generateSalt();
  const iv = generateIv();
  
  // Da der Schlüssel für PBKDF2 abgeleitet wird, muss er erst aus dem Master-Passwort abgeleitet werden.
  // Hier wird der Key, der bereits ein CryptoKey ist, direkt verwendet.
  // Das Salt muss in der Datenbank gespeichert werden, falls der Schlüssel neu abgeleitet werden muss (z.B. bei einem Browser-Neustart).
  // Da der `key` hier bereits der aus dem Master-Passwort *abgeleitete* Schlüssel ist, muss das ursprüngliche PBKDF2-Salt 
  // entweder separat behandelt oder man leitet den Schlüssel pro Eintrag neu ab, was ineffizient ist.
  // Zur Vereinfachung (da der Master-Passwort-Key im State gespeichert wird) überspringen wir die Salt-Speicherung für die Key-Derivation
  // und verwenden nur IV für AES-GCM. 
  // WICHTIG: In einer echten Anwendung müsste das PBKDF2-Salt persistent gespeichert werden, um den Master-Schlüssel wiederherzustellen.
  
  const enc = new TextEncoder();
  const ciphertextBuffer = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    enc.encode(plaintext)
  );

  return {
    ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertextBuffer))),
    iv: btoa(String.fromCharCode(...iv)),
  };
};

/**
 * Entschlüsselt Text.
 * @param {CryptoKey} key Der AES-GCM-Schlüssel.
 * @param {string} ciphertext Der verschlüsselte Text.
 * @param {string} iv Der Initialization Vector (Base64).
 * @returns {Promise<string>} Der entschlüsselte Text.
 */
const decryptText = async (key, ciphertext, iv) => {
  try {
    const rawCiphertext = new Uint8Array(atob(ciphertext).split('').map(char => char.charCodeAt(0)));
    const rawIv = new Uint8Array(atob(iv).split('').map(char => char.charCodeAt(0)));

    const decryptedBuffer = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: rawIv },
      key,
      rawCiphertext
    );

    const dec = new TextDecoder();
    return dec.decode(decryptedBuffer);
  } catch (error) {
    console.error("Entschlüsselung fehlgeschlagen:", error);
    return "[ENTSTELLUNG FEHLGESCHLAGEN]";
  }
};

// --- Komponenten und Haupt-App ---

// Hilfsfunktion zum Kopieren in die Zwischenablage (iFrame-sicherer Fallback)
const copyToClipboard = (text) => {
  const textarea = document.createElement('textarea');
  textarea.value = text;
  document.body.appendChild(textarea);
  textarea.select();
  try {
    document.execCommand('copy');
    return true;
  } catch (err) {
    console.error('Kopieren fehlgeschlagen:', err);
    return false;
  } finally {
    document.body.removeChild(textarea);
  }
};

// Passwortgenerator Logik
const generatePassword = (length = 16, options = {}) => {
  const { lower = true, upper = true, number = true, symbol = true } = options;
  let charset = '';
  if (lower) charset += 'abcdefghijklmnopqrstuvwxyz';
  if (upper) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (number) charset += '0123456789';
  if (symbol) charset += '!@#$%^&*()-=_+[]{}|;:,.<>?';

  if (charset.length === 0) return '';

  let password = '';
  const charArray = Array.from(charset);
  const randomBytes = new Uint32Array(length);
  window.crypto.getRandomValues(randomBytes);

  for (let i = 0; i < length; i++) {
    password += charArray[randomBytes[i] % charArray.length];
  }

  return password;
};


// --- Hauptkomponente: App ---
const App = () => {
  const [authState, setAuthState] = useState({
    isAuthReady: false,
    userId: null,
    db: null,
  });
  const [vault, setVault] = useState([]);
  const [masterPasswordInput, setMasterPasswordInput] = useState('');
  const [masterKey, setMasterKey] = useState(null); // Der abgeleitete CryptoKey
  const [isLocked, setIsLocked] = useState(true);
  const [error, setError] = useState('');
  const [filter, setFilter] = useState('');
  const [showAddEditModal, setShowAddEditModal] = useState(false);
  const [currentEntry, setCurrentEntry] = useState(null); // Für Bearbeitung

  const { isAuthReady, userId } = authState;

  // 1. Firebase Auth und Setup
  useEffect(() => {
    if (!app || !auth || !db) return;

    const setupAuth = async () => {
      try {
        if (initialAuthToken) {
          await signInWithCustomToken(auth, initialAuthToken);
        } else {
          await signInAnonymously(auth);
        }
      } catch (e) {
        console.error("Fehler beim Anmelden:", e);
      }
    };

    const unsubscribe = onAuthStateChanged(auth, (user) => {
      setAuthState({
        isAuthReady: true,
        userId: user ? user.uid : null,
        db: db,
      });
    });

    setupAuth();
    return () => unsubscribe();
  }, []);

  // 2. Vault-Pfad
  const vaultCollectionPath = useMemo(() => {
    if (userId) {
      // Speichere private Daten unter dem Benutzerpfad
      return `artifacts/${appId}/users/${userId}/passwords`;
    }
    return null;
  }, [userId]);

  // 3. Vault-Daten aus Firestore laden (verschlüsselt)
  useEffect(() => {
    if (!vaultCollectionPath || isLocked) return;

    const q = query(collection(db, vaultCollectionPath));

    const unsubscribe = onSnapshot(q, async (snapshot) => {
      const encryptedEntries = snapshot.docs.map(doc => ({
        id: doc.id,
        ...doc.data(),
      }));

      // Versuche, alle Einträge zu entschlüsseln, wenn der Master-Schlüssel verfügbar ist
      if (masterKey) {
        const decryptedVault = await Promise.all(encryptedEntries.map(async (entry) => {
          try {
            const decryptedPassword = await decryptText(masterKey, entry.encryptedPassword.ciphertext, entry.encryptedPassword.iv);
            return {
              ...entry,
              password: decryptedPassword,
            };
          } catch (e) {
            console.error("Fehler beim Entschlüsseln eines Eintrags:", e);
            return {
              ...entry,
              password: "[DECRYPT ERROR]",
            };
          }
        }));
        setVault(decryptedVault.sort((a, b) => (b.createdAt?.toMillis() || 0) - (a.createdAt?.toMillis() || 0)));
      } else {
        // Sollte nicht passieren, wenn die Sperre aktiv ist
        setVault([]);
      }
    }, (e) => {
      console.error("Firestore Snapshot Fehler:", e);
    });

    // Clean-up Funktion
    return () => unsubscribe();
  }, [vaultCollectionPath, masterKey, isLocked]);


  // 4. Entsperr-Logik (Key-Ableitung)
  const handleUnlock = async () => {
    setError('');
    if (!masterPasswordInput) {
      setError('Bitte Master-Passwort eingeben.');
      return;
    }

    // Wir benötigen ein konsistentes Salt, um den Schlüssel abzuleiten. 
    // FÜR DIESES BEISPIEL: Da wir nur einen Session-Key ableiten, 
    // verwenden wir ein statisches, nicht geheimes App-Salt für PBKDF2.
    // In einer ECHTEN App müsste das PBKDF2-Salt persistent (aber öffentlich) gespeichert werden!
    const staticSalt = new TextEncoder().encode("VaultManagerStaticSalt");

    try {
      const derivedKey = await deriveKey(masterPasswordInput, staticSalt);
      setMasterKey(derivedKey);
      setIsLocked(false);
      setMasterPasswordInput(''); // Master-Passwort sofort löschen
    } catch (e) {
      console.error("Schlüsselableitung fehlgeschlagen:", e);
      setError('Ungültiges Master-Passwort.');
    }
  };

  // 5. Eintrag speichern/bearbeiten
  const handleSaveEntry = async (entryData) => {
    if (!masterKey || !vaultCollectionPath) {
      setError('Vault ist nicht entsperrt.');
      return;
    }

    try {
      // 1. Passwort verschlüsseln
      const encryptedData = await encryptText(masterKey, entryData.password);

      // 2. Daten für Firestore vorbereiten (ID nur, wenn es eine Bearbeitung ist)
      const dataToSave = {
        serviceName: entryData.serviceName || 'Unbenannter Service',
        username: entryData.username || 'n/a',
        url: entryData.url || '',
        notes: entryData.notes || '',
        encryptedPassword: encryptedData, // Enthält ciphertext und iv
        createdAt: entryData.id ? entryData.createdAt : serverTimestamp(),
      };

      const docRef = entryData.id 
        ? doc(db, vaultCollectionPath, entryData.id) 
        : doc(collection(db, vaultCollectionPath)); // Firestore generiert die ID

      await setDoc(docRef, dataToSave, { merge: true });
      setShowAddEditModal(false);
      setCurrentEntry(null);
    } catch (e) {
      console.error("Fehler beim Speichern des Eintrags:", e);
      setError('Speichern fehlgeschlagen: ' + e.message);
    }
  };

  // 6. Eintrag löschen
  const handleDeleteEntry = async (id) => {
    if (!vaultCollectionPath) return;

    if (window.confirm("Sind Sie sicher, dass Sie diesen Eintrag löschen möchten?")) {
      try {
        await deleteDoc(doc(db, vaultCollectionPath, id));
      } catch (e) {
        console.error("Fehler beim Löschen des Eintrags:", e);
        setError('Löschen fehlgeschlagen: ' + e.message);
      }
    }
  };
  
  // 7. Gefilterte Vault-Liste
  const filteredVault = useMemo(() => {
    const lowerCaseFilter = filter.toLowerCase();
    return vault.filter(entry =>
      entry.serviceName?.toLowerCase().includes(lowerCaseFilter) ||
      entry.username?.toLowerCase().includes(lowerCaseFilter) ||
      entry.url?.toLowerCase().includes(lowerCaseFilter)
    );
  }, [vault, filter]);


  // --- UI Komponenten: Passwortkarte (PasswordCard) ---
  const PasswordCard = ({ entry }) => {
    const [showPassword, setShowPassword] = useState(false);
    const [copyStatus, setCopyStatus] = useState(null); // 'password', 'username', null

    const handleCopy = (text, type) => {
      if (copyToClipboard(text)) {
        setCopyStatus(type);
        setTimeout(() => setCopyStatus(null), 1500);
      }
    };

    const handleEdit = () => {
      // Setzt den Eintrag und öffnet das Modal
      setCurrentEntry(entry);
      setShowAddEditModal(true);
    };

    return (
      <div className="bg-white p-4 shadow-xl rounded-xl transition duration-300 ease-in-out hover:shadow-2xl flex flex-col space-y-3">
        <div className="flex justify-between items-start">
          <div className="flex-1 min-w-0">
            <h3 className="text-xl font-bold text-gray-800 truncate" title={entry.serviceName}>
              {entry.serviceName}
            </h3>
            {entry.url && (
              <a 
                href={entry.url.startsWith('http') ? entry.url : `https://${entry.url}`} 
                target="_blank" 
                rel="noopener noreferrer" 
                className="text-sm text-blue-600 hover:underline truncate block"
                title={entry.url}
              >
                {entry.url.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0]}
              </a>
            )}
          </div>
          <div className="flex space-x-2 ml-4 flex-shrink-0">
            <button 
                onClick={() => handleEdit(entry)}
                className="p-2 text-blue-500 hover:text-blue-700 rounded-full transition duration-150"
                title="Eintrag bearbeiten"
            >
                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                  <path d="M13.586 3.586a2 2 0 112.828 2.828l-.793.793-2.828-2.828.793-.793zm-5.464 5.464a1 1 0 000 1.414l5.464 5.464a1 1 0 001.414 0 1 1 0 000-1.414l-5.464-5.464a1 1 0 00-1.414 0z" />
                </svg>
            </button>
            <button 
                onClick={() => handleDeleteEntry(entry.id)}
                className="p-2 text-red-500 hover:text-red-700 rounded-full transition duration-150"
                title="Eintrag löschen"
            >
                <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M9 2a1 1 0 00-.894.553L7.382 4H4a1 1 0 000 2v10a2 2 0 002 2h8a2 2 0 002-2V6a1 1 0 100-2h-3.382l-.724-1.447A1 1 0 0011 2H9zM7 8a1 1 0 012 0v6a1 1 0 11-2 0V8zm5-1a1 1 0 00-1 1v6a1 1 0 102 0V8a1 1 0 00-1-1z" clipRule="evenodd" />
                </svg>
            </button>
          </div>
        </div>

        {/* Benutzername Sektion */}
        <div className="flex items-center space-x-2 bg-gray-50 p-2 rounded-lg">
          <span className="text-gray-500 font-medium w-24">Nutzername:</span>
          <span className="flex-1 font-mono text-sm break-all">{entry.username}</span>
          <button 
            onClick={() => handleCopy(entry.username, 'username')}
            className={`p-1 rounded-full text-white text-xs font-semibold ${copyStatus === 'username' ? 'bg-green-500' : 'bg-blue-500 hover:bg-blue-600'}`}
          >
            {copyStatus === 'username' ? 'Kopiert!' : 'Kopieren'}
          </button>
        </div>

        {/* Passwort Sektion */}
        <div className="flex items-center space-x-2 bg-gray-50 p-2 rounded-lg">
          <span className="text-gray-500 font-medium w-24">Passwort:</span>
          <span className="flex-1 font-mono text-sm break-all">
            {showPassword ? entry.password : '••••••••••••••••'}
          </span>
          <button 
            onClick={() => setShowPassword(!showPassword)}
            className="p-1 text-gray-600 hover:text-gray-800 transition duration-150"
          >
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
              {showPassword ? (
                <path fillRule="evenodd" d="M3.707 2.293a1 1 0 00-1.414 1.414l14 14a1 1 0 001.414-1.414l-14-14zM10 5a5 5 0 00-7.07 1.93l-1.42 1.42a1 1 0 000 1.41l8.49 8.49a1 1 0 001.41 0l1.42-1.42A5 5 0 0015 10a5 5 0 00-1.55-3.55l1.41-1.41a1 1 0 00-1.41-1.41l-1.41 1.41A5.002 5.002 0 0010 5zM10 13a3 3 0 100-6 3 3 0 000 6z" clipRule="evenodd" />
              ) : (
                <path d="M10 12.5a2.5 2.5 0 100-5 2.5 2.5 0 000 5z" />
              )}
            </svg>
          </button>
          <button 
            onClick={() => handleCopy(entry.password, 'password')}
            className={`p-1 rounded-full text-white text-xs font-semibold ${copyStatus === 'password' ? 'bg-green-500' : 'bg-blue-500 hover:bg-blue-600'}`}
          >
            {copyStatus === 'password' ? 'Kopiert!' : 'Kopieren'}
          </button>
        </div>

        {/* Notizen Sektion */}
        {entry.notes && (
          <div className="bg-gray-100 p-3 rounded-lg border-l-4 border-yellow-500">
            <p className="text-sm font-semibold text-gray-700">Notizen:</p>
            <p className="text-sm text-gray-600 mt-1 whitespace-pre-wrap">{entry.notes}</p>
          </div>
        )}
      </div>
    );
  };
  
  // --- UI Komponenten: Passwort-Generator-Modal (PasswordGenerator) ---
  const PasswordGenerator = ({ onGenerate }) => {
    const [length, setLength] = useState(16);
    const [options, setOptions] = useState({ lower: true, upper: true, number: true, symbol: true });
    const [generatedPwd, setGeneratedPwd] = useState(generatePassword(16, options));

    useEffect(() => {
        setGeneratedPwd(generatePassword(length, options));
    }, [length, options]);
    
    const handleChange = (e) => {
        const newOptions = { ...options, [e.target.name]: e.target.checked };
        setOptions(newOptions);
    };

    return (
        <div className="p-4 bg-gray-50 rounded-xl shadow-inner mt-4">
            <h4 className="text-lg font-semibold mb-3 text-gray-700">Passwort-Generator</h4>
            
            <div className="mb-4">
                <label className="block text-sm font-medium text-gray-700">Länge: {length}</label>
                <input
                    type="range"
                    min="8"
                    max="32"
                    value={length}
                    onChange={(e) => setLength(Number(e.target.value))}
                    className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer range-lg"
                />
            </div>

            <div className="grid grid-cols-2 gap-2 mb-4 text-sm">
                <label className="flex items-center">
                    <input type="checkbox" name="lower" checked={options.lower} onChange={handleChange} className="mr-2 rounded text-blue-600" />
                    Kleinbuchstaben (a-z)
                </label>
                <label className="flex items-center">
                    <input type="checkbox" name="upper" checked={options.upper} onChange={handleChange} className="mr-2 rounded text-blue-600" />
                    Großbuchstaben (A-Z)
                </label>
                <label className="flex items-center">
                    <input type="checkbox" name="number" checked={options.number} onChange={handleChange} className="mr-2 rounded text-blue-600" />
                    Zahlen (0-9)
                </label>
                <label className="flex items-center">
                    <input type="checkbox" name="symbol" checked={options.symbol} onChange={handleChange} className="mr-2 rounded text-blue-600" />
                    Symbole (!@#$%)
                </label>
            </div>

            <div className="flex items-center space-x-3 bg-white p-3 border border-gray-300 rounded-lg">
                <span className="flex-1 font-mono text-sm break-all">{generatedPwd}</span>
                <button
                    type="button"
                    onClick={() => onGenerate(generatedPwd)}
                    className="px-3 py-1 bg-green-500 text-white text-sm font-semibold rounded-lg hover:bg-green-600 transition"
                >
                    Übernehmen
                </button>
            </div>
        </div>
    );
  };
  

  // --- UI Komponenten: Add/Edit Modal (AddEditModal) ---
  const AddEditModal = ({ isOpen, onClose, onSave, entry }) => {
    const [formData, setFormData] = useState({
      serviceName: '', username: '', password: '', url: '', notes: '',
    });

    useEffect(() => {
      if (entry) {
        setFormData({
          serviceName: entry.serviceName || '',
          username: entry.username || '',
          password: entry.password || '', // Entschlüsseltes Passwort
          url: entry.url || '',
          notes: entry.notes || '',
        });
      } else {
        setFormData({ serviceName: '', username: '', password: '', url: '', notes: '' });
      }
    }, [entry, isOpen]);

    if (!isOpen) return null;

    const handleChange = (e) => {
      setFormData({ ...formData, [e.target.name]: e.target.value });
    };

    const handleGeneratePassword = (newPassword) => {
        setFormData(prev => ({ ...prev, password: newPassword }));
    };

    const handleSubmit = (e) => {
      e.preventDefault();
      onSave({ ...formData, id: entry?.id, createdAt: entry?.createdAt });
    };

    return (
      <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
        <div className="bg-white rounded-2xl w-full max-w-lg shadow-2xl p-6 relative">
          <h2 className="text-2xl font-bold text-gray-800 mb-4">{entry ? 'Eintrag bearbeiten' : 'Neuen Eintrag hinzufügen'}</h2>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700">Service-Name</label>
              <input type="text" name="serviceName" value={formData.serviceName} onChange={handleChange} required className="mt-1 block w-full border border-gray-300 rounded-lg p-2 focus:ring-blue-500 focus:border-blue-500" />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700">Benutzername/E-Mail</label>
              <input type="text" name="username" value={formData.username} onChange={handleChange} required className="mt-1 block w-full border border-gray-300 rounded-lg p-2 focus:ring-blue-500 focus:border-blue-500" />
            </div>
            
            <PasswordGenerator onGenerate={handleGeneratePassword} />

            <div>
              <label className="block text-sm font-medium text-gray-700">Passwort</label>
              <input type="text" name="password" value={formData.password} onChange={handleChange} required className="mt-1 block w-full border border-gray-300 rounded-lg p-2 font-mono focus:ring-blue-500 focus:border-blue-500" />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700">URL (Optional)</label>
              <input type="url" name="url" value={formData.url} onChange={handleChange} className="mt-1 block w-full border border-gray-300 rounded-lg p-2 focus:ring-blue-500 focus:border-blue-500" placeholder="https://beispiel.de" />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700">Notizen (Optional)</label>
              <textarea name="notes" value={formData.notes} onChange={handleChange} rows="3" className="mt-1 block w-full border border-gray-300 rounded-lg p-2 focus:ring-blue-500 focus:border-blue-500"></textarea>
            </div>

            <div className="flex justify-end space-x-3 pt-4">
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 text-gray-700 bg-gray-200 rounded-xl hover:bg-gray-300 font-semibold transition"
              >
                Abbrechen
              </button>
              <button
                type="submit"
                className="px-4 py-2 bg-blue-600 text-white rounded-xl hover:bg-blue-700 font-semibold shadow-lg shadow-blue-500/50 transition"
              >
                Speichern
              </button>
            </div>
          </form>
        </div>
      </div>
    );
  };
  

  // --- Haupt-Render ---
  if (!isAuthReady) {
    return (
      <div className="flex items-center justify-center h-screen bg-gray-50 p-4">
        <div className="text-lg font-medium text-gray-600">Lade Authentifizierung...</div>
      </div>
    );
  }

  // UI für gesperrten Vault
  if (isLocked) {
    return (
      <div className="min-h-screen bg-gray-50 flex flex-col items-center justify-center p-4">
        <div className="w-full max-w-md bg-white p-8 rounded-2xl shadow-2xl">
          <h1 className="text-3xl font-extrabold text-center text-gray-800 mb-6">
            <span className="text-blue-600">Secure</span> Vault
          </h1>
          <p className="text-center text-gray-600 mb-8">
            Bitte geben Sie Ihr Master-Passwort ein, um den Vault zu entschlüsseln.
          </p>

          <div className="space-y-4">
            <input
              type="password"
              value={masterPasswordInput}
              onChange={(e) => setMasterPasswordInput(e.target.value)}
              placeholder="Master-Passwort"
              onKeyPress={(e) => e.key === 'Enter' && handleUnlock()}
              className="w-full p-3 border border-gray-300 rounded-xl focus:ring-blue-500 focus:border-blue-500 shadow-md"
              autoComplete="off"
            />
            {error && <p className="text-red-500 text-center text-sm">{error}</p>}
            
            <button
              onClick={handleUnlock}
              className="w-full py-3 bg-blue-600 text-white font-bold text-lg rounded-xl shadow-lg shadow-blue-500/50 hover:bg-blue-700 transition duration-300"
            >
              Vault entsperren
            </button>
          </div>
          <p className="text-xs text-center text-gray-400 mt-6">
            Ihr Master-Passwort wird nur zur Entschlüsselung verwendet und nicht gespeichert.
          </p>
          <p className="text-xs text-center text-gray-400 mt-2">
            Ihre Benutzer-ID (für private Daten): 
            <span className="font-mono text-gray-600 break-all ml-1">{userId || 'Gast'}</span>
          </p>
        </div>
      </div>
    );
  }

  // UI für entsperrten Vault
  return (
    <div className="min-h-screen bg-gray-50 p-4 sm:p-8 font-sans">
      <header className="flex flex-col sm:flex-row justify-between items-center mb-6 sticky top-0 bg-gray-50 pt-4 pb-4 z-40 shadow-sm border-b border-gray-200">
        <div className="mb-4 sm:mb-0">
          <h1 className="text-3xl font-extrabold text-gray-800">
            <span className="text-blue-600">Secure</span> Vault
          </h1>
          <p className="text-sm text-gray-500">Ihre {vault.length} gespeicherten Zugänge</p>
        </div>
        <div className="flex flex-wrap gap-3 w-full sm:w-auto">
          <input
            type="text"
            placeholder="Suchen nach Service/Nutzername..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="flex-1 min-w-[200px] p-2 border border-gray-300 rounded-xl focus:ring-blue-500 focus:border-blue-500 shadow-sm"
          />
          <button
            onClick={() => { setCurrentEntry(null); setShowAddEditModal(true); }}
            className="flex-shrink-0 px-4 py-2 bg-green-500 text-white font-semibold rounded-xl hover:bg-green-600 transition duration-300 shadow-md flex items-center justify-center"
          >
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 mr-1" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M10 5a1 1 0 011 1v3h3a1 1 0 110 2h-3v3a1 1 0 11-2 0v-3H6a1 1 0 110-2h3V6a1 1 0 011-1z" clipRule="evenodd" />
            </svg>
            Neuer Eintrag
          </button>
          <button
            onClick={() => { setMasterKey(null); setIsLocked(true); setVault([]); setError(''); }}
            className="flex-shrink-0 px-4 py-2 bg-red-500 text-white font-semibold rounded-xl hover:bg-red-600 transition duration-300 shadow-md"
            title="Vault sperren und Master-Passwort löschen"
          >
            Sperren
          </button>
        </div>
      </header>

      {error && (
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded-xl relative mb-4" role="alert">
          <strong className="font-bold">Fehler: </strong>
          <span className="block sm:inline">{error}</span>
        </div>
      )}

      {/* Vault List */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
        {filteredVault.length > 0 ? (
          filteredVault.map(entry => (
            <PasswordCard key={entry.id} entry={entry} />
          ))
        ) : (
          <div className="md:col-span-2 lg:col-span-3 xl:col-span-4 bg-white p-10 rounded-2xl text-center text-gray-500 shadow-lg">
            {filter ? (
              <p className="text-xl font-medium">Keine Einträge gefunden, die "<strong>{filter}</strong>" enthalten.</p>
            ) : (
              <p className="text-xl font-medium">Ihr Vault ist leer. Fügen Sie oben Ihren ersten Eintrag hinzu!</p>
            )}
            
          </div>
        )}
      </div>

      <AddEditModal
        isOpen={showAddEditModal}
        onClose={() => { setShowAddEditModal(false); setCurrentEntry(null); }}
        onSave={handleSaveEntry}
        entry={currentEntry}
      />
    </div>
  );
};

export default App;

// Setzt den Log-Level für Firestore, falls verfügbar
if (typeof setLogLevel !== 'undefined') {
    setLogLevel('Debug');
}