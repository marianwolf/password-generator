"""
Verschlüsselungsmodul für den Passwort-Manager.
Verwendet Cryptography-Bibliothek für sichere Verschlüsselung.
"""

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os
import hashlib


class EncryptionManager:
    """Verwaltet die Verschlüsselung und Entschlüsselung von Passwörtern."""
    
    def __init__(self, master_password: str, salt: bytes = None):
        """
        Initialisiert den EncryptionManager.
        
        Args:
            master_password: Das Master-Passwort für die Verschlüsselung
            salt: Optionaler Salt-Wert für die Schlüsselgenerierung
        """
        if salt is None:
            salt = os.urandom(16)
        self.salt = salt
        self.key = self._derive_key(master_password)
        self.cipher = Fernet(self.key)
    
    def _derive_key(self, password: str) -> bytes:
        """Leitet einen Verschlüsselungsschlüssel aus dem Master-Passwort ab."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=480000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    def encrypt(self, data: str) -> str:
        """
        Verschlüsselt einen String.
        
        Args:
            data: Der zu verschlüsselnde String
            
        Returns:
            Base64-kodierter verschlüsselter String
        """
        encrypted = self.cipher.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        """
        Entschlüsselt einen String.
        
        Args:
            encrypted_data: Der Base64-kodierte verschlüsselte String
            
        Returns:
            Der entschlüsselte Klartext
        """
        decoded = base64.urlsafe_b64decode(encrypted_data.encode())
        return self.cipher.decrypt(decoded).decode()
    
    def get_salt(self) -> bytes:
        """Gibt den Salt-Wert zurück."""
        return self.salt
    
    @staticmethod
    def hash_password(password: str) -> str:
        """
        Erstellt einen Hash eines Passworts (für Master-Passwort-Überprüfung).
        
        Args:
            password: Das zu hashende Passwort
            
        Returns:
            Der SHA-256 Hash als Hex-String
        """
        return hashlib.sha256(password.encode()).hexdigest()
