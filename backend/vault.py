#!/usr/bin/env python3
"""
Secure Vault Configuration Manager
===================================

This module provides a secure vault for storing sensitive configuration
such as environment variables, API keys, and credentials.

Features:
- Encryption at rest on disk
- In-memory only decryption
- Automatic .env parsing and vault migration
- Access logging for all vault operations
- Fallback strategy for vault unavailability
- "VAULT_" prefix for stored secrets

Usage:
    from vault import Vault
    
    vault = Vault()
    vault.initialize()
    
    # Get a secret
    api_key = vault.get('API_KEY')
    
    # Set a secret
    vault.set('NEW_SECRET', 'value')
"""

import os
import sys
import json
import logging
import secrets
import hashlib
import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from getpass import getpass
from contextlib import contextmanager

# Configure module logger
logger = logging.getLogger(__name__)


class VaultSecurityError(Exception):
    """Base exception for vault security errors."""
    pass


class VaultNotInitializedError(VaultSecurityError):
    """Raised when vault is not initialized."""
    pass


class VaultDecryptionError(VaultSecurityError):
    """Raised when vault decryption fails."""
    pass


class VaultAccessError(VaultSecurityError):
    """Raised when vault access is denied."""
    pass


class AuditLogger:
    """
    Secure audit logger for vault operations.
    Ensures sensitive data never appears in logs.
    """
    
    def __init__(self, log_file: str = 'logs/vault_audit.log'):
        self.log_file = log_file
        self._ensure_log_directory()
        
        # Create audit logger
        self.audit_logger = logging.getLogger('vault_audit')
        self.audit_logger.setLevel(logging.INFO)
        
        # File handler for audit log
        handler = logging.FileHandler(log_file)
        handler.setFormatter(
            logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        )
        self.audit_logger.addHandler(handler)
        
        # Console handler for errors
        error_handler = logging.StreamHandler(sys.stderr)
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        )
        self.audit_logger.addHandler(error_handler)
    
    def _ensure_log_directory(self):
        """Ensure log directory exists."""
        log_dir = Path(self.log_file).parent
        log_dir.mkdir(parents=True, exist_ok=True)
    
    def log_access(self, operation: str, key: str, success: bool, 
                   user: str = 'system', details: Optional[str] = None):
        """
        Log a vault access operation.
        
        Args:
            operation: Type of operation (GET, SET, DELETE, INIT)
            key: The key being accessed (never the value!)
            success: Whether the operation was successful
            user: User performing the operation
            details: Additional non-sensitive details
        """
        # NEVER log the actual value - only metadata
        log_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'operation': operation,
            'key_hash': self._hash_key(key),
            'success': success,
            'user': user,
            'details': details
        }
        
        if success:
            self.audit_logger.info(json.dumps(log_entry))
        else:
            self.audit_logger.warning(json.dumps(log_entry))
    
    def log_error(self, error_type: str, message: str, recoverable: bool):
        """
        Log a vault error without exposing sensitive data.
        
        Args:
            error_type: Type of error
            message: Error message (sanitized, no sensitive data)
            recoverable: Whether the error was recoverable
        """
        log_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'error_type': error_type,
            'message': message,
            'recoverable': recoverable
        }
        
        if recoverable:
            self.audit_logger.warning(json.dumps(log_entry))
        else:
            self.audit_logger.error(json.dumps(log_entry))
    
    @staticmethod
    def _hash_key(key: str) -> str:
        """Create a one-way hash of a key for logging."""
        return hashlib.sha256(key.encode()).hexdigest()[:16]


class VaultEncryption:
    """
    Handles encryption and decryption of vault data.
    Uses AES-256-GCM for authenticated encryption.
    """
    
    def __init__(self, master_key: bytes):
        """
        Initialize encryption with a master key.
        
        Args:
            master_key: The master encryption key (32 bytes for AES-256)
        """
        self.master_key = master_key
        self._cipher = AESGCM(master_key)
    
    @classmethod
    def generate_key(cls, password: str, salt: Optional[bytes] = None) -> tuple:
        """
        Generate an encryption key from a password using PBKDF2.
        
        Args:
            password: The master password
            salt: Optional salt (generated if not provided)
            
        Returns:
            Tuple of (key, salt)
        """
        if salt is None:
            salt = secrets.token_bytes(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = kdf.derive(password.encode())
        
        return key, salt
    
    def encrypt(self, data: str) -> bytes:
        """
        Encrypt data using AES-256-GCM.
        
        Args:
            data: Plain text data to encrypt
            
        Returns:
            Encrypted data with nonce prepended
        """
        nonce = secrets.token_bytes(12)  # 96 bits for GCM
        encrypted = self._cipher.encrypt(nonce, data.encode(), None)
        
        # Prepend nonce to encrypted data
        return nonce + encrypted
    
    def decrypt(self, encrypted_data: bytes) -> str:
        """
        Decrypt data using AES-256-GCM.
        
        Args:
            encrypted_data: Encrypted data with nonce prepended
            
        Returns:
            Decrypted plain text
            
        Raises:
            VaultDecryptionError: If decryption fails
        """
        try:
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            decrypted = self._cipher.decrypt(nonce, ciphertext, None)
            return decrypted.decode()
        except Exception as e:
            raise VaultDecryptionError(
                "Failed to decrypt vault data. The master key may be incorrect."
            ) from e


class Vault:
    """
    Secure configuration vault for sensitive data.
    
    The vault provides:
    - Encrypted storage on disk
    - In-memory decryption only
    - Automatic .env migration
    - Secure audit logging
    - Fallback strategies
    """
    
    VAULT_PREFIX = "VAULT_"
    VAULT_FILE = "data/vault.enc"
    ENV_FILE = ".env"
    
    def __init__(self, vault_dir: Optional[str] = None, 
                 master_password: Optional[str] = None,
                 auto_initialize: bool = True):
        """
        Initialize the vault.
        
        Args:
            vault_dir: Directory for vault storage (default: app directory)
            master_password: Master password for encryption
            auto_initialize: Whether to auto-initialize on first access
        """
        self.app_dir = Path(vault_dir) if vault_dir else Path(__file__).parent
        self.vault_file = self.app_dir / self.VAULT_FILE
        self.env_file = self.app_dir / (self.VAULT_PREFIX + self.ENV_FILE)
        
        self._master_password: Optional[str] = None
        self._encryption: Optional[VaultEncryption] = None
        self._is_initialized: bool = False
        self._is_unlocked: bool = False
        self._data: Dict[str, Any] = {}
        self._audit_logger = AuditLogger()
        
        # Auto-initialize if enabled
        if auto_initialize:
            self._auto_initialize(master_password)
    
    def _auto_initialize(self, master_password: Optional[str] = None):
        """
        Automatically initialize the vault.
        
        Steps:
        1. Check if vault exists
        2. If not, create new vault with master password
        3. If exists, unlock with master password
        4. Parse any .env files and migrate to vault
        """
        try:
            if self.vault_file.exists():
                # Vault exists, attempt to unlock
                self.unlock(master_password)
            else:
                # Create new vault
                self._create_vault(master_password)
            
            # Migrate .env files
            self._migrate_env_files()
            
        except VaultSecurityError as e:
            self._audit_logger.log_error(
                "INIT_ERROR",
                str(e),
                recoverable=False
            )
            raise
    
    def _create_vault(self, master_password: Optional[str] = None):
        """
        Create a new vault with the given master password.
        
        Args:
            master_password: Master password for encryption
        """
        if master_password is None:
            master_password = self._prompt_master_password()
        
        # Generate encryption key from password
        key, salt = VaultEncryption.generate_key(master_password)
        
        # Generate unique vault ID
        vault_id = secrets.token_urlsafe(16)
        
        # Create vault metadata
        metadata: Dict[str, Any] = {
            'vault_id': vault_id,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'version': '1.0.0',
            'salt': base64.b64encode(salt).decode()
        }
        
        # Initialize empty data store
        self._data: Dict[str, Any] = {
            '__metadata__': metadata,
            '__keys__': []  # Track all keys for auditing
        }
        
        # Create encryption handler
        self._encryption = VaultEncryption(key)
        self._master_password = master_password  # Keep in memory only
        
        # Save vault
        self._save()
        
        self._is_initialized = True
        self._is_unlocked = True
        
        self._audit_logger.log_access(
            operation='CREATE',
            key='*VAULT*',
            success=True,
            details=f"Vault created with ID: {vault_id}"
        )
    
    def unlock(self, master_password: Optional[str] = None) -> bool:
        """
        Unlock the vault with the master password.
        
        Args:
            master_password: Master password for decryption
            
        Returns:
            True if unlock successful
            
        Raises:
            VaultSecurityError: If unlock fails
        """
        if not self.vault_file.exists():
            raise VaultNotInitializedError(
                "Vault does not exist. Please initialize the vault first."
            )
        
        try:
            # Load encrypted vault
            with open(self.vault_file, 'rb') as f:
                encrypted_data = f.read()
            
            # Extract salt from metadata (first 200 bytes contain JSON)
            try:
                # Attempt to read salt from encrypted metadata area
                salt_b64 = encrypted_data[:200].decode('utf-8').split('"salt":"')[1].split('"')[0]
                salt = base64.b64decode(salt_b64)
            except (UnicodeDecodeError, IndexError, KeyError):
                # Fallback: use old salt or generate new
                salt = secrets.token_bytes(16)
            
            if master_password is None:
                master_password = self._prompt_master_password()
            
            # Derive key and attempt decryption
            key, _ = VaultEncryption.generate_key(master_password, salt)
            encryption = VaultEncryption(key)
            
            # Try to decrypt
            decrypted = encryption.decrypt(encrypted_data[200:])
            self._data = json.loads(decrypted)
            
            # Verify vault integrity
            if '__metadata__' not in self._data:
                raise VaultDecryptionError("Invalid vault structure")
            
            self._encryption = encryption
            self._master_password = master_password  # Keep in memory only
            self._is_initialized = True
            self._is_unlocked = True
            
            self._audit_logger.log_access(
                operation='UNLOCK',
                key='*VAULT*',
                success=True,
                details=f"Vault unlocked successfully"
            )
            
            return True
            
        except Exception as e:
            self._audit_logger.log_access(
                operation='UNLOCK',
                key='*VAULT*',
                success=False,
                details="Invalid master password or corrupted vault"
            )
            raise VaultAccessError(
                "Failed to unlock vault. Invalid master password or corrupted data."
            ) from e
    
    def lock(self):
        """Lock the vault and clear in-memory data."""
        self._data.clear()
        self._master_password = None
        self._is_unlocked = False
        
        self._audit_logger.log_access(
            operation='LOCK',
            key='*VAULT*',
            success=True,
            details="Vault locked"
        )
    
    def _prompt_master_password(self) -> str:
        """
        Securely prompt for master password.
        
        Returns:
            Master password from user input
        """
        # Check for environment variable first
        env_password = os.environ.get('VAULT_MASTER_PASSWORD')
        if env_password:
            return env_password
        
        # Prompt user (only if interactive)
        if sys.stdin.isatty():
            return getpass("Enter vault master password: ")
        
        raise VaultAccessError(
            "No master password provided. Set VAULT_MASTER_PASSWORD "
            "environment variable or run interactively."
        )
    
    def _save(self):
        """Save the vault to disk with encryption."""
        if self._encryption is None:
            raise VaultNotInitializedError("Vault not initialized")
        
        # Serialize data (exclude sensitive raw values from logs)
        json_data = json.dumps(self._data)
        
        # Encrypt data
        encrypted = self._encryption.encrypt(json_data)
        
        # Create parent directory if needed
        self.vault_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Write to file with secure permissions
        mode = 0o600  # Owner read/write only
        self.vault_file.write_bytes(encrypted)
        os.chmod(self.vault_file, mode)
        
        self._audit_logger.log_access(
            operation='SAVE',
            key='*VAULT*',
            success=True,
            details=f"Vault saved with {len(self._data)} entries"
        )
    
    def _migrate_env_files(self):
        """
        Migrate .env files to the vault.
        
        Searches for:
        - .env
        - .env.{FLASK_ENV}
        - .env.{VAULT_PREFIX}*
        """
        if not self._is_unlocked:
            raise VaultNotInitializedError("Vault must be unlocked to migrate")
        
        env_files = [
            self.app_dir / self.ENV_FILE,
            self.app_dir / f".env.{os.environ.get('FLASK_ENV', 'development')}",
        ]
        
        for env_file in env_files:
            if env_file.exists():
                self._parse_and_migrate_env(env_file)
    
    def _parse_and_migrate_env(self, env_file: Path):
        """
        Parse an .env file and migrate secrets to the vault.
        
        Args:
            env_file: Path to .env file
        """
        self._audit_logger.log_access(
            operation='MIGRATE',
            key=str(env_file),
            success=True,
            details="Starting .env migration"
        )
        
        migrated_count = 0
        skipped_count = 0
        
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                
                # Parse KEY=VALUE format
                if '=' not in line:
                    continue
                
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                # Skip non-sensitive entries
                if self._is_sensitive_key(key):
                    # Add VAULT_ prefix and store
                    vault_key = self.VAULT_PREFIX + key
                    self.set(vault_key, value, persist=False)
                    migrated_count += 1
                else:
                    skipped_count += 1
        
        # Save after migration
        self._save()
        
        self._audit_logger.log_access(
            operation='MIGRATE',
            key=str(env_file),
            success=True,
            details=f"Migrated {migrated_count} secrets, skipped {skipped_count} non-sensitive"
        )
        
        # Securely delete the .env file
        self._secure_delete_env_file(env_file)
    
    @staticmethod
    def _is_sensitive_key(key: str) -> bool:
        """
        Determine if a key contains sensitive data.
        
        Args:
            key: The environment variable key
            
        Returns:
            True if the key likely contains sensitive data
        """
        sensitive_patterns = [
            'KEY', 'SECRET', 'PASSWORD', 'CREDENTIAL',
            'TOKEN', 'API', 'AUTH', 'JWT',
            'ENCRYPTION', 'PRIVATE', 'CERTIFICATE',
            'DATABASE_URL', 'CONNECTION_STRING'
        ]
        
        upper_key = key.upper()
        return any(pattern in upper_key for pattern in sensitive_patterns)
    
    def _secure_delete_env_file(self, file_path: Path):
        """
        Securely delete an .env file by overwriting before unlink.
        
        Args:
            file_path: Path to file to delete
        """
        try:
            if file_path.exists():
                # Overwrite with random data 3 times
                file_size = file_path.stat().st_size
                for _ in range(3):
                    with open(file_path, 'wb') as f:
                        f.write(secrets.token_bytes(file_size))
                
                # Rename before delete to hide traces
                temp_path = file_path.with_suffix('.tmp')
                file_path.rename(temp_path)
                temp_path.unlink()
                
                self._audit_logger.log_access(
                    operation='DELETE',
                    key=str(file_path),
                    success=True,
                    details="Securely deleted .env file"
                )
        except Exception as e:
            self._audit_logger.log_error(
                "DELETE_ERROR",
                f"Failed to securely delete {file_path}: {str(e)}",
                recoverable=True
            )
    
    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """
        Get a secret from the vault.
        
        Args:
            key: The key to retrieve (VAULT_ prefix optional)
            default: Default value if key not found
            
        Returns:
            The secret value or default
            
        Raises:
            VaultNotInitializedError: If vault not initialized
        """
        if not self._is_unlocked:
            raise VaultNotInitializedError("Vault is locked. Please unlock first.")
        
        # Add VAULT_ prefix if not present
        if not key.startswith(self.VAULT_PREFIX):
            key = self.VAULT_PREFIX + key
        
        value = self._data.get(key, default)
        
        self._audit_logger.log_access(
            operation='GET',
            key=key,
            success=value is not None,
            details=f"Key{'found' if value else 'not found'}"
        )
        
        return value
    
    def set(self, key: str, value: str, persist: bool = True):
        """
        Set a secret in the vault.
        
        Args:
            key: The key (VAULT_ prefix added automatically)
            value: The secret value
            persist: Whether to persist to disk immediately
            
        Raises:
            VaultNotInitializedError: If vault not initialized
        """
        if not self._is_unlocked:
            raise VaultNotInitializedError("Vault is locked. Please unlock first.")
        
        # Add VAULT_ prefix if not present
        if not key.startswith(self.VAULT_PREFIX):
            key = self.VAULT_PREFIX + key
        
        # Store in memory
        self._data[key] = value
        
        # Track keys for auditing
        if key not in self._data.get('__keys__', []):
            keys = self._data.get('__keys__', [])
            keys.append(key)
            self._data['__keys__'] = keys
        
        # Persist if requested
        if persist:
            self._save()
        
        self._audit_logger.log_access(
            operation='SET',
            key=key,
            success=True,
            details="Secret stored in vault"
        )
    
    def delete(self, key: str, persist: bool = True):
        """
        Delete a secret from the vault.
        
        Args:
            key: The key to delete
            persist: Whether to persist to disk immediately
        """
        if not self._is_unlocked:
            raise VaultNotInitializedError("Vault is locked. Please unlock first.")
        
        # Add VAULT_ prefix if not present
        if not key.startswith(self.VAULT_PREFIX):
            key = self.VAULT_PREFIX + key
        
        if key in self._data:
            del self._data[key]
            
            # Remove from keys list
            keys_list: list = self._data.get('__keys__', [])
            if key in keys_list:
                keys_list.remove(key)
                self._data['__keys__'] = keys_list
        
        if persist:
            self._save()
        
        self._audit_logger.log_access(
            operation='DELETE',
            key=key,
            success=True,
            details="Secret deleted from vault"
        )
    
    def list_keys(self) -> List[str]:
        """
        List all keys in the vault.
        
        Returns:
            List of key names (without VAULT_ prefix)
        """
        if not self._is_unlocked:
            raise VaultNotInitializedError("Vault is locked. Please unlock first.")
        
        keys = self._data.get('__keys__', [])
        return [k.replace(self.VAULT_PREFIX, '') for k in keys if not k.startswith('__')]
    
    def get_all(self) -> Dict[str, str]:
        """
        Get all secrets from the vault.
        
        Returns:
            Dictionary of all secrets
        """
        if not self._is_unlocked:
            raise VaultNotInitializedError("Vault is locked. Please unlock first.")
        
        return {
            k.replace(self.VAULT_PREFIX, ''): v 
            for k, v in self._data.items() 
            if k.startswith(self.VAULT_PREFIX)
        }
    
    def rotate_master_key(self, new_password: str):
        """
        Rotate the master encryption key.
        
        Args:
            new_password: New master password
        """
        if not self._is_unlocked:
            raise VaultNotInitializedError("Vault is locked. Please unlock first.")
        
        # Generate new key
        new_key, salt = VaultEncryption.generate_key(new_password)
        
        # Re-encrypt all data with new key
        new_encryption = VaultEncryption(new_key)
        encrypted = new_encryption.encrypt(json.dumps(self._data))
        
        # Update salt and encryption
        metadata: Dict[str, Any] = self._data.get('__metadata__', {})
        metadata['salt'] = base64.b64encode(salt).decode()
        metadata['rotated_at'] = datetime.now(timezone.utc).isoformat()
        self._data['__metadata__'] = metadata
        self._encryption = new_encryption
        self._master_password = new_password
        
        # Save with new encryption
        self.vault_file.write_bytes(encrypted)
        
        self._audit_logger.log_access(
            operation='ROTATE',
            key='*VAULT*',
            success=True,
            details="Master key rotated successfully"
        )
    
    @contextmanager
    def secure_session(self):
        """
        Context manager for temporary vault access.
        
        Usage:
            with vault.secure_session() as v:
                api_key = v.get('API_KEY')
            # Vault is automatically locked after
        """
        try:
            yield self
        finally:
            self.lock()
    
    @property
    def is_initialized(self) -> bool:
        """Check if vault is initialized."""
        return self._is_initialized
    
    @property
    def is_unlocked(self) -> bool:
        """Check if vault is unlocked."""
        return self._is_unlocked


# Integration with Flask application
class VaultConfig:
    """
    Flask configuration wrapper that loads from vault.
    """
    
    def __init__(self, vault: Vault):
        self.vault = vault
    
    def init_app(self, app):
        """
        Initialize Flask app with vault configuration.
        
        Args:
            app: Flask application instance
        """
        # Load all vault secrets into Flask config
        for key, value in self.vault.get_all().items():
            app.config[key] = value
        
        # Make vault available in app context
        app.vault = self.vault


# CLI interface for vault management
def main():
    """CLI interface for vault management."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Vault Configuration Manager'
    )
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Create vault command
    create_parser = subparsers.add_parser('create', help='Create a new vault')
    create_parser.add_argument('--password', help='Master password')
    
    # Set secret command
    set_parser = subparsers.add_parser('set', help='Set a secret')
    set_parser.add_argument('key', help='Secret key')
    set_parser.add_argument('value', help='Secret value')
    
    # Get secret command
    get_parser = subparsers.add_parser('get', help='Get a secret')
    get_parser.add_argument('key', help='Secret key')
    
    # List secrets command
    subparsers.add_parser('list', help='List all secrets')
    
    args = parser.parse_args()
    
    try:
        vault = Vault()
        
        if args.command == 'create':
            vault._create_vault(args.password)
            print("Vault created successfully")
        
        elif args.command == 'set':
            vault.set(args.key, args.value)
            print(f"Secret {args.key} set successfully")
        
        elif args.command == 'get':
            value = vault.get(args.key)
            if value:
                print(f"{args.key}: {value}")
            else:
                print(f"Key {args.key} not found")
        
        elif args.command == 'list':
            keys = vault.list_keys()
            for key in keys:
                print(f"- {key}")
        
        else:
            parser.print_help()
    
    except VaultSecurityError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
