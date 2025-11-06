from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def demonstriere_schluessel_generierung():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    )

    print("✅ Öffentlicher Schlüssel (SSH-Format-Ausschnitt):\n")
    print(public_key.decode().split()[0] + "...") 
    print("\nDies demonstriert, dass Python kryptographische Primitive verarbeiten kann.")

if __name__ == "__main__":
    demonstriere_schluessel_generierung()