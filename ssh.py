import subprocess
import os
import sys

KEY_FILE_NAME = "ssh_key" 

def generate_ssh_key_safe():
    ssh_dir = os.path.join(os.path.expanduser("~"), ".ssh")
    os.makedirs(ssh_dir, exist_ok=True)
    private_key_path = os.path.join(ssh_dir, KEY_FILE_NAME)
    public_key_path = f"{private_key_path}.pub"
    if os.path.exists(private_key_path):
        print("ERROR: Der private Schlüssel existiert bereits.")
        print(f"Die Datei {private_key_path} wird NICHT überschrieben.")
        print("Löschen Sie die Datei manuell oder ändern Sie den KEY_FILE_NAME.")
        return
    command = [
        "ssh-keygen", 
        "-t", "rsa", 
        "-b", "4096", 
        "-f", private_key_path,
        "-q"
    ]

    try:
        subprocess.run(command, check=True, capture_output=True, text=True, stdin=sys.stdin)
        
        with open(public_key_path, 'r') as f:
            public_key_content = f.read().strip()
            
        print("\nSchlüsselpaar erfolgreich generiert.")
        print("Öffentlicher Schlüssel (Inhalt der .pub-Datei):\n")
        print(public_key_content)
        
        print("\nSpeicherort:")
        print(f"Privater Schlüssel (NICHT TEILEN): {private_key_path}")
        print(f"Öffentlicher Schlüssel: {public_key_path}")
        
    except FileNotFoundError:
        print("\nERROR: Der Befehl 'ssh-keygen' wurde nicht gefunden. Stellen Sie sicher, dass OpenSSH installiert ist.")
    except subprocess.CalledProcessError as e:
        print(f"\nERROR beim Ausführen von ssh-keygen: {e.stderr.strip()}")
    except Exception as e:
        print(f"\nERROR: Ein unerwarteter Fehler ist aufgetreten: {e}")

if __name__ == "__main__":
    generate_ssh_key_safe()