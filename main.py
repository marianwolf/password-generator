import string
import secrets
import random

def passwort_generator():
    OPTIMIZED_PUNCTUATION = "!@#$%^&*+-=?" 
    laenge = 0
    while True:
        laenge = int(input("Passwortlänge (mindestens 8): "))
        
        if laenge >= 8:
            break

    zeichen_vorrat = string.ascii_letters + string.digits 
    
    while True:
        soll_sonderzeichen = input("Sollen Sonderzeichen eingeschlossen werden? (J/n): ").lower()
        if soll_sonderzeichen in ["j", "n", "j", "N", ""]:
            break
        else:
            print("❌ Ungültige Eingabe. Bitte 'j' oder 'n' eingeben.") 

    if soll_sonderzeichen == "j" or soll_sonderzeichen == "J" or soll_sonderzeichen == "":
        zeichen_vorrat += OPTIMIZED_PUNCTUATION

    if not zeichen_vorrat:
        print("🛑 ERROR: Der Zeichenvorrat ist leer. Das Programm wird beendet.")
        return
    
    erforderliche_zeichen = []
    erforderliche_zeichen.append(secrets.choice(string.ascii_uppercase))
    erforderliche_zeichen.append(secrets.choice(string.ascii_lowercase))
    erforderliche_zeichen.append(secrets.choice(string.digits))
    
    if soll_sonderzeichen == "j":
        erforderliche_zeichen.append(secrets.choice(OPTIMIZED_PUNCTUATION))

    anzahl_erforderlich = len(erforderliche_zeichen)
    restliche_laenge = laenge - anzahl_erforderlich
    restliche_zeichen = [secrets.choice(zeichen_vorrat) for _ in range(restliche_laenge)]
    passwort_liste = erforderliche_zeichen + restliche_zeichen
    random.shuffle(passwort_liste)
    passwort = "".join(passwort_liste)

    print("\n" + "="*50)
    print(f"Dein {laenge}-stelliges Passwort:")
    print(f"{passwort}")
    print("="*50)

if __name__ == "__main__":
    passwort_generator()