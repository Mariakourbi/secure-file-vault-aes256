import os
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

def derive_key(password: str, salt: bytes) -> bytes:
    # 1. Μετατροπή password (string) σε bytes
    password_bytes = password.encode()

    # 2. Ρύθμισε τον αλγόριθμο PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,               # 32 bytes = 256 bits
        salt=salt,
        iterations=480000,
    )

    # 3. Παράξε και επέστρεψε το κλειδί καλώντας τη μέθοδο .derive() πάνω στο kdf
    #    δίνοντας ως όρισμα το password_bytes
    return kdf.derive(password_bytes)

def encrypt_data(data: bytes, password: str) -> bytes:
    # 1. Δημιούργησε τυχαίο salt 16 bytes
    salt = os.urandom(16)
    
    # 2. Κάλεσε τη derive_key για να βγάλεις το κλειδί
    key = derive_key(password, salt)
    
    # 3. Αρχικοποίησε το εργαλείο AESGCM με το κλειδί
    aesgcm = AESGCM(key)
    
    # 4. Δημιούργησε ένα τυχαίο nonce μήκους 12 bytes
    nonce = os.urandom(12)
    
    # 5. Κρυπτογράφησε τα δεδομένα 
    ciphertext = aesgcm.encrypt(nonce, data, None)
    
    return salt + nonce + ciphertext



def decrypt_data(encrypted_data: bytes, password: str) -> bytes:
    salt = encrypted_data[:16]
    nonce = encrypted_data[16:28]
    ciphertext = encrypted_data[28:]
    
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    
    # Αν ο κωδικός είναι λάθος ή τα δεδομένα αλλοιωθούν, πετάει InvalidTag
    return aesgcm.decrypt(nonce, ciphertext, None)



def encrypt_file(file_path: str, password: str):
    # 1. Διάβασε τα περιεχόμενα του αρχείου σε μορφή bytes
    with open(file_path, "rb") as f:
        file_data = f.read()
    
    # 2. Κρυπτογράφησέ τα καλώντας την encrypt_data
    encrypted_data = encrypt_data(file_data, password)
    
    # 3. Αποθήκευσε το νέο κρυπτογραφημένο αρχείο με κατάληξη .enc
    output_path = file_path + ".enc"
    with open(output_path, "wb") as f:
        f.write(encrypted_data)
        
    print(f"[+] Το αρχείο κρυπτογραφήθηκε επιτυχώς: {output_path}")

def decrypt_file(file_path: str, password: str):
    with open(file_path, "rb") as f:
        encrypted_data = f.read()
        
    try:
        decrypted_data = decrypt_data(encrypted_data, password)
    except InvalidTag:
        print("[-] Σφάλμα: Λάθος κωδικός ή το αρχείο έχει τροποποιηθεί/αλλοιωθεί!")
        return
        
    # Αφαιρούμε την κατάληξη .enc για να επαναφέρουμε το αρχικό όνομα
    output_path = file_path.replace(".enc", ".restored")
    with open(output_path, "wb") as f:
        f.write(decrypted_data)
        
    print(f"[+] Το αρχείο αποκρυπτογραφήθηκε επιτυχώς: {output_path}")



def main():
    print("=" * 45)
    print("      SECURE FILE VAULT (AES-256-GCM)")
    print("=" * 45)
    print("1. Κρυπτογράφηση αρχείου (Encrypt)")
    print("2. Αποκρυπτογράφηση αρχείου (Decrypt)")
    choice = input("Επίλεξε ενέργεια (1/2): ").strip()

    if choice not in ["1", "2"]:
        print("[-] Μη έγκυρη επιλογή.")
        return

    file_path = input("Δώσε τη διαδρομή/όνομα του αρχείου: ").strip()
    
    if not os.path.exists(file_path):
        print("[-] Το αρχείο δεν βρέθηκε!")
        return

    # Χρησιμοποιούμε getpass για να μην φαίνεται ο κωδικός στην οθόνη
    password = getpass.getpass("Δώσε το Master Password: ")

    if choice == "1":
        confirm_pass = getpass.getpass("Επιβεβαίωση Master Password: ")
        if password != confirm_pass:
            print("[-] Οι κωδικοί δεν ταιριάζουν!")
            return
        encrypt_file(file_path, password)
    else:
        decrypt_file(file_path, password)

if __name__ == "__main__":
    main()



