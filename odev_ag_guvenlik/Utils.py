# Dosya: Utils.py
import json
import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# --- SABİT DEĞERLER ---
P = 23
G = 5

# --- DIFFIE HELLMAN ---
def dh_generate_keys():
    private_key = int.from_bytes(get_random_bytes(1), 'big') % (P - 1) + 1
    public_key = pow(G, private_key, P)
    return private_key, public_key

def dh_calculate_shared_secret(my_private, other_public):
    return pow(other_public, my_private, P)

def derive_secret_key(master_key_int):
    """
    Master Key (Km) kullanılarak Session Key (Ks) türetir.
    Hocanın 3. maddesindeki (Obtaining Ks using Km) şartını sağlar.
    """
    # 1. Master Key'i byte haline getir
    mk_bytes = str(master_key_int).encode('utf-8')
    
    # 2. Araya sabit bir "Context/Salt" verisi ekle.
    # NOT: Burada rastgele sayı kullanmıyoruz, çünkü iki Client'ın da
    # AYNI session key'i bulması lazım. Bu ekleme Km ve Ks'yi birbirinden ayırır.
    salt = b"2025_Term_Project_Secure_Session_Salt" 
    
    # 3. Km + Salt birleşimini Hash'le (SHA-256)
    digest = SHA256.new()
    digest.update(mk_bytes + salt)
    
    # Çıkan sonuç bizim Session Key'imizdir (Ks)
    return digest.digest()

# --- AES ŞİFRELEME ---
def aes_encrypt(plain_text, secret_key):
    iv = get_random_bytes(16)
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    encrypted_bytes = cipher.encrypt(pad(plain_text.encode('utf-8'), AES.block_size))
    encoded = base64.b64encode(iv + encrypted_bytes).decode('utf-8')
    # Hocaya kanıt için:
    print(f"--> ŞİFRELİ VERİ: {encoded}")
    return encoded

def aes_decrypt(cipher_text_b64, secret_key):
    try:
        raw = base64.b64decode(cipher_text_b64)
        iv = raw[:16]
        encrypted_bytes = raw[16:]
        cipher = AES.new(secret_key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(encrypted_bytes), AES.block_size).decode('utf-8')
    except:
        return "[Şifre Çözülemedi]"

# --- X.509 SERTİFİKA İŞLEMLERİ (GÜNCELLENDİ) ---

def generate_rsa_pair():
    return RSA.generate(2048)

def create_certificate(ca_private_key, subject_id, public_key_val):
    """
    İstenilen X.509 alanlarını içeren bir sözlük (JSON) oluşturur ve imzalar.
    """
    # 1. Sertifika İçeriği (Unsigned Certificate)
    cert_data = {
        "Serial_Number": int.from_bytes(get_random_bytes(4), 'big'), # Rastgele Seri No
        "Subject_ID": subject_id,
        "Validity_Period": "2025-01-01 to 2026-01-01",
        "Algorithm_ID": "Diffie-Hellman",
        "Public_Key_Value": public_key_val
    }
    
    # 2. İmzalanacak veriyi string'e çevir (Canonicalize)
    cert_string = json.dumps(cert_data, sort_keys=True)
    
    # 3. İmzala
    h = SHA256.new(cert_string.encode('utf-8'))
    signature = pkcs1_15.new(ca_private_key).sign(h)
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    
    # 4. İmzayı sertifikaya ekle
    cert_data["CA_Digital_Signature"] = signature_b64
    
    # JSON olarak döndür
    return json.dumps(cert_data)

def verify_certificate_logic(ca_public_key_pem, cert_json_str):
    """
    Sertifikanın imzasını ve içeriğini doğrular.
    """
    try:
        cert_dict = json.loads(cert_json_str)
        signature_b64 = cert_dict.pop("CA_Digital_Signature") # İmzayı ayır
        
        # Geriye kalan veri (Unsigned part)
        unsigned_data_str = json.dumps(cert_dict, sort_keys=True)
        
        # Doğrulama
        key = RSA.import_key(ca_public_key_pem)
        h = SHA256.new(unsigned_data_str.encode('utf-8'))
        sig = base64.b64decode(signature_b64)
        pkcs1_15.new(key).verify(h, sig)
        
        return True, cert_dict["Public_Key_Value"]
    except Exception as e:
        print(f"Doğrulama Hatası: {e}")
        return False, None