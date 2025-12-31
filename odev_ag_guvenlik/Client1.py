import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
import Utils
import json

# Sabit Değerler
CA_PORT = 12345
MY_P2P_PORT = 6000

# --- RENK PALETİ ---
BG_COLOR = "#2C3E50"
TEXT_COLOR = "#ECF0F1"
INPUT_BG = "#34495E"
BTN_ORANGE = "#E67E22"
BTN_BLUE = "#2980B9"

def get_my_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except: return "127.0.0.1"

my_ip_address = get_my_ip()
my_priv, my_pub = Utils.dh_generate_keys()
my_full_certificate = None
ca_public_key = None
final_key = None
p2p_socket = None

pencere = tk.Tk()
pencere.title(f"CLIENT 1 - Bekleyen Taraf")
pencere.geometry("500x700")
pencere.configure(bg=BG_COLOR)

def log(m):
    log_ekrani.config(state=tk.NORMAL)
    log_ekrani.insert(tk.END, ">> " + m + "\n")
    log_ekrani.see(tk.END)
    log_ekrani.config(state=tk.DISABLED)

def get_cert():
    global my_full_certificate, ca_public_key
    target_ca_ip = entry_ca_ip.get()

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(None)
        log(f"CA'ya bağlanılıyor: {target_ca_ip}:{CA_PORT}...")
        s.connect((target_ca_ip, CA_PORT))
        
        # Kullanıcı adını ve Diffie-Hellman public key'i gönder
        s.send(f"{entry_username.get()}|{my_pub}".encode('utf-8'))
        raw = s.recv(8192).decode('utf-8')
        
        my_full_certificate, ca_public_key = raw.split("###")
        log(f"✅ Sertifika Alındı!")
        lbl_cert_status.config(text="Sertifika: ✔️ VAR", fg="#2ECC71")
        s.close()
        
        # Sertifika alındıktan sonra P2P dinlemeye başla
        threading.Thread(target=wait_client2, daemon=True).start()
        btn_get_cert.config(state=tk.DISABLED, bg="#7F8C8D")
        entry_ca_ip.config(state=tk.DISABLED)
        entry_username.config(state=tk.DISABLED)
    except Exception as e:
        log(f"CA Bağlantı Hatası: {e}")

def wait_client2():
    global p2p_socket, final_key
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', MY_P2P_PORT))
        s.listen(1)
        log(f"⏳ Client 2 bekleniyor... (Port: {MY_P2P_PORT})")
        lbl_conn_status.config(text="Bağlantı: BEKLENİYOR...", fg="#F1C40F")
        
        conn, addr = s.accept()
        p2p_socket = conn
        log(f"🔗 Bağlantı Geldi: {addr[0]}")
        
        # Sertifika Değişimi
        conn.send(my_full_certificate.encode('utf-8'))
        other_cert_json = conn.recv(8192).decode('utf-8')
        
        # Sertifika Doğrulama
        is_valid, other_pub_key = Utils.verify_certificate_logic(ca_public_key, other_cert_json)
        
        if is_valid:
            log("✅ Sertifika DOĞRULANDI")
            shared = Utils.dh_calculate_shared_secret(my_priv, other_pub_key)
            final_key = Utils.derive_secret_key(shared)
            lbl_conn_status.config(text="Bağlantı: GÜVENLİ (AES-256)", fg="#2ECC71")
            entry_msg.config(state=tk.NORMAL)
            btn_send.config(state=tk.NORMAL)
            threading.Thread(target=read_msg, daemon=True).start()
        else:
            log("❌ Sertifika SAHTE!")
            conn.close()
    except Exception as e:
        log(f"P2P Hatası: {e}")

def read_msg():
    while True:
        try:
            d = p2p_socket.recv(1024).decode('utf-8')
            if not d: break
            log(Utils.aes_decrypt(d, final_key))
        except: break

def send():
    username = entry_username.get().strip()
    msg = entry_msg.get()
    
    if final_key and msg:
        formatted_msg = f"{username}: {msg}"
        enc = Utils.aes_encrypt(formatted_msg, final_key)
        p2p_socket.send(enc.encode('utf-8'))
        log(f"Ben: {msg}")
        entry_msg.delete(0, tk.END)

# --- ARAYÜZ ---
tk.Label(pencere, text="CLIENT 1 KONTROL PANELİ", bg=BG_COLOR, fg="#3498DB", font=("Arial", 14, "bold")).pack(pady=5)

# Kullanıcı Adı (Username)
frame_user = tk.Frame(pencere, bg=BG_COLOR)
frame_user.pack(fill=tk.X, padx=10, pady=5)
tk.Label(frame_user, text="Rumuz (Username):", bg=BG_COLOR, fg="white").pack(side=tk.LEFT, padx=5)
entry_username = tk.Entry(frame_user, bg=INPUT_BG, fg="#F1C40F", font=("Arial", 10, "bold"))
entry_username.insert(0, "Client_1")
entry_username.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

tk.Label(pencere, text=f"Benim IP Adresim: {my_ip_address}", bg=BG_COLOR, fg="#BDC3C7", font=("Arial", 9, "italic")).pack(pady=5)

# Adım 1: CA Bağlantısı (Sadece IP)
frame_1 = tk.LabelFrame(pencere, text="Adım 1: CA Kimlik Doğrulama", bg=BG_COLOR, fg="#F39C12", font=("Arial", 10, "bold"))
frame_1.pack(fill=tk.X, padx=10, pady=5)

inner_frame = tk.Frame(frame_1, bg=BG_COLOR)
inner_frame.pack(pady=5, fill=tk.X)

tk.Label(inner_frame, text="CA IP:", bg=BG_COLOR, fg="white").pack(side=tk.LEFT, padx=5)
entry_ca_ip = tk.Entry(inner_frame, bg=INPUT_BG, fg="white", width=25)
entry_ca_ip.insert(0, "localhost") # Varsayılan olarak localhost
entry_ca_ip.pack(side=tk.LEFT, padx=5)

btn_get_cert = tk.Button(inner_frame, text="Sertifika Al", command=get_cert, bg=BTN_ORANGE, fg="white", font=("Arial", 9, "bold"))
btn_get_cert.pack(side=tk.RIGHT, padx=10)

lbl_cert_status = tk.Label(frame_1, text="Sertifika: YOK", bg=BG_COLOR, fg="#E74C3C")
lbl_cert_status.pack(pady=5)

# Adım 2: P2P Durumu
frame_2 = tk.LabelFrame(pencere, text="Adım 2: P2P Bağlantısı", bg=BG_COLOR, fg="#F39C12", font=("Arial", 10, "bold"))
frame_2.pack(fill=tk.X, padx=10, pady=5)
lbl_conn_status = tk.Label(frame_2, text="Bağlantı: KAPALI", bg=BG_COLOR, fg="#95A5A6")
lbl_conn_status.pack(pady=10)

# Güvenli Sohbet
frame_3 = tk.LabelFrame(pencere, text="Güvenli Sohbet", bg=BG_COLOR, fg="#F39C12", font=("Arial", 10, "bold"))
frame_3.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
log_ekrani = scrolledtext.ScrolledText(frame_3, bg=INPUT_BG, fg="white", font=("Consolas", 10), height=15)
log_ekrani.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

# Mesaj Gönder
frame_4 = tk.Frame(pencere, bg=BG_COLOR)
frame_4.pack(fill=tk.X, padx=10, pady=10)
entry_msg = tk.Entry(frame_4, bg=INPUT_BG, fg="white", font=("Arial", 12), state=tk.DISABLED)
entry_msg.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
btn_send = tk.Button(frame_4, text="GÖNDER", command=send, bg=BTN_BLUE, fg="white", state=tk.DISABLED)
btn_send.pack(side=tk.RIGHT)

pencere.mainloop()