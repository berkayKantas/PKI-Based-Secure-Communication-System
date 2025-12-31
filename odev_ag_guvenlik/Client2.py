import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
import Utils
import json

CA_PORT = 12345
CLIENT1_PORT = 6000

# --- RENK PALETİ ---
BG_COLOR = "#2C3E50"
TEXT_COLOR = "#ECF0F1"
LOG_BG = "#34495E"
INPUT_BG = "#34495E"
BTN_ORANGE = "#E67E22"
BTN_PURPLE = "#8E44AD"
BTN_BLUE = "#2980B9"

def get_my_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

my_ip_address = get_my_ip()
my_priv, my_pub = Utils.dh_generate_keys()
my_full_certificate = None
ca_public_key = None
final_key = None
p2p_socket = None

pencere = tk.Tk()
pencere.title(f"CLIENT 2 - Bağlanan Taraf")
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
    
    if not target_ca_ip:
        log("Hata: CA IP adresini girin!")
        return

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(None)
        s.connect((target_ca_ip, CA_PORT))
        s.send(f"Client2|{my_pub}".encode('utf-8'))
        raw = s.recv(8192).decode('utf-8')
        
        my_full_certificate, ca_public_key = raw.split("###")
        cert_dict = json.loads(my_full_certificate)
        log(f"✅ Sertifika Alındı! Seri No: {cert_dict['Serial_Number']}")
        
        lbl_cert_status.config(text="Sertifika: ✔️ VAR", fg="#2ECC71")
        s.close()
        
        btn_connect.config(state=tk.NORMAL)
        btn_get_cert.config(state=tk.DISABLED, bg="#7F8C8D")
        entry_ca_ip.config(state=tk.DISABLED)
        entry_username.config(state=tk.DISABLED) # Sertifika alınca ismi kilitle
    except Exception as e:
        log(f"CA Bağlantı Hatası: {e}")

def connect():
    global p2p_socket, final_key
    target_client1 = entry_target_ip.get()
    
    if not target_client1:
        log("Hata: Client 1 IP adresini girin!")
        return

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(None)
        log(f"🔗 {target_client1} adresine bağlanılıyor...")
        s.connect((target_client1, CLIENT1_PORT))
        p2p_socket = s
        
        other_cert_json = s.recv(8192).decode('utf-8')
        is_valid, other_pub_key = Utils.verify_certificate_logic(ca_public_key, other_cert_json)
        
        if is_valid:
            log("✅ Client 1 Sertifikası DOĞRULANDI")
            s.send(my_full_certificate.encode('utf-8'))
            
            shared = Utils.dh_calculate_shared_secret(my_priv, other_pub_key)
            final_key = Utils.derive_secret_key(shared)
            log(f"🔑 Session Key Oluşturuldu.")
            
            lbl_conn_status.config(text="Bağlantı: GÜVENLİ (AES-256)", fg="#2ECC71")
            entry_msg.config(state=tk.NORMAL)
            btn_send.config(state=tk.NORMAL)
            btn_connect.config(state=tk.DISABLED, bg="#7F8C8D")
            entry_target_ip.config(state=tk.DISABLED)
            
            threading.Thread(target=read_msg, daemon=True).start()
        else:
            log("❌ Sertifika SAHTE! Güvenlik ihlali.")
            s.close()
    except Exception as e:
        log(f"Bağlantı Hatası: {e}")

def read_msg():
    while True:
        try:
            d = p2p_socket.recv(1024).decode('utf-8')
            if not d: break
            decrypted = Utils.aes_decrypt(d, final_key)
            log(decrypted) # İsim zaten şifreli paketin içinde
        except: break

def send():
    username = entry_username.get().strip()
    msg = entry_msg.get()
    
    if not username:
        log("Hata: Önce bir kullanıcı adı belirleyin!")
        return
        
    if final_key and msg:
        # 1. İsmi mesajla birleştiriyoruz
        formatted_msg = f"{username}: {msg}"
        
        # 2. Şifrelerken isimli halini (formatted_msg) kullanıyoruz
        enc = Utils.aes_encrypt(formatted_msg, final_key)
        
        p2p_socket.send(enc.encode('utf-8'))
        log(f"Ben: {msg}")
        entry_msg.delete(0, tk.END)

# --- ARAYÜZ DÜZENİ ---
tk.Label(pencere, text="CLIENT 2 KONTROL PANELİ", bg=BG_COLOR, fg="#3498DB", font=("Arial", 14, "bold")).pack(pady=5)

frame_user = tk.Frame(pencere, bg=BG_COLOR)
frame_user.pack(fill=tk.X, padx=10, pady=5)
tk.Label(frame_user, text="Rumuz (Username):", bg=BG_COLOR, fg="white", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=5)
entry_username = tk.Entry(frame_user, bg=INPUT_BG, fg="#F1C40F", font=("Arial", 10, "bold"))
entry_username.insert(0, "Client_2")
entry_username.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

tk.Label(pencere, text=f"Benim IP Adresim: {my_ip_address}", bg=BG_COLOR, fg="#BDC3C7", font=("Arial", 9, "italic")).pack(pady=5)

# Adım 1: CA Sertifikası
frame_1 = tk.LabelFrame(pencere, text="Adım 1: CA Kimlik Doğrulama", bg=BG_COLOR, fg="#F39C12", font=("Arial", 10, "bold"))
frame_1.pack(fill=tk.X, padx=10, pady=5)
inner_frame1 = tk.Frame(frame_1, bg=BG_COLOR)
inner_frame1.pack(pady=5, fill=tk.X)
tk.Label(inner_frame1, text="CA IP:", bg=BG_COLOR, fg="white").pack(side=tk.LEFT, padx=5)
entry_ca_ip = tk.Entry(inner_frame1, bg=INPUT_BG, fg="white", width=15)
entry_ca_ip.insert(0, "localhost")
entry_ca_ip.pack(side=tk.LEFT, padx=5)
btn_get_cert = tk.Button(inner_frame1, text="Sertifika Al", command=get_cert, bg=BTN_ORANGE, fg="white", font=("Arial", 9, "bold"))
btn_get_cert.pack(side=tk.RIGHT, padx=10)
lbl_cert_status = tk.Label(frame_1, text="Sertifika Durumu: YOK", bg=BG_COLOR, fg="#E74C3C")
lbl_cert_status.pack(pady=5)

# Adım 2: Client 1'e Bağlantı
frame_2 = tk.LabelFrame(pencere, text="Adım 2: Client 1'e Güvenli Bağlan", bg=BG_COLOR, fg="#F39C12", font=("Arial", 10, "bold"))
frame_2.pack(fill=tk.X, padx=10, pady=5)
inner_frame2 = tk.Frame(frame_2, bg=BG_COLOR)
inner_frame2.pack(pady=10, fill=tk.X)
tk.Label(inner_frame2, text="Hedef IP:", bg=BG_COLOR, fg="white").pack(side=tk.LEFT, padx=5)
entry_target_ip = tk.Entry(inner_frame2, bg=INPUT_BG, fg="white", width=15)
entry_target_ip.insert(0, "localhost")
entry_target_ip.pack(side=tk.LEFT, padx=5)
btn_connect = tk.Button(inner_frame2, text="BAĞLAN", command=connect, bg=BTN_PURPLE, fg="white", state=tk.DISABLED, font=("Arial", 9, "bold"))
btn_connect.pack(side=tk.RIGHT, padx=10)
lbl_conn_status = tk.Label(frame_2, text="Bağlantı: KAPALI", bg=BG_COLOR, fg="#95A5A6")
lbl_conn_status.pack(pady=5)

# Log/Chat Ekranı
frame_3 = tk.LabelFrame(pencere, text="Güvenli Sohbet & Loglar", bg=BG_COLOR, fg="#F39C12", font=("Arial", 10, "bold"))
frame_3.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
log_ekrani = scrolledtext.ScrolledText(frame_3, bg=INPUT_BG, fg="white", font=("Consolas", 10), height=15)
log_ekrani.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

# Mesaj Gönderme
frame_4 = tk.Frame(pencere, bg=BG_COLOR)
frame_4.pack(fill=tk.X, padx=10, pady=10)
entry_msg = tk.Entry(frame_4, bg=INPUT_BG, fg="white", font=("Arial", 12), state=tk.DISABLED)
entry_msg.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
btn_send = tk.Button(frame_4, text="GÖNDER 🔒", command=send, bg=BTN_BLUE, fg="white", state=tk.DISABLED)
btn_send.pack(side=tk.RIGHT)

pencere.mainloop()