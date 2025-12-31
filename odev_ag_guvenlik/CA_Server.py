# Dosya: CA_Server.py
import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
import Utils

HOST = '0.0.0.0' # Tüm ağ arayüzlerini dinle
PORT = 12345

# --- RENK PALETİ ---
BG_COLOR = "#2C3E50"
TEXT_COLOR = "#ECF0F1"
LOG_BG = "#34495E"
BTN_COLOR = "#27AE60"
FONT_MAIN = ("Consolas", 10)
FONT_HEADER = ("Segoe UI", 12, "bold")

# --- YENİ: IP ADRESİNİ OTOMATİK BULMA ---
def get_local_ip():
    """Bağlı olduğun ortak ağdaki yerel IP adresini bulur."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # 8.8.8.8'e gerçekten bağlanmaz, sadece hangi arayüzden çıkış yapacağını bulur
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

server_ip = get_local_ip()

# CA Anahtarları
try:
    ca_key_pair = Utils.generate_rsa_pair()
    ca_public_key_export = ca_key_pair.publickey().export_key().decode('utf-8')
except:
    pass

pencere = tk.Tk()
pencere.title("CA - CERTIFICATE AUTHORITY")
pencere.geometry("600x600") # IP Paneli için boyutu biraz artırdık
pencere.configure(bg=BG_COLOR)

def log(m):
    log_ekrani.config(state=tk.NORMAL)
    log_ekrani.insert(tk.END, ">> " + m + "\n")
    log_ekrani.see(tk.END)
    log_ekrani.config(state=tk.DISABLED)

def handle_client(conn, addr):
    try:
        data = conn.recv(4096).decode('utf-8').strip()
        if "|" in data:
            parts = data.split("|")
            subject_id = parts[0]
            pub_key_str = parts[1]
            
            log(f"İstek Geldi: {subject_id} ({addr[0]})")
            
            signed_cert_json = Utils.create_certificate(ca_key_pair, subject_id, int(pub_key_str))
            response = f"{signed_cert_json}###{ca_public_key_export}"
            conn.sendall(response.encode('utf-8'))
            log(f"✅ Sertifika İmzalandı -> {subject_id}")
    except Exception as e:
        log(f"Hata: {e}")
    conn.close()

def start_server():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(10)
        
        lbl_status.config(text="DURUM: AKTİF - DİNLENİYOR", fg="#2ECC71")
        log(f"CA Sunucusu Başlatıldı. IP: {server_ip} | Port: {PORT}")
        
        def accept_loop():
            while True:
                try:
                    conn, addr = s.accept()
                    threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
                except: break
        threading.Thread(target=accept_loop, daemon=True).start()
        btn_start.config(state=tk.DISABLED, bg="#7F8C8D")
    except Exception as e:
        log(f"Başlatma Hatası: {e}")

# --- ARAYÜZ DÜZENLEME ---
# Başlık
tk.Label(pencere, text="🛡️ GÜVENLİ SERTİFİKA OTORİTESİ (CA)", 
         bg=BG_COLOR, fg="#F1C40F", font=("Segoe UI", 16, "bold")).pack(pady=10)

# --- YENİ: IP GÖSTERGE PANELİ ---
frame_ip = tk.Frame(pencere, bg="#34495E", padx=15, pady=10, highlightbackground="#3498DB", highlightthickness=2)
frame_ip.pack(pady=5)
tk.Label(frame_ip, text="CA Server IP Adresi:", bg="#34495E", fg="white", font=("Arial", 9)).pack()
tk.Label(frame_ip, text=server_ip, bg="#34495E", fg="#3498DB", font=("Arial", 16, "bold")).pack()

# Durum
lbl_status = tk.Label(pencere, text="DURUM: KAPALI", bg=BG_COLOR, fg="#E74C3C", font=FONT_HEADER)
lbl_status.pack(pady=10)

# Log Alanı Çerçevesi
frame_log = tk.Frame(pencere, bg=BG_COLOR)
frame_log.pack(padx=20, pady=5, fill=tk.BOTH, expand=True)

tk.Label(frame_log, text="Sistem Logları:", bg=BG_COLOR, fg=TEXT_COLOR, font=FONT_MAIN).pack(anchor="w")
log_ekrani = scrolledtext.ScrolledText(frame_log, bg=LOG_BG, fg="#2ECC71", insertbackground="white", font=("Consolas", 9))
log_ekrani.pack(fill=tk.BOTH, expand=True)

# Başlat Butonu
btn_start = tk.Button(pencere, text="SUNUCUYU BAŞLAT", command=start_server, 
                      bg=BTN_COLOR, fg="white", font=FONT_HEADER, activebackground="#219150")
btn_start.pack(pady=20, fill=tk.X, padx=50)

pencere.mainloop()