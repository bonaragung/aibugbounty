# AI BUG BOUNTY 🛡️🤖
**AI-Augmented Bug Bounty Scanner — Mencari Celah di Era Kecerdasan Buatan**

AI Bug Bounty adalah alat pemindaian keamanan (reconnaissance) yang menggabungkan kekuatan alat *open-source* klasik dengan kecerdasan buatan (**Llama3 8B-Instruct** via Ollama) untuk melakukan triase otomatis terhadap temuan kerentanan.

---
![Dashboard Screenshot](Screenshot.png)

## 🚀 Filosofi & Alur Kerja
Tool ini dirancang dengan prinsip bahwa AI bukanlah pengganti manusia, melainkan partner analisis yang mempercepat proses identifikasi celah keamanan.

**Alur Kerja Utama:**
1.  **RECON:** Mengumpulkan data mentah menggunakan Nmap, Nikto, dan Gobuster.
2.  **INTELLIGENT PARSING:** Melakukan filter terhadap *noise* hasil scan dan ekstraksi cerdas versi software serta CVE.
3.  **AI TRIAGE:** Mengirim ringkasan data ke LLM untuk mendapatkan analisis vektor serangan yang realistis.
4.  **REPORT:** Menghasilkan laporan teknis profesional dalam format `.txt` dan `.html`.



---

## 🛠️ Persiapan (Prerequisites)

Sebelum menjalankan tool ini, pastikan sistem kamu sudah siap:

### 1. Security Tools
Pastikan alat-alat berikut terinstal dan dapat diakses dari command line:
* **Nmap:** Untuk deteksi service dan port.
* **Nikto:** Untuk pemindaian kerentanan web.
* **Gobuster:** Untuk pencarian direktori (directory brute force).
* **Searchsploit:** Bagian dari ExploitDB untuk pemetaan eksploitasi.

### 2. Konfigurasi AI (Ollama)
Tool ini menggunakan **Ollama** sebagai backend AI lokal:
1.  Unduh dan instal [Ollama](https://ollama.com/).
2.  Tarik model Llama3:
    ```bash
    ollama pull llama3
    ```
3.  Pastikan Ollama berjalan di latar belakang (default: `http://localhost:11434`).
    ```bash
    taskkill /IM "ollama app.exe" /F
    taskkill /IM ollama.exe /F
    set OLLAMA_HOST=0.0.0.0
    ollama server
    ```

### 3. Python Dependencies
Instal pustaka Python yang diperlukan:
```bash
pip install requests psutil
pip install requests request
```

## ⚙️ Konfigurasi Script
Sebelum menjalankan, buka file redteamai.py dan sesuaikan variabel berikut di bagian KONFIGURASI:

```bash
OLLAMA_API     = "http://localhost:11434/api/generate" # Alamat API Ollama Anda
WORDLIST       = "/path/to/your/wordlist/common.txt"   # Lokasi wordlist untuk Gobuster
```

## 💻 Cara Penggunaan
Jalankan script dengan memberikan target berupa IP address atau Domain:
```bash
python3 redteamai.py <target>
```
## 📊 Hasil Laporan (Output)
Setiap sesi scan akan secara otomatis membuat folder ./reports/ yang berisi:

TXT Report: Laporan berbasis teks untuk audit cepat.

HTML Report: Laporan berbasis web dengan desain dark theme yang mencakup peta permukaan serangan, skor CVSS, dan rantai serangan (attack chain).

## ⚠️ Pernyataan Hukum (Disclaimer)
Penggunaan alat ini pada target tanpa izin tertulis sebelumnya adalah ILEGAL. Penulis tidak bertanggung jawab atas penyalahgunaan atau kerusakan yang disebabkan oleh alat ini. Gunakanlah secara etis untuk program Bug Bounty yang sah atau Penetration Testing yang legal.




