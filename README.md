# RSA-CLIENT-SERVER

Sistem komunikasi aman antara client dan server menggunakan algoritma RSA berbasis socket. Proyek ini dirancang untuk mengenkripsi dan mendekripsi pesan antara client dan server untuk memastikan keamanan, integritas, dan autentikasi data selama transmisi.

## **Fitur**

- Enkripsi pesan menggunakan **kunci publik RSA**.
- Dekripsi pesan menggunakan **kunci privat RSA**.
- Komunikasi antara client dan server melalui **socket**.
- Proteksi data terhadap penyadapan atau modifikasi selama transmisi.
- Implementasi dengan bahasa **C** menggunakan pustaka **OpenSSL**.

## **Persyaratan**

- GCC (GNU Compiler Collection)
- OpenSSL (untuk enkripsi dan dekripsi)

## **Cara Menggunakan**

Ikuti langkah-langkah berikut untuk menjalankan:

### **1. Clone Repository**

Clone repository dari GitHub ke komputer lokal:

```bash
git clone https://github.com/muhakbarhamid21/RSA-CLIENT-SERVER.git
cd RSA-CLIENT-SERVER
```

### **2. Install Dependencies**

Pastikan memiliki OpenSSL dan GCC terinstal pada sistem:

- Ubuntu/Debian:

```bash
sudo apt update
sudo apt install build-essential openssl libssl-dev
```

- MacOS (menggunakan Homebrew):

```bash
brew install openssl
```

- Windows:

  1. Download dan install [MinGW](https://sourceforge.net/projects/mingw/) untuk GCC.
  2. Install [OpenSSL](https://slproweb.com/products/Win32OpenSSL.html) dari slproweb.

### **3. Membuat Kunci RSA**

Buat kunci RSA untuk client dan server menggunakan perintah berikut:

```bash
# Membuat kunci privat dan publik untuk server
openssl genpkey -algorithm RSA -out server/server_private.pem
openssl rsa -pubout -in server/server_private.pem -out server/server_public.pem

# Membuat kunci privat dan publik untuk client
openssl genpkey -algorithm RSA -out client/client_private.pem
openssl rsa -pubout -in client/client_private.pem -out client/client_public.pem
```

### **4. Kompilasi Program**

Kompilasi kode client dan server menggunakan GCC:

```bash
# Kompilasi server
gcc -o server/server server/server.c -lssl -lcrypto

# Kompilasi client
gcc -o client/client client/client.c -lssl -lcrypto

```

### **5. Menjalankan Program**

- Jalankan server terlebih dahulu:

```bash
./server/server
```

- Jalankan client setelah server siap (jalankan beda tempat dari server):

```bash
./client/client
```

## **Arsitektur Sistem**

<div align="center">
  <img src="https://github.com/user-attachments/assets/7e6169db-ba43-472f-9927-a68887678236"/>
</div>

## **Alur Proses Sistem**

<div align="center">
  <img src="https://github.com/user-attachments/assets/45e20d4c-7963-4f49-9729-9b28c22fb471"/>
</div>

## **Lisensi**

Proyek ini dilisensikan di bawah MIT [LICENSE](https://pages.github.com/).
