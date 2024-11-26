#include <arpa/inet.h>   // Header untuk operasi jaringan seperti inet_pton
#include <stdio.h>       // Header untuk fungsi input/output standar
#include <string.h>      // Header untuk manipulasi string
#include <sys/socket.h>  // Header untuk fungsi socket
#include <unistd.h>      // Header untuk fungsi sistem POSIX seperti close()
#include <openssl/evp.h> // Header untuk fungsi kriptografi (EVP)
#include <openssl/pem.h> // Header untuk membaca dan menulis file kunci
#include <stdlib.h>      // Header untuk fungsi standar seperti malloc dan free

#define PORT 8080  // Port yang digunakan untuk komunikasi server-client

// Fungsi untuk memuat kunci privat dari file
EVP_PKEY *load_private_key(const char *filename) {
    FILE *file = fopen(filename, "r");  // Membuka file kunci privat
    if (!file) {
        fprintf(stderr, "Gagal membuka file kunci privat: %s\n", filename);
        return NULL;
    }
    // Membaca kunci privat dari file
    EVP_PKEY *pkey = PEM_read_PrivateKey(file, NULL, NULL, NULL);
    fclose(file);  // Menutup file setelah membaca
    return pkey;   // Mengembalikan pointer ke kunci privat
}

// Fungsi untuk memuat kunci publik dari file
EVP_PKEY *load_public_key(const char *filename) {
    FILE *file = fopen(filename, "r");  // Membuka file kunci publik
    if (!file) {
        fprintf(stderr, "Gagal membuka file kunci publik: %s\n", filename);
        return NULL;
    }
    // Membaca kunci publik dari file
    EVP_PKEY *pkey = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    fclose(file);  // Menutup file setelah membaca
    return pkey;   // Mengembalikan pointer ke kunci publik
}

// Fungsi untuk mencetak data dalam format heksadesimal (digunakan untuk mencetak ciphertext)
void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);  // Mencetak setiap byte dalam format dua digit heksadesimal
    }
    printf("\n");
}

int main() {
    int sock;  // Variabel untuk socket client
    struct sockaddr_in serv_addr;  // Struktur alamat untuk server

    // Memuat kunci publik server dan kunci privat client
    EVP_PKEY *server_public = load_public_key("server_public.pem");
    EVP_PKEY *client_private = load_private_key("client_private.pem");
    if (!server_public || !client_private) {  // Jika gagal memuat kunci
        fprintf(stderr, "Gagal memuat kunci.\n");
        return 1;
    }

    // Membuat socket untuk komunikasi
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "Socket gagal.\n");
        return 1;
    }

    // Mengisi struktur alamat server
    serv_addr.sin_family = AF_INET;           // Keluarga alamat (IPv4)
    serv_addr.sin_port = htons(PORT);        // Port server (dikonversi ke urutan byte jaringan)

    // Mengonversi alamat IP ke format jaringan
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        fprintf(stderr, "Alamat tidak valid.\n");
        return 1;
    }

    // Menghubungkan ke server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        fprintf(stderr, "Koneksi gagal.\n");
        return 1;
    }

    // Memasukkan pesan dari pengguna
    char message[1024];  // Buffer untuk pesan pengguna
    printf("Masukkan pesan rahasia: ");
    fgets(message, sizeof(message), stdin);  // Membaca input dari pengguna
    message[strcspn(message, "\n")] = '\0';  // Menghapus karakter newline dari input

    // Enkripsi pesan menggunakan kunci publik server
    size_t encrypted_len;  // Variabel untuk menyimpan panjang ciphertext
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(server_public, NULL);  // Membuat konteks enkripsi
    EVP_PKEY_encrypt_init(ctx);  // Inisialisasi enkripsi
    EVP_PKEY_encrypt(ctx, NULL, &encrypted_len, (unsigned char *)message, strlen(message));  // Mendapatkan panjang ciphertext
    unsigned char *encrypted = malloc(encrypted_len);  // Alokasi memori untuk ciphertext
    EVP_PKEY_encrypt(ctx, encrypted, &encrypted_len, (unsigned char *)message, strlen(message));  // Melakukan enkripsi

    // Menampilkan ciphertext sebelum pengiriman
    printf("\nPesan terenkripsi (ciphertext) yang dikirim ke server: ");
    print_hex(encrypted, encrypted_len);

    // Mengirim pesan terenkripsi ke server
    send(sock, encrypted, encrypted_len, 0);  // Mengirim data melalui socket
    printf("\nPesan rahasia terkirim.\n");

    // Menerima balasan terenkripsi dari server
    unsigned char buffer[1024] = {0};  // Buffer untuk data yang diterima
    ssize_t len = read(sock, buffer, sizeof(buffer));  // Membaca data dari server
    if (len <= 0) {
        fprintf(stderr, "Tidak ada balasan diterima.\n");
        return 1;
    }

    // Menampilkan ciphertext balasan dari server
    printf("\nBalasan terenkripsi (ciphertext) dari server: ");
    print_hex(buffer, len);

    // Dekripsi balasan menggunakan kunci privat client
    size_t decrypted_len;  // Variabel untuk panjang hasil dekripsi
    EVP_PKEY_CTX *dec_ctx = EVP_PKEY_CTX_new(client_private, NULL);  // Membuat konteks dekripsi
    EVP_PKEY_decrypt_init(dec_ctx);  // Inisialisasi dekripsi
    EVP_PKEY_decrypt(dec_ctx, NULL, &decrypted_len, buffer, len);  // Mendapatkan panjang hasil dekripsi
    unsigned char *decrypted = malloc(decrypted_len + 1);  // Alokasi memori untuk hasil dekripsi
    EVP_PKEY_decrypt(dec_ctx, decrypted, &decrypted_len, buffer, len);  // Melakukan dekripsi
    decrypted[decrypted_len] = '\0';  // Menambahkan null-terminator untuk string hasil dekripsi

    // Menampilkan pesan hasil dekripsi
    printf("\nBalasan terdekripsi: %s\n", decrypted);

    // Membersihkan memori dan konteks
    free(encrypted);
    free(decrypted);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(dec_ctx);
    EVP_PKEY_free(server_public);
    EVP_PKEY_free(client_private);
    close(sock);  // Menutup socket
    return 0;
}
