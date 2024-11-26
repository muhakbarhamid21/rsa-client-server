#include <netinet/in.h>   // Header untuk struktur alamat jaringan (sockaddr_in)
#include <stdio.h>        // Header untuk fungsi input/output standar
#include <string.h>       // Header untuk manipulasi string
#include <sys/socket.h>   // Header untuk fungsi socket
#include <unistd.h>       // Header untuk fungsi sistem POSIX, seperti close()
#include <openssl/evp.h>  // Header untuk fungsi kriptografi (EVP)
#include <openssl/pem.h>  // Header untuk membaca dan menulis file kunci
#include <stdlib.h>       // Header untuk fungsi standar seperti malloc dan free

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
    int server_fd, new_socket;  // Variabel untuk socket server dan koneksi baru
    struct sockaddr_in address;  // Struktur alamat untuk server
    int opt = 1;  // Opsi untuk socket (digunakan untuk pengaturan ulang)
    socklen_t addrlen = sizeof(address);  // Panjang struktur alamat

    // Memuat kunci privat server dan kunci publik client
    EVP_PKEY *server_private = load_private_key("server_private.pem");
    EVP_PKEY *client_public = load_public_key("client_public.pem");
    if (!server_private || !client_public) {  // Jika gagal memuat kunci
        fprintf(stderr, "Gagal memuat kunci.\n");
        return 1;
    }

    // Membuat socket untuk komunikasi
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket gagal");  // Pesan kesalahan jika socket gagal dibuat
        return 1;
    }

    // Mengatur opsi socket agar dapat digunakan ulang
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("Setsockopt gagal");
        return 1;
    }

    // Mengisi struktur alamat untuk server
    address.sin_family = AF_INET;           // Keluarga alamat (IPv4)
    address.sin_addr.s_addr = INADDR_ANY;  // Mendengarkan pada semua alamat jaringan yang tersedia
    address.sin_port = htons(PORT);        // Port server (dikonversi ke urutan byte jaringan)

    // Mengikat socket ke alamat dan port yang ditentukan
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind gagal");
        return 1;
    }

    // Memulai mendengarkan koneksi masuk
    if (listen(server_fd, 3) < 0) {
        perror("Listen gagal");
        return 1;
    }

    printf("Menunggu koneksi...\n");

    // Menerima koneksi dari client
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, &addrlen)) < 0) {
        perror("Accept gagal");
        return 1;
    }

    unsigned char buffer[1024] = {0};  // Buffer untuk menyimpan data yang diterima
    ssize_t len = read(new_socket, buffer, sizeof(buffer));  // Membaca data dari client
    if (len <= 0) {
        fprintf(stderr, "Tidak ada data diterima.\n");
        return 1;
    }

    // Menampilkan ciphertext yang diterima
    printf("\nPesan terenkripsi (ciphertext) dari client: ");
    print_hex(buffer, len);

    // Dekripsi pesan menggunakan kunci privat server
    size_t decrypted_len;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(server_private, NULL);  // Membuat konteks dekripsi
    EVP_PKEY_decrypt_init(ctx);  // Inisialisasi dekripsi
    EVP_PKEY_decrypt(ctx, NULL, &decrypted_len, buffer, len);  // Mendapatkan panjang hasil dekripsi
    unsigned char *decrypted = malloc(decrypted_len + 1);  // Alokasi memori untuk hasil dekripsi
    EVP_PKEY_decrypt(ctx, decrypted, &decrypted_len, buffer, len);  // Melakukan dekripsi
    decrypted[decrypted_len] = '\0';  // Menambahkan null-terminator untuk string hasil dekripsi

    // Menampilkan pesan asli setelah dekripsi
    printf("\nPesan terdekripsi dari client: %s\n", decrypted);

    // Enkripsi balasan menggunakan kunci publik client
    size_t encrypted_len;
    EVP_PKEY_CTX *enc_ctx = EVP_PKEY_CTX_new(client_public, NULL);  // Membuat konteks enkripsi
    EVP_PKEY_encrypt_init(enc_ctx);  // Inisialisasi enkripsi
    EVP_PKEY_encrypt(enc_ctx, NULL, &encrypted_len, (unsigned char *)decrypted, strlen((const char *)decrypted));  // Mendapatkan panjang hasil enkripsi
    unsigned char *encrypted = malloc(encrypted_len);  // Alokasi memori untuk hasil enkripsi
    EVP_PKEY_encrypt(enc_ctx, encrypted, &encrypted_len, (unsigned char *)decrypted, strlen((const char *)decrypted));  // Melakukan enkripsi

    // Menampilkan ciphertext yang akan dikirim ke client
    printf("\nPesan terenkripsi (ciphertext) yang dikirim ke client: ");
    print_hex(encrypted, encrypted_len);

    // Mengirim pesan terenkripsi ke client
    send(new_socket, encrypted, encrypted_len, 0);
    printf("\nBalasan terkirim.\n");

    // Membersihkan memori dan konteks
    free(decrypted);
    free(encrypted);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(enc_ctx);
    EVP_PKEY_free(server_private);
    EVP_PKEY_free(client_public);
    close(new_socket);  // Menutup socket
    return 0;
}
