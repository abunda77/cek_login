# SSH Login Log Analyzer

CLI Python minimal untuk menemukan alamat IP yang melakukan sedikitnya 5 percobaan autentikasi SSH gagal dari file Linux `auth.log`.

## Menjalankan

```bash
python analyze_login.py /var/log/auth.log
```

Baris yang dianalisis memiliki pola seperti:

```text
Failed password for invalid user admin from 192.0.2.10 port 22 ssh2
Failed password for root from 2001:db8::1 port 22 ssh2
```

IP dengan 5 atau lebih percobaan gagal ditampilkan dalam tabel. Output menggunakan warna dan bold saat berjalan langsung di terminal, tetapi tetap terbaca sebagai teks biasa saat diarahkan ke file atau ketika environment variable `NO_COLOR` tersedia.

Aplikasi menggunakan Python standard library saja, sehingga tidak memerlukan instalasi dependency tambahan.

## Pengujian

```bash
python -m unittest discover -s tests -v
```
