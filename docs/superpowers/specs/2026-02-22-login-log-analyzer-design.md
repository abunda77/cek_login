# Login Log Analyzer Design

## Goal

Membangun aplikasi CLI Python minimal untuk menganalisis `auth.log` Linux/SSH dan menampilkan alamat IP dengan sedikitnya 5 percobaan autentikasi gagal dalam format teks terminal yang rapi dan mudah dipindai.

## Scope

- Input berupa satu path file log dari argumen CLI.
- Baris yang dihitung adalah percobaan SSH dengan pola `Failed password ... from <IP>`.
- IP dikelompokkan dan dihitung tanpa membedakan username atau port.
- Hanya IP dengan jumlah kegagalan `>= 5` yang ditampilkan.
- Mendukung alamat IPv4 dan IPv6 melalui parser alamat standar Python.
- Output menggunakan ANSI bold/warna dan tabel ASCII berbingkai agar eye-catching di terminal.
- Program tetap menghasilkan output teks yang terbaca ketika ANSI color tidak tersedia atau output diarahkan ke non-terminal.
- Tidak ada dependency pihak ketiga.

Di luar scope: pemantauan log realtime, blocking IP/firewall, dashboard web, ekspor JSON/CSV, dan analisis jenis event login lain.

## User Interface

Perintah utama:

```bash
python analyze_login.py /var/log/auth.log
```

Output sukses dengan temuan menggunakan struktur berikut:

```text
╔══════════════════════════════════════════════════════════════╗
║                 SSH LOGIN SECURITY ANALYSIS                 ║
╠══════════════════════════════════════════════════════════════╣
║  Source : /var/log/auth.log                                ║
║  Rule   : failed authentication attempts >= 5              ║
╚══════════════════════════════════════════════════════════════╝

  SUSPICIOUS IP ADDRESSES
  ┌──────────────────────┬──────────────────┐
  │ IP ADDRESS           │ FAILED ATTEMPTS  │
  ├──────────────────────┼──────────────────┤
  │ 192.168.1.10         │                7 │
  └──────────────────────┴──────────────────┘

  ⚠ 1 IP address exceeded the failure threshold.
```

Jika tidak ada IP yang memenuhi ambang batas, program menampilkan ringkasan sukses yang menyatakan bahwa tidak ditemukan IP mencurigakan. Warna hanya sebagai peningkat visual; isi dan struktur harus tetap jelas tanpa warna.

Kesalahan penggunaan atau file tidak dapat dibaca harus ditampilkan ke stderr dengan pesan singkat dan exit code non-zero.

## Architecture

Satu modul utama `analyze_login.py` berisi fungsi-fungsi kecil yang dapat diuji terpisah:

- `extract_failed_ip(line: str) -> str | None`: mengambil IP dari baris yang cocok dengan event `Failed password` dan memvalidasi alamatnya menggunakan `ipaddress.ip_address`.
- `count_failed_attempts(lines: Iterable[str]) -> Counter[str]`: menghitung IP valid dari seluruh baris.
- `find_suspicious_ips(counts: Mapping[str, int], threshold: int = 5) -> list[tuple[str, int]]`: menyaring dan mengurutkan hasil berdasarkan jumlah terbesar, lalu alamat IP sebagai tie-breaker.
- Fungsi presentasi terminal untuk merender header, tabel, ringkasan, dan pesan error.
- `main(argv: Sequence[str] | None = None) -> int`: memvalidasi argumen, membaca file UTF-8 dengan fallback aman untuk karakter log tidak valid, menjalankan analisis, dan mengembalikan exit code.

Regex hanya digunakan untuk menemukan kandidat token setelah kata `from`; validasi final alamat dilakukan oleh `ipaddress`, sehingga username, hostname, dan token malformed tidak dihitung.

ANSI color diaktifkan saat stdout adalah TTY dan tidak sedang dimatikan oleh environment `NO_COLOR`; opsi CLI tambahan tidak dibuat karena belum dibutuhkan. Lebar tabel ditetapkan agar output konsisten dan tidak memerlukan dependency terminal.

## Error Handling

- Tanpa argumen atau argumen lebih dari satu: tampilkan usage ke stderr dan kembalikan exit code `2`.
- File tidak ditemukan, bukan file biasa, atau tidak dapat dibaca: tampilkan pesan error ke stderr dan kembalikan exit code `1`.
- Baris yang rusak atau IP tidak valid diabaikan; satu baris buruk tidak menghentikan analisis.
- File kosong tetap dianggap sukses dan menghasilkan ringkasan tanpa temuan.

## Testing

Gunakan `unittest` dari standard library dalam `tests/test_analyze_login.py` untuk memverifikasi:

- parsing baris `Failed password` IPv4;
- parsing baris `Failed password` IPv6;
- baris sukses, baris non-SSH, dan baris dengan IP malformed tidak dihitung;
- agregasi beberapa baris dari IP yang sama;
- threshold tepat 5 termasuk, threshold di bawah 5 tidak ditampilkan;
- urutan hasil berdasarkan jumlah terbesar dan tie-breaker alamat;
- `main` mengembalikan error untuk path yang tidak ada;
- output laporan memiliki header dan kolom utama yang terstruktur.

Verifikasi manual juga menjalankan CLI terhadap fixture log kecil dengan hasil temuan dan tanpa temuan.

## Acceptance Criteria

1. `python analyze_login.py <auth.log>` membaca log dan tidak gagal pada format auth.log yang umum.
2. Setiap IP dengan sedikitnya 5 baris `Failed password` muncul tepat satu kali dengan jumlah yang benar.
3. IP dengan 4 atau kurang kegagalan tidak muncul sebagai temuan.
4. Output terminal memiliki header, metadata sumber/rule, tabel berkolom, dan ringkasan yang mudah dibaca.
5. Warna/bold tidak menjadi syarat agar output tetap terbaca pada redirect/non-TTY.
6. Kesalahan input memiliki exit code non-zero dan tidak menghasilkan traceback pengguna.
7. Semua pengujian standard-library lulus tanpa dependency eksternal.
