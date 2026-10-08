# Login Log Analyzer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Membangun CLI Python minimal yang membaca `auth.log`, mendeteksi IP dengan sedikitnya 5 autentikasi SSH gagal, dan menampilkan laporan terminal yang rapi serta eye-catching.

**Architecture:** Satu modul `analyze_login.py` menangani parsing, agregasi, penyaringan, rendering, dan entry point CLI. Test standard library menguji logika parser/agregasi serta alur CLI; tidak ada dependency pihak ketiga.

**Tech Stack:** Python 3.10+, standard library (`argparse`, `collections`, `ipaddress`, `pathlib`, `re`, `unittest`). ANSI escape sequence digunakan langsung untuk warna/bold.

**Spec:** `docs/superpowers/specs/2026-02-22-login-log-analyzer-design.md`

## Global Constraints

- Analisis hanya menghitung pola SSH `Failed password ... from <IP>`.
- Ambang deteksi default adalah `5`, dan nilai tepat `5` termasuk hasil.
- IPv4 dan IPv6 divalidasi dengan `ipaddress.ip_address`.
- Tidak menambah dependency pihak ketiga.
- Output harus tetap terbaca tanpa ANSI color pada non-TTY atau saat `NO_COLOR` tersedia.
- Error input mengembalikan exit code non-zero tanpa traceback pengguna.
- Perubahan harus terbatas pada aplikasi, test, dokumentasi penggunaan, dan project ignore rules.

## Review Focus

- IPv6 dengan format auth.log dan karakter setelah alamat tidak boleh salah dipotong; test parser IPv6.
- Token setelah `from` yang bukan alamat IP tidak boleh dihitung; test malformed IP/hostname.
- Ambang tepat lima harus terdeteksi, sedangkan empat tidak; test filtering.
- File log dengan karakter UTF-8 tidak valid tidak boleh menggagalkan seluruh analisis; test CLI dengan fixture bytes invalid.
- Output yang diarahkan ke non-TTY tidak boleh mengandung escape sequence dan tetap memuat struktur laporan; test rendering non-color.

---

### Task 1: Project setup and CLI test scaffolding

**Files:**
- Create: `.gitignore`
- Create: `tests/test_analyze_login.py`

**Interfaces:**
- Produces the test cases and ignored-file rules used by later tasks.

- [ ] **Step 1: Create `.gitignore`**

  Ignore Python bytecode/cache directories, virtual environments, test/coverage output, local environment files, and common IDE/OS metadata without ignoring source, tests, documentation, or sample logs.

- [ ] **Step 2: Write failing unit tests for parser and aggregation behavior**

  Add `unittest.TestCase` methods covering:
  - `extract_failed_ip` returns an IPv4 address from a standard `Failed password` line.
  - `extract_failed_ip` returns an IPv6 address from a standard line.
  - success lines, unrelated lines, hostnames, and malformed addresses return `None`.
  - `count_failed_attempts` aggregates repeated IPs.
  - `find_suspicious_ips` includes count `5`, excludes count `4`, sorts descending by count then ascending IP.

- [ ] **Step 3: Run the focused tests to confirm the expected initial failure**

  Run: `python -m unittest tests.test_analyze_login -v`

  Expected: FAIL because `analyze_login.py` and its public functions do not yet exist.

---

### Task 2: Implement log parsing and analysis rules

**Files:**
- Create: `analyze_login.py`
- Test: `tests/test_analyze_login.py`

**Interfaces:**
- Produces `extract_failed_ip(line: str) -> str | None`.
- Produces `count_failed_attempts(lines: Iterable[str]) -> Counter[str]`.
- Produces `find_suspicious_ips(counts: Mapping[str, int], threshold: int = 5) -> list[tuple[str, int]]`.

- [ ] **Step 1: Implement `extract_failed_ip`**

  Match only lines containing the SSH event phrase `Failed password` and a token after `from`; validate the captured token with `ipaddress.ip_address`. Return the normalized string form of valid IPv4/IPv6 addresses and `None` for all other lines.

- [ ] **Step 2: Implement `count_failed_attempts`**

  Iterate once over the supplied lines, call `extract_failed_ip`, and increment a `Counter` only for valid extracted addresses.

- [ ] **Step 3: Implement `find_suspicious_ips`**

  Filter counts at `threshold` inclusively, then return tuples sorted by descending count and ascending IP string. Reject a threshold below `1` with `ValueError`.

- [ ] **Step 4: Run parser and aggregation tests**

  Run: `python -m unittest tests.test_analyze_login -v`

  Expected: all parser, aggregation, threshold, sorting, IPv6, and malformed-input tests PASS.

---

### Task 3: Implement structured terminal reporting

**Files:**
- Modify: `analyze_login.py`
- Test: `tests/test_analyze_login.py`

**Interfaces:**
- Produces a renderer callable from `main` that accepts source path, suspicious results, and a color-enabled flag.
- Output includes `SSH LOGIN SECURITY ANALYSIS`, source, rule, `IP ADDRESS`, `FAILED ATTEMPTS`, and a clear no-findings or findings summary.

- [ ] **Step 1: Write failing rendering tests**

  Capture renderer output with color disabled and assert it contains the report title, source/rule metadata, table column labels, counts, and summary. Assert the non-color output contains no `\x1b[` escape sequence. Add a findings and no-findings case.

- [ ] **Step 2: Implement the report renderer**

  Render a fixed-width boxed header, section title, table with aligned columns, and summary using Unicode box-drawing characters. Apply ANSI bold/color only when explicitly enabled; use plain text otherwise. Keep the same semantic content in both modes.

- [ ] **Step 3: Run rendering tests**

  Run: `python -m unittest tests.test_analyze_login -v`

  Expected: all rendering tests PASS.

---

### Task 4: Implement the CLI entry point and file handling

**Files:**
- Modify: `analyze_login.py`
- Test: `tests/test_analyze_login.py`

**Interfaces:**
- Produces `main(argv: Sequence[str] | None = None) -> int`.
- Executable module behavior calls `raise SystemExit(main())`.

- [ ] **Step 1: Write failing CLI tests**

  Add tests that:
  - call `main([])` and assert exit code `2` plus usage on stderr;
  - call `main([missing_path])` and assert exit code `1` plus a concise error on stderr and no traceback;
  - use a temporary auth log containing five matching failures and unrelated lines, capture stdout, and assert the IP/count appear;
  - use a temporary file containing invalid UTF-8 bytes and assert `main` still returns `0`;
  - verify no-color CLI output is readable and has no ANSI escapes when stdout is captured as non-TTY.

- [ ] **Step 2: Implement `main` and file reading**

  Use one positional path argument. Read as UTF-8 with `errors="replace"`, analyze the lines, render the report, and return `0`. Convert argument errors to code `2`; catch file access errors and return `1` after writing a short message to stderr. Enable ANSI only when stdout is a TTY and `NO_COLOR` is absent.

- [ ] **Step 3: Run the full test suite**

  Run: `python -m unittest discover -s tests -v`

  Expected: all tests PASS with zero errors and zero failures.

---

### Task 5: Add usage documentation and perform acceptance verification

**Files:**
- Create: `README.md`
- Test fixture: create temporary file outside the repository during verification only.

**Interfaces:**
- Documents the command, supported log pattern, threshold behavior, output style, and test command.

- [ ] **Step 1: Write `README.md`**

  Document Python requirement, command example, supported `auth.log` examples, meaning of the suspicious-IP threshold, no-dependency setup, and test command. Mention that ANSI styling is automatically disabled for redirected output or `NO_COLOR`.

- [ ] **Step 2: Run automated verification**

  Run: `python -m unittest discover -s tests -v`

  Expected: exit code `0`, all tests pass.

- [ ] **Step 3: Run manual CLI verification with a temporary fixture**

  Create a temporary auth log with five failures from one IP and fewer failures from another, run `python analyze_login.py <fixture>`, and verify the report contains the first IP/count but not the second IP. Run against an empty fixture and verify the no-findings summary.

- [ ] **Step 4: Review the final diff and project status**

  Run: `git diff --check`, `git status --short`, and inspect that only the planned files are present. Confirm no generated bytecode, cache, or local environment files are tracked.
