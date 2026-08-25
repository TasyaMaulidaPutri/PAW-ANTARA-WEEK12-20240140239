# Tugas Week 12 — Keamanan Web Dasar

**Nama:** Tasya Maulida Putri
**NIM:** 20240140239
**Kelas:** A
**Repo asal:** https://github.com/Kakonoomoide/PAW-ANTARA-WEEK12

> Catatan cara baca dokumen ini: setiap bukti di bawah aslinya dijalanin & di-screenshot
> langsung di browser (`http://localhost:3000/...`) sesuai instruksi tugas. Supaya gampang
> direproduksi ulang oleh siapa aja yang mau ngecek, tiap bagian juga saya sertain
> **request persis yang dikirim** (method + payload) dan **potongan HTML hasil render**
> yang jadi dasar screenshot-nya — tinggal buka URL yang sama di browser buat lihat
> versi visualnya.

---

## Bagian 1 — Eksplorasi Kerentanan (`secure-search-app`)

Setup: `cp .env.example .env`, set `ENABLE_VULN_DEMO=true`, `npm install`, `npm run seed`,
`npm run dev`, login `admin` / `password123`, lalu buka tiap halaman `/demo/*`.

### Screenshot 1 — SQL Injection (`/demo/sql-injection`)

**Payload:** `' OR '1'='1` di kotak search.

**Hasil:**

| Kolom | Query yang jalan | Hasil |
|---|---|---|
| ✅ AMAN (`Op.iLike`, Sequelize) | parameterized, `q` dikirim terpisah dari query | **0 produk** — diperlakukan sebagai teks pencarian literal |
| ⚠️ RENTAN (raw query) | `SELECT * FROM products WHERE name ILIKE '%${q}%'` → jadi `...ILIKE '%' OR '1'='1%'` | **5 produk (SEMUA produk)** — filter search berhasil di-bypass |

```
<img width="959" height="481" alt="Screenshot 2026-08-25 164743" src="https://github.com/user-attachments/assets/aaa66eb1-05fb-4ce5-9e98-df12290fa2ef" />
```

**Kenapa payload ini bisa tembus:** di `controllers/demo.unsafe.controller.js`
fungsi `sqlInjectionDemo`, query rentan dibikin dengan **menyambung string SQL
secara manual** pakai template literal:

```js
const unsafeQueryString = `SELECT * FROM products WHERE name ILIKE '%${q}%'`;
const [rows] = await sequelize.query(unsafeQueryString);
```

Karena `q` langsung disisipkan ke dalam string SQL, tanda kutip `'` di payload
`' OR '1'='1` berhasil **"kabur" dari konteks nilai** dan mengubah struktur
query jadi punya kondisi `OR '1'='1'` yang selalu `TRUE`, sehingga WHERE clause
jadi selalu benar dan semua baris ikut kebawa. Bandingkan dengan versi aman
yang pakai `Product.findAll({ where: { name: { [Op.iLike]: ... } } })` — di
situ Sequelize mengirim query dan value **terpisah** lewat parameterized
query/prepared statement, jadi `q` selamanya cuma dianggap data, bukan kode SQL.

---

### Screenshot 2 — XSS Reflected (`/demo/xss`)

**Payload:** `<script>alert('XSS dari '+document.cookie)</script>` di kotak input.

```
<img width="959" height="481" alt="Screenshot 2026-08-25 164743" src="https://github.com/user-attachments/assets/bcbee2a0-1120-4658-95d3-d289c5ef41e5" />
```

Potongan hasil render (dari kotak "Hasil di-render (unescaped)"):

```html
<div class="border border-dashed border-red-300 rounded p-3 text-sm">
  <script>alert('XSS dari '+document.cookie)</script>
</div>
```

**Kenapa payload ini bisa tembus:** di `views/demo/xss.ejs`, input ditampilkan
ulang pakai tag EJS **`<%- input %>`** (raw output, dash bukan sama-dengan),
bukan `<%= input %>`. Karena itu string `<script>...</script>` dikirim apa
adanya ke HTML tanpa di-escape, browser membacanya sebagai tag `<script>`
sungguhan dan mengeksekusinya — bukan ditampilkan sebagai teks. `input`
sendiri juga tidak difilter/divalidasi sama sekali di
`controllers/demo.unsafe.controller.js` (`xssDemo`), jadi apa pun yang
diketik user langsung diteruskan ke view.

---

### Screenshot 3 — XSS Stored (`/search-unsafe-demo`)

**Cara reproduksi:** buka `/search-unsafe-demo`, search apa saja (mis. `a`)
supaya semua produk termasuk produk demo ikut muncul.

```
<img width="959" height="470" alt="Screenshot 2026-08-25 164940" src="https://github.com/user-attachments/assets/28a672d9-c2b8-4b35-a2c9-9451c920e258" />
```

Potongan hasil render:

```html
<h3 class="font-semibold text-gray-800 mb-2">
  <script>alert("Stored XSS dari nama produk")</script>
</h3>
```

**Kenapa payload ini bisa tembus:** payload `<script>...</script>` sudah
"nempel" permanen di kolom `name` salah satu produk lewat `seeders/seed.js`
(disimpan sejak awal, bukan dari input user saat itu juga). Saat
`views/search-unsafe.ejs` merender daftar produk, nama produk ditampilkan
pakai `<%- %>` (unescaped) — sama seperti kasus reflected, cuma sumber
datanya dari database, bukan dari query string. Karena itu payload ini
**ke-trigger otomatis ke SEMUA orang** yang membuka halaman tersebut, tidak
hanya orang yang mengetik payload-nya — inilah yang membedakan stored XSS
dari reflected XSS.

---

### Screenshot 4 — Escape HTML (`/demo/escape-html`)

**Payload:** `<img src=x onerror=alert(1)>`

```
<img width="958" height="475" alt="Screenshot 2026-08-25 164631" src="https://github.com/user-attachments/assets/9a13751e-f08c-476f-9485-d183eb8e9a8b" />
```

Potongan hasil render, dua cara berdampingan:

```html
<!-- ✅ Pake <%= input %> (auto-escape) -->
<div>&lt;img src=x onerror=alert(1)&gt;</div>

<!-- ⚠️ Pake <%- input %> (raw, TIDAK di-escape) -->
<div><img src=x onerror=alert(1)></div>
```

**Kenapa payload ini bisa tembus (di kotak kanan):** `views/demo/escape-html.ejs`
sengaja menampilkan variabel `input` yang sama dengan dua cara berbeda —
`<%= input %>` mengubah karakter `<`, `>`, dll menjadi HTML entity
(`&lt;`, `&gt;`) sehingga browser menampilkannya sebagai teks biasa, sedangkan
`<%- input %>` menyisipkan string mentah ke HTML. Karena `<img>` yang
`src`-nya sengaja rusak (`x`) memicu event `onerror`, browser langsung
menjalankan `alert(1)` yang ada di dalam atribut tersebut — ini contoh XSS
yang tidak butuh tag `<script>` sama sekali, cukup lewat event handler HTML.

---

## Bagian 2 — Implementasi Mandiri: Halaman "Komentar Produk"

**Tema:** form komentar produk (nama, email, isi komentar) + daftar komentar +
fitur cari komentar. Halaman baru, terpisah dari kode demo Bagian 1, dengan
akses lewat `/komentar` (login dulu di `/login`, lalu klik link "ke halaman
Komentar Produk (Bagian 2)" di `/demo`, atau langsung buka `/komentar`).

File yang ditambahkan/diubah:

```
models/comment.model.js         # model baru
models/index.js                 # daftarin model Comment
middlewares/validators.js       # + komentarValidationRules, komentarSearchRules
controllers/comment.controller.js
routes/comment.routes.js
views/komentar.ejs
app.js                          # daftarin commentRoutes
```

### 1) Validasi server-side

**Kode** (`middlewares/validators.js`):

```js
const komentarValidationRules = [
  body('name')
    .trim()
    .isLength({ min: 3, max: 50 })
    .withMessage('Nama harus 3-50 karakter')
    .matches(/^[a-zA-Z\s]+$/)
    .withMessage('Nama cuma boleh huruf & spasi, gak boleh angka/simbol')
    .escape(),
  body('email')
    .trim()
    .isEmail()
    .withMessage('Format email gak valid')
    .normalizeEmail(),
  body('message')
    .trim()
    .isLength({ min: 5, max: 300 })
    .withMessage('Komentar harus 5-300 karakter')
    .escape(),
];
```

Dipasang di route (`routes/comment.routes.js`) **sebelum** controller:
`router.post('/komentar', requireAuth, captureRawBody, komentarValidationRules, handleValidationErrors, commentController.submitKomentar)`.

**Bukti:** submit langsung lewat `curl` (skip form HTML/JS client sama sekali)
dengan data tidak valid — nama pakai angka & simbol, email salah format, pesan
kepanjekan:

```bash
curl -X POST http://localhost:3000/komentar \
  --data-urlencode "name=Budi123!!!" \
  --data-urlencode "email=bukan-email" \
  --data-urlencode "message=hi"
```

Hasil: **HTTP 400**, server menolak dan menampilkan pesan spesifik per field
(bukan cuma "invalid" generik):

```
❌ Ditolak server, ada yang gak valid:
• Nama cuma boleh huruf & spasi, gak boleh angka/simbol
• Format email gak valid
• Komentar harus 5-300 karakter
```

```
<img width="956" height="478" alt="Screenshot 2026-08-25 171222" src="https://github.com/user-attachments/assets/93997e1f-c3e5-4686-abdc-8adb8f2facdf" />
```

Karena pengecekan ada di `komentarValidationRules` yang jalan **di server**
(bukan cuma atribut `required` di HTML atau validasi JS di browser), request
yang dikirim langsung lewat `curl`/Postman pun tetap ditolak — membuktikan
validasi tidak bisa dibypass hanya dengan mematikan JavaScript di browser.

### 2) Sanitasi input sebelum disimpan

**Kode:** `.trim()` (buang spasi nempel) dan `.escape()` (ubah karakter
HTML-sensitif jadi entity aman) dijalankan di `komentarValidationRules` yang
sama, sebelum data masuk `Comment.create(...)`.

**Before/after** (dari `req.rawBodyForDemo` yang di-snapshot sebelum sanitasi
oleh `captureRawBody`, dibandingkan dengan `req.body` sesudahnya):

```bash
curl -X POST http://localhost:3000/komentar \
  --data-urlencode "name=  Budi Santoso  " \
  --data-urlencode "email= Budi.S+promo@GMAIL.com " \
  --data-urlencode "message=  Produk ini <b>lumayan</b> bagus juga  "
```

| Field | Sebelum (raw) | Sesudah (disanitasi) |
|---|---|---|
| `name` | `"  Budi Santoso  "` | `"Budi Santoso"` |
| `message` | `"  Produk ini <b>lumayan</b> bagus juga  "` | `"Produk ini &amp;lt;b&amp;gt;lumayan&amp;lt;&amp;#x2F;b&amp;gt; bagus juga"` (tampil sbg `Produk ini &lt;b&gt;lumayan&lt;/b&gt; bagus juga` di HTML — tag `<b>` sudah jadi teks, bukan elemen HTML aktif lagi) |
| `email` | `" Budi.S+promo@GMAIL.com "` | `"budis+promo@gmail.com"` (lowercase, spasi hilang) |

```
<img width="956" height="476" alt="Screenshot 2026-08-25 171547" src="https://github.com/user-attachments/assets/5f547b24-beab-42bf-9448-bc158647844a" />
```

### 3) Escape saat render (anti-XSS)

**Kode** (`views/komentar.ejs`) — memakai `<%= %>`, **bukan** `<%- %>`, untuk
semua data yang berasal dari user:

```ejs
<p class="text-sm font-semibold text-gray-800">
  <%= c.name %> <span class="text-xs text-gray-400 font-normal">(<%= c.email %>)</span>
</p>
<p class="text-sm text-gray-600 mt-1"><%= c.message %></p>
```

**Bukti:** submit komentar dengan payload persis seperti Bagian 1:

```bash
curl -X POST http://localhost:3000/komentar \
  --data-urlencode "name=Penyerang" \
  --data-urlencode "email=penyerang@evil.com" \
  --data-urlencode "message=<script>alert('XSS dari '+document.cookie)</script>"
```

Hasil render di HTML (bukan lewat DevTools, ini betulan yang dikirim server):

```html
<p class="text-sm text-gray-600 mt-1">
  &amp;lt;script&amp;gt;alert(&amp;#x27;XSS dari &amp;#x27;+document.cookie)&amp;lt;&amp;#x2F;script&amp;gt;
</p>
```

Payload tampil sebagai **teks biasa** (`<script>alert('XSS dari '+document.cookie)</script>`
apa adanya di layar), **tidak muncul popup `alert()`** sama sekali.

```
<img width="1920" height="1080" alt="Screenshot (836)" src="https://github.com/user-attachments/assets/db44ef31-0aeb-4459-a4d9-5d60e239629b" />
```

*Catatan:* di implementasi ini payload malah ter-escape **dua kali** (sekali
oleh `.escape()` saat sanitasi sebelum disimpan, sekali lagi oleh `<%= %>`
saat render) — jadi tampil sebagai teks entity ganda. Ini bukan bug; intinya
tag `<script>` tidak pernah dianggap HTML aktif oleh browser di titik mana
pun, baik saat disimpan maupun saat ditampilkan.

### 4) Parameterized query / ORM

**Kode simpan** (`controllers/comment.controller.js`):

```js
// INSERT — Sequelize generate "INSERT INTO comments (...) VALUES ($1,$2,$3)"
// dengan value dikirim terpisah, bukan string yang disambung manual
await Comment.create({
  name: req.body.name,
  email: req.body.email,
  message: req.body.message,
});
```

**Kode cari** (fitur search komentar, `showKomentarPage`):

```js
const where = q
  ? {
      [Op.or]: [
        { name: { [Op.iLike]: `%${q}%` } },
        { message: { [Op.iLike]: `%${q}%` } },
      ],
    }
  : undefined;

const comments = await Comment.findAll({ where, order: [['createdAt', 'DESC']] });
```

Tidak ada satu pun query di fitur ini yang dibangun dengan menyambung string
SQL manual (`sequelize.query(\`... ${q} ...\`)`) — semuanya lewat method
Sequelize ORM (`create`, `findAll` + operator `Op.iLike`/`Op.or`), yang
otomatis memakai parameterized query/prepared statement di level driver `pg`.

### 5) Serang halaman sendiri — buktikan gagal tembus

**Percobaan XSS** (payload sama seperti Bagian 1, lihat poin 3 di atas):
hasil **gagal** — tersimpan & tertampil sebagai teks biasa, tidak ada
`alert()` yang jalan.

**Percobaan SQL Injection** — payload `' OR '1'='1` di kotak search:

```bash
curl -G "http://localhost:3000/komentar" --data-urlencode "q=' OR '1'='1"
```

Hasil: **`0 komentar`** ditampilkan (bukan "semua komentar"), sama seperti
kolom AMAN di Bagian 1 — payload diperlakukan sebagai teks pencarian literal
yang memang tidak match komentar manapun.

**Percobaan UNION SELECT** (coba curi tabel `users`):

```bash
curl -G "http://localhost:3000/komentar" \
  --data-urlencode "q=' UNION SELECT username, password, 1 FROM users --"
```

Hasil: server tetap merespons normal (**HTTP 200**, halaman `/komentar`
ter-render biasa) dengan **`0 komentar`** — tidak ada error SQL yang bocor ke
user, dan tentu saja tidak ada data tabel `users` yang ikut tertampil.

```
<img width="959" height="476" alt="Screenshot 2026-08-25 171905" src="https://github.com/user-attachments/assets/0600568b-d1ea-4bcb-808e-2085a4b1560c" />

<img width="959" height="474" alt="image" src="https://github.com/user-attachments/assets/ba232794-4b52-4e9c-b048-50c7059c4e09" />
```

---

## Ringkasan Bagian 2 — 5 Syarat Terpenuhi

| # | Syarat | Terpenuhi di | Bukti |
|---|---|---|---|
| 1 | Validasi server-side | `middlewares/validators.js` → `komentarValidationRules` | HTTP 400 + pesan per field saat data invalid |
| 2 | Sanitasi sebelum disimpan | `.trim()` / `.escape()` di rule yang sama | Tabel before/after |
| 3 | Escape saat render | `views/komentar.ejs` pakai `<%= %>` | Payload `<script>` tampil sebagai teks, gak jalan |
| 4 | Parameterized query / ORM | `Comment.create()` & `Comment.findAll()` (Sequelize) | Tidak ada string SQL yang disambung manual |
| 5 | Tahan serangan (payload sama Bagian 1) | seluruh alur di atas | `' OR '1'='1`, UNION SELECT, dan `<script>` semua gagal tembus |
