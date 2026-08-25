const { body, query, validationResult } = require('express-validator');

/**
 * VALIDASI vs SANITASI - dua hal beda tapi sering jalan bareng:
 * - Validasi  : cek apakah input SESUAI ATURAN (kalo enggak, tolak)
 * - Sanitasi  : "bersihin"/ubah input jadi bentuk aman/normal (trim spasi,
 *               escape karakter berbahaya, dll), dijalanin walau input valid
 *
 * Semua ATURAN INI JALAN DI SERVER, bukan cuma validasi di HTML/JS client.
 * Validasi client-side gampang banget di-bypass (lewat Postman, curl, atau
 * disable JS), jadi validasi di server itu WAJIB, client-side cuma buat UX.
 */

// 🛡️ DITANGANI DI SINI - Validasi Server-Side (topik #1) + Sanitasi (topik #2)
const registerValidationRules = [
  body('username')
    .trim() // sanitasi: buang spasi nempel di depan/belakang
    .isLength({ min: 3, max: 20 })
    .withMessage('Username harus 3-20 karakter')
    .isAlphanumeric()
    .withMessage('Username cuma boleh huruf & angka, gak boleh spasi/simbol')
    .escape(), // sanitasi: ubah karakter HTML-sensitif (<, >, &, dll) jadi entity aman

  body('email')
    .trim()
    .isEmail()
    .withMessage('Format email gak valid')
    .normalizeEmail(), // sanitasi: lowercase-in, buang titik/plus alias gmail, dll

  body('password')
    .isLength({ min: 8 })
    .withMessage('Password minimal 8 karakter')
    .matches(/\d/)
    .withMessage('Password harus mengandung minimal 1 angka'),
];

const loginValidationRules = [
  body('username').trim().notEmpty().withMessage('Username wajib diisi').escape(),
  body('password').notEmpty().withMessage('Password wajib diisi'),
];

const searchValidationRules = [
  query('q')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 100 })
    .withMessage('Kata pencarian maksimal 100 karakter')
    .escape(), // sanitasi: kata pencarian bakal ditampilin lagi ke halaman, wajib di-escape
];

/**
 * 🛡️ DITANGANI DI SINI - Rules khusus buat halaman demo /demo/sanitasi.
 * Sengaja dipisah dari registerValidationRules biar demo-nya fokus nunjukin
 * SANITASI doang (gak nyampur sama pesan-pesan validasi kayak "harus 8 karakter").
 * `.trim()` dan `.escape()` di sini yang bikin before/after keliatan bedanya.
 */
const sanitasiDemoRules = [
  body('teks').trim().escape(),
  body('email_input').optional({ checkFalsy: true }).trim().normalizeEmail(),
];

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

const komentarSearchRules = [
  query('q')
    .optional({ checkFalsy: true })
    .trim()
    .isLength({ max: 100 })
    .withMessage('Kata pencarian maksimal 100 karakter')
    .escape(),
];

/**
 * Middleware buat ngecek hasil validasi. Kalo ada error, dikumpulin
 * jadi array pesan yang gampang ditampilin ulang ke form.
 */
function handleValidationErrors(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    req.validationErrors = errors.array().map((e) => e.msg);
    return next(); // tetep lanjut, controller yang mutusin re-render form
  }
  next();
}

module.exports = {
  registerValidationRules,
  loginValidationRules,
  searchValidationRules,
  sanitasiDemoRules,
  komentarValidationRules, 
  komentarSearchRules,
  handleValidationErrors,
};
