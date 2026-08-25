const { Op } = require('sequelize');
const { Comment } = require('../models');

/**
 * ============================================================
 * BAGIAN 2 TUGAS — Halaman "Komentar Produk" (implementasi mandiri)
 * ============================================================
 * Memenuhi 5 syarat:
 *  1. Validasi server-side  -> komentarValidationRules (middlewares/validators.js)
 *  2. Sanitasi input        -> .trim()/.escape() di komentarValidationRules,
 *                               before/after ditunjukin lewat req.rawBodyForDemo
 *  3. Escape saat render    -> views/komentar.ejs pakai <%= %>, BUKAN <%- %>
 *  4. Parameterized query   -> Comment.create() & Comment.findAll() (Sequelize ORM,
 *                               value dikirim terpisah dari query, bukan digabung
 *                               pakai string manual)
 *  5. Tahan serangan        -> dibuktikan di tugas.md pakai payload yang sama
 *                               kayak Bagian 1 (SQLi & XSS)
 */

// GET /komentar — tampilin form + daftar komentar (bisa difilter search)
async function showKomentarPage(req, res) {
  // req.query.q di titik ini SUDAH divalidasi & di-escape oleh komentarSearchRules
  const q = req.query.q || '';

  const where = q
    ? {
        [Op.or]: [
          { name: { [Op.iLike]: `%${q}%` } },
          { message: { [Op.iLike]: `%${q}%` } },
        ],
      }
    : undefined;

  // 🛡️ #4 PARAMETERIZED QUERY: Sequelize ORM (findAll + where object) selalu
  // mengirim query & value TERPISAH ke Postgres lewat prepared statement.
  // Apapun isi `q` (termasuk `' OR '1'='1` atau `<script>...`) diperlakukan
  // SEBAGAI DATA/TEKS PENCARIAN BIASA, gak pernah jadi bagian perintah SQL.
  const comments = await Comment.findAll({
    where,
    order: [['createdAt', 'DESC']],
  });

  res.render('komentar', {
    username: req.session.username,
    comments: comments.map((c) => c.toJSON()),
    query: q,
    errors: [],
    old: { name: '', email: '', message: '' },
    before: null,
    after: null,
  });
}

// POST /komentar — validasi, sanitasi, baru simpan
async function submitKomentar(req, res) {
  const errors = req.validationErrors || [];

  // #1 VALIDASI SERVER-SIDE: kalo ada aturan yang gak terpenuhi
  // (komentarValidationRules di middlewares/validators.js, dicek SEBELUM
  // controller ini jalan), tolak di server dengan pesan jelas per field —
  // TIDAK disimpan ke DB. Ini tetap jalan walau JS client dimatiin atau
  // request dikirim langsung lewat curl/Postman, karena dicek di server.
  if (errors.length > 0) {
    const comments = await Comment.findAll({ order: [['createdAt', 'DESC']] });
    return res.status(400).render('komentar', {
      username: req.session.username,
      comments: comments.map((c) => c.toJSON()),
      query: '',
      errors,
      // req.body di titik ini sudah lewat .trim()/.escape() (sanitasi tetap
      // jalan duluan walau akhirnya ditolak validasi)
      old: req.body,
      before: null,
      after: null,
    });
  }

  // 🛡️ #2 SANITASI: req.rawBodyForDemo = snapshot SEBELUM sanitasi (lewat
  // captureRawBody di routes/comment.routes.js). req.body di titik ini
  // adalah hasil SETELAH .trim().escape() jalan (komentarValidationRules).
  const before = req.rawBodyForDemo || null;
  const after = { ...req.body };

  // 🛡️ #4 PARAMETERIZED QUERY: Comment.create() -> Sequelize generate
  // "INSERT INTO comments (...) VALUES ($1,$2,$3)" + value dikirim terpisah,
  // bukan string SQL yang disambung manual pakai template literal.
  await Comment.create({
    name: req.body.name,
    email: req.body.email,
    message: req.body.message,
  });

  const comments = await Comment.findAll({ order: [['createdAt', 'DESC']] });

  res.render('komentar', {
    username: req.session.username,
    comments: comments.map((c) => c.toJSON()),
    query: '',
    errors: [],
    old: { name: '', email: '', message: '' },
    before,
    after,
  });
}

module.exports = { showKomentarPage, submitKomentar };
