const express = require('express');
const router = express.Router();
const requireAuth = require('../middlewares/auth.middleware');
const {
  komentarValidationRules,
  komentarSearchRules,
  handleValidationErrors,
} = require('../middlewares/validators');
const commentController = require('../controllers/comment.controller');

// snapshot body SEBELUM sanitasi jalan, biar bisa nunjukin before/after di tugas.md
function captureRawBody(req, res, next) {
  req.rawBodyForDemo = { ...req.body };
  next();
}

// GET /komentar — form + daftar komentar (bisa ?q= buat search, parameterized)
router.get('/komentar', requireAuth, komentarSearchRules, handleValidationErrors, commentController.showKomentarPage);

// POST /komentar — validasi server-side -> sanitasi -> simpan (parameterized insert)
router.post(
  '/komentar',
  requireAuth,
  captureRawBody,
  komentarValidationRules,
  handleValidationErrors,
  commentController.submitKomentar
);

module.exports = router;
