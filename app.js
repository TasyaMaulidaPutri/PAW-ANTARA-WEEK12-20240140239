require('dotenv').config();
const express = require('express');
const session = require('express-session');
const { sequelize } = require('./models');

const authRoutes = require('./routes/auth.routes');
const searchRoutes = require('./routes/search.routes');
const demoRoutes = require('./routes/demo.routes');
const pageRoutes = require('./routes/page.routes');
const commentRoutes = require('./routes/comment.routes');

const app = express();

app.set('view engine', 'ejs');
app.set('views', './views');
app.use(express.static('public'));

app.use(express.json());
app.use(express.urlencoded({ extended: true })); // buat baca body dari form HTML biasa

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'secret-default',
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24,
      httpOnly: true,
    },
  })
);

app.use('/', authRoutes);
app.use('/', searchRoutes);
app.use('/', demoRoutes);
app.use('/', pageRoutes);
app.use('/', commentRoutes); 

const PORT = process.env.PORT || 3000;

async function start() {
  try {
    await sequelize.authenticate();
    console.log('Koneksi database berhasil');

    await sequelize.sync();
    console.log('Sync model selesai');

    if (process.env.ENABLE_VULN_DEMO === 'true') {
      console.warn('\n⚠️  ⚠️  ⚠️  ENABLE_VULN_DEMO=true - jangan pernah deploy kondisi ini ke server publik ⚠️  ⚠️  ⚠️\n');
    }

    app.listen(PORT, () => {
      console.log(`Server jalan di http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error('Gagal konek ke database:', err.message);
  }
}

start();
