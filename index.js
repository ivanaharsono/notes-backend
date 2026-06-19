const express = require('express');
const { Pool } = require('pg');
const app = express();
app.use(express.json());

// =========================================================================
// KONEKSI KE NEON.TECH
// Ganti teks di dalam tanda kutip di bawah dengan Connection String asli lu!
// =========================================================================
const pool = new Pool({
  connectionString: "PASTE_CONNECTION_STRING_NEON_LU_DI_SINI",
  ssl: { rejectUnauthorized: false }
});

// 1. ENDPOINT REGISTER (Biar Dosen / Hana bisa bikin akun dari HP)
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  try {
    // Cek apakah email sudah pernah dipakai
    const userExist = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userExist.rows.length > 0) {
      return res.status(400).json({ status: "failed", message: "Email sudah terdaftar!" });
    }
    // Kalau aman, masukkan data ke tabel users cloud
    await pool.query('INSERT INTO users (email, password) VALUES ($1, $2)', [email, password]);
    res.json({ status: "success", message: "Registrasi Berhasil!" });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

// 2. ENDPOINT LOGIN (Untuk divalidasi oleh Retrofit Android lu)
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    // Cari di tabel users, apakah email dan password-nya cocok
    const result = await pool.query('SELECT * FROM users WHERE email = $1 AND password = $2', [email, password]);
    if (result.rows.length > 0) {
      res.json({ status: "success", message: "Login Berhasil!" });
    } else {
      res.status(401).json({ status: "failed", message: "Email atau Password Salah" });
    }
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

// Hugging Face Spaces butuh port default 7860, kita set dinamis agar aman
const PORT = process.env.PORT || 7860;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));