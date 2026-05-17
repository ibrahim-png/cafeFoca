require("dotenv").config();

const path = require("path");
const express = require("express");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const bcrypt = require("bcrypt");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  store: new pgSession({
    pool: pool,
    tableName: "session"
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: 1000 * 60 * 60 * 8
  }
}));

function requireLoginPage(req, res, next) {
  if (!req.session.user) {
    return res.redirect("/login.html");
  }

  next();
}

function requireLoginApi(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ message: "Login gerekli" });
  }

  next();
}

app.get("/", (req, res) => {
  if (req.session.user) {
    return res.redirect("/home");
  }

  res.redirect("/login.html");
});

app.get("/login.html", (req, res) => {
  if (req.session.user) {
    return res.redirect("/home");
  }

  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.get("/home", requireLoginPage, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "home.html"));
});

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const result = await pool.query(
      `SELECT id, username, password_hash, full_name, role, is_active
       FROM users
       WHERE username = $1`,
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: "Kullanıcı adı veya şifre hatalı" });
    }

    const user = result.rows[0];

    if (user.is_active !== "1") {
      return res.status(403).json({ message: "Kullanıcı pasif" });
    }

    const passwordOk = await bcrypt.compare(password, user.password_hash);

    if (!passwordOk) {
      return res.status(401).json({ message: "Kullanıcı adı veya şifre hatalı" });
    }

    req.session.regenerate((err) => {
      if (err) {
        return res.status(500).json({ message: "Session oluşturulamadı" });
      }

      req.session.user = {
        id: user.id,
        username: user.username,
        fullName: user.full_name,
        role: user.role
      };

      res.json({
        message: "Login başarılı",
        user: req.session.user
      });
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Sunucu hatası" });
  }
});

app.get("/api/me", requireLoginApi, (req, res) => {
  res.json(req.session.user);
});

app.post("/api/logout", requireLoginApi, (req, res) => {
  req.session.destroy(() => {
    res.json({ message: "Çıkış yapıldı" });
  });
});

app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, "public", "404.html"));
});

app.listen(PORT, () => {
  console.log(`Server ${PORT} portunda çalışıyor`);
});