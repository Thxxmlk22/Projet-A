/**
 * ACR-Lite — Single-file web app (Node.js + Express + SQLite)
 * Features:
 * - Collect personal data (name, surname, address, date/place of birth, country of residence)
 * - Upload photo & supporting document
 * - Dispatch into precise categories
 * - RBAC: grant rights & privileges via access codes per category (ACR-style)
 * - Basic approval workflow (Draft -> Submitted -> Approved/Rejected)
 * - Admin pages to manage categories, access codes, and mappings
 * - Simple session auth (admin + RO representative roles)
 *
 * SECURITY NOTE: This is a demo. For production, harden security (HTTPS, secure cookies,
 *   CSRF protection, input validation, file scanning, robust auth, rate limiting, etc.).
 *
 * How to run:
 *   1) npm init -y
 *   2) npm i express better-sqlite3 multer bcrypt uuid express-session mime-types
 *   3) node server.js
 *   4) Open http://localhost:3000
 *   Login with admin@example.com / admin123 (change after first login).
 */

const path = require('path');
const fs = require('fs');
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const Database = require('better-sqlite3');
const mime = require('mime-types');

const app = express();
const PORT = process.env.PORT || 3000;

// --- Paths ---
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
const DB_PATH = path.join(DATA_DIR, 'acr-lite.db');

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// --- DB ---
const db = new Database(DB_PATH);

db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','ro_rep')),
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS categories (
  id TEXT PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  description TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS access_codes (
  id TEXT PRIMARY KEY,
  code TEXT UNIQUE NOT NULL,
  label TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS category_access (
  category_id TEXT NOT NULL,
  access_code_id TEXT NOT NULL,
  PRIMARY KEY (category_id, access_code_id),
  FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE CASCADE,
  FOREIGN KEY (access_code_id) REFERENCES access_codes(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS applications (
  id TEXT PRIMARY KEY,
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  address TEXT NOT NULL,
  date_of_birth TEXT NOT NULL,
  place_of_birth TEXT NOT NULL,
  country_of_residence TEXT NOT NULL,
  category_id TEXT NOT NULL,
  photo_path TEXT,
  document_path TEXT,
  status TEXT NOT NULL CHECK(status IN ('draft','submitted','approved','rejected')),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (category_id) REFERENCES categories(id),
  FOREIGN KEY (created_by) REFERENCES users(id)
);
`);

// Seed admin user if not exists
(function seedAdmin() {
  const row = db.prepare('SELECT id FROM users WHERE email = ?').get('admin@example.com');
  if (!row) {
    const id = uuidv4();
    const hash = bcrypt.hashSync('admin123', 10);
    db.prepare('INSERT INTO users (id, email, password_hash, role, created_at) VALUES (?,?,?,?,datetime(\'now\'))')
      .run(id, 'admin@example.com', hash, 'admin');
    console.log('Seeded admin user: admin@example.com / admin123');
  }
})();

// Seed default data
(function seedDefaults() {
  const catCount = db.prepare('SELECT COUNT(*) as c FROM categories').get().c;
  if (catCount === 0) {
    const cats = [
      { name: 'NOC - Team Official' },
      { name: 'IF - Technical Official' },
      { name: 'Media - Journalist' },
      { name: 'YOGOC - Staff' }
    ];
    const ins = db.prepare('INSERT INTO categories (id,name,description) VALUES (?,?,?)');
    cats.forEach(c => ins.run(uuidv4(), c.name, 'Default seeded category'));
  }
  const codeCount = db.prepare('SELECT COUNT(*) as c FROM access_codes').get().c;
  if (codeCount === 0) {
    const codes = [
      { code: 'VEN', label: 'Venue Access' },
      { code: 'MPC', label: 'Main Press Centre' },
      { code: 'IBC', label: 'International Broadcast Centre' },
      { code: 'ATH', label: 'Athlete Areas' },
      { code: 'OPS', label: 'Operations Areas' }
    ];
    const ins = db.prepare('INSERT INTO access_codes (id,code,label) VALUES (?,?,?)');
    codes.forEach(c => ins.run(uuidv4(), c.code, c.label));
  }
})();

// --- Sessions & middleware ---
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev_secret_change_me',
  resave: false,
  saveUninitialized: false,
}));

// Static assets (for uploaded files)
app.use('/uploads', express.static(UPLOAD_DIR));

// --- Multer for uploads ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = mime.extension(file.mimetype) || 'bin';
    cb(null, `${uuidv4()}.${ext}`);
  }
});
const upload = multer({ storage });

// --- Helpers ---
function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).send('Forbidden');
  next();
}

function layout(title, body, user) {
  return `<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${title}</title>
  <link rel="stylesheet" href="https://unpkg.com/@picocss/pico@2.0.6/css/pico.min.css" />
  <style>
    .chip{display:inline-block;padding:0.3rem 0.8rem;border-radius:12px;background:#42a5f5;color:white;font-weight:bold;border:2px solid #1976d2;margin:0.125rem;font-size:0.9rem}
    .badge{display:inline-block;padding:0.3rem 0.6rem;border-radius:8px;background:#66bb6a;color:white;font-weight:bold;border:2px solid #388e3c;font-size:0.8rem}
    .grid-2{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
    .grid-3{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem}
    header{margin:1rem 0}
    .status-draft{background:#ffd54f;color:#333;font-weight:bold;padding:0.3rem 0.8rem;border-radius:12px;border:2px solid #ffb300}
    .status-submitted{background:#42a5f5;color:white;font-weight:bold;padding:0.3rem 0.8rem;border-radius:12px;border:2px solid #1976d2}
    .status-approved{background:#66bb6a;color:white;font-weight:bold;padding:0.3rem 0.8rem;border-radius:12px;border:2px solid #388e3c}
    .status-rejected{background:#ef5350;color:white;font-weight:bold;padding:0.3rem 0.8rem;border-radius:12px;border:2px solid #d32f2f}
  </style>
</head>
<body>
  <main class="container">
    <header>
      <nav>
        <ul>
          <li><strong>ACR‑Lite</strong></li>
        </ul>
        <ul>
          ${user ? `<li><a href="/">Dashboard</a></li>` : ''}
          ${user && user.role==='admin' ? `<li><a href="/admin">Admin</a></li>` : ''}
          ${user ? `<li><span class="badge">${user.email} (${user.role})</span></li>` : ''}
          ${user ? `<li><a href="/logout">Se déconnecter</a></li>` : `
            <li><a href="/login">Se connecter</a></li>
            <li><a href="/register">Créer un compte</a></li>
          `}
        </ul>
      </nav>
    </header>
    ${body}
  </main>
</body>
</html>`;
}

function statusChip(s){
  const map = {draft:'status-draft',submitted:'status-submitted',approved:'status-approved',rejected:'status-rejected'};
  return `<span class="chip ${map[s]||''}">${s}</span>`;
}

// --- Auth routes ---
app.get('/login', (req,res)=>{
  const body = `
  <article>
    <h2>Connexion</h2>
    <form method="post" action="/login">
      <label>Email<input type="email" name="email" required /></label>
      <label>Mot de passe<input type="password" name="password" required /></label>
      <button type="submit">Se connecter</button>
    </form>
    <p>Pas encore de compte ? <a href="/register">Créer un compte RO (représentant)</a></p>
  </article>`;
  res.send(layout('Connexion', body, req.session.user));
});

app.get('/register', (req,res)=>{
  const body = `
  <article>
    <h2>Créer un compte</h2>
    <form method="post" action="/register">
      <label>Email<input type="email" name="email" required /></label>
      <label>Mot de passe<input type="password" name="password" required /></label>
      <button type="submit">Créer le compte</button>
    </form>
    <p>Déjà un compte ? <a href="/login">Se connecter</a></p>
  </article>`;
  res.send(layout('Créer un compte', body, req.session.user));
});

app.post('/login', (req,res)=>{
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user) return res.status(401).send('Utilisateur introuvable');
  const ok = bcrypt.compareSync(password, user.password_hash);
  if (!ok) return res.status(401).send('Mot de passe invalide');
  req.session.user = { id: user.id, email: user.email, role: user.role };
  res.redirect('/');
});

app.post('/register', (req,res)=>{
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).send('Email et mot de passe requis');
  const exists = db.prepare('SELECT 1 FROM users WHERE email = ?').get(email);
  if (exists) return res.status(400).send('Email déjà utilisé');
  const id = uuidv4();
  const hash = bcrypt.hashSync(password, 10);
  db.prepare('INSERT INTO users (id,email,password_hash,role,created_at) VALUES (?,?,?,?,datetime(\'now\'))')
    .run(id, email, hash, 'ro_rep');
  res.redirect('/login');
});

app.get('/logout', (req,res)=>{
  req.session.destroy(()=>res.redirect('/login'));
});

// --- Dashboard ---
app.get('/', requireAuth, (req,res)=>{
  const apps = db.prepare(`
    SELECT a.*, c.name as category_name
    FROM applications a
    JOIN categories c ON c.id = a.category_id
    WHERE a.created_by = ? OR ? = 'admin'
    ORDER BY a.created_at DESC
  `).all(req.session.user.id, req.session.user.role);

  const body = `
  <article>
    <h2>Tableau de bord</h2>
    <p>Créez une demande d'accréditation, téléversez les pièces et soumettez pour validation.</p>
    <a href="/applications/new"><button>Nouvelle demande</button></a>
    <h3>Mes demandes</h3>
    <table>
      <thead><tr><th>Nom</th><th>Catégorie</th><th>Statut</th><th>Créée le</th><th>Actions</th></tr></thead>
      <tbody>
        ${apps.map(a=>`
          <tr>
            <td>${a.last_name} ${a.first_name}</td>
            <td>${a.category_name}</td>
            <td>${statusChip(a.status)}</td>
            <td>${new Date(a.created_at).toLocaleString()}</td>
            <td>
              <a href="/applications/${a.id}">Voir</a>
              ${a.status==='draft' ? `| <a href="/applications/${a.id}/edit">Modifier</a>`:''}
            </td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  </article>`;

  res.send(layout('Dashboard', body, req.session.user));
});

// --- New application form ---
app.get('/applications/new', requireAuth, (req,res)=>{
  const cats = db.prepare('SELECT * FROM categories ORDER BY name').all();
  const body = `
  <article>
    <h2>Nouvelle demande</h2>
    <form method="post" action="/applications" enctype="multipart/form-data">
      <div class="grid-2">
        <label>Prénom<input name="first_name" required /></label>
        <label>Nom<input name="last_name" required /></label>
      </div>
      <label>Adresse<textarea name="address" required></textarea></label>
      <div class="grid-3">
        <label>Date de naissance<input type="date" name="date_of_birth" required /></label>
        <label>Lieu de naissance<input name="place_of_birth" required /></label>
        <label>Pays de résidence<input name="country_of_residence" required /></label>
      </div>
      <label>Catégorie
        <select name="category_id" required>
          ${cats.map(c=>`<option value="${c.id}">${c.name}</option>`).join('')}
        </select>
      </label>
      <div class="grid-2">
        <label>Photo (JPEG/PNG)
          <input type="file" name="photo" accept="image/*" required />
        </label>
        <label>Document (PDF ou image)
          <input type="file" name="document" accept="application/pdf,image/*" required />
        </label>
      </div>
      <button type="submit">Enregistrer en brouillon</button>
    </form>
  </article>`;
  res.send(layout('Nouvelle demande', body, req.session.user));
});

app.post('/applications', requireAuth, upload.fields([{name:'photo'},{name:'document'}]), (req,res)=>{
  const { first_name, last_name, address, date_of_birth, place_of_birth, country_of_residence, category_id } = req.body;
  const photo = (req.files && req.files.photo && req.files.photo[0]) ? `/uploads/${req.files.photo[0].filename}` : null;
  const document = (req.files && req.files.document && req.files.document[0]) ? `/uploads/${req.files.document[0].filename}` : null;
  const id = uuidv4();
  const now = new Date().toISOString();
  db.prepare(`INSERT INTO applications (id,first_name,last_name,address,date_of_birth,place_of_birth,country_of_residence,category_id,photo_path,document_path,status,created_by,created_at,updated_at)
  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
    id, first_name, last_name, address, date_of_birth, place_of_birth, country_of_residence, category_id, photo, document, 'draft', req.session.user.id, now, now
  );
  res.redirect(`/applications/${id}`);
});

// View application
app.get('/applications/:id', requireAuth, (req,res)=>{
  const a = db.prepare(`
    SELECT a.*, c.name as category_name FROM applications a
    JOIN categories c ON c.id = a.category_id WHERE a.id = ?
  `).get(req.params.id);
  if (!a) return res.status(404).send('Demande introuvable');
  if (req.session.user.role !== 'admin' && a.created_by !== req.session.user.id) return res.status(403).send('Interdit');

  const codes = db.prepare(`
    SELECT ac.code, ac.label FROM category_access ca
    JOIN access_codes ac ON ac.id = ca.access_code_id
    WHERE ca.category_id = ?
  `).all(a.category_id);

  const body = `
  <article>
    <h2>Demande #${a.id.slice(0,8)}</h2>
    <p>${statusChip(a.status)} — Catégorie: <strong>${a.category_name}</strong></p>
    <div class="grid-2">
      <img src="${a.photo_path}" alt="photo" style="max-width:100%;max-height:260px;object-fit:cover;border-radius:8px;border:1px solid #ddd" />
      <div>
        <p><strong>${a.last_name} ${a.first_name}</strong></p>
        <p>${a.address}</p>
        <p>Né(e) le ${a.date_of_birth} à ${a.place_of_birth}</p>
        <p>Pays de résidence: ${a.country_of_residence}</p>
        <p>Document: ${a.document_path ? `<a href="${a.document_path}" target="_blank">Télécharger</a>` : '—'}</p>
      </div>
    </div>
    <h3>Droits & privilèges (codes d’accès)</h3>
    <p>${codes.length? codes.map(c=>`<span class="chip">${c.code} — ${c.label}</span>`).join('') : 'Aucun code associé à cette catégorie'}</p>

    <details>
      <summary>Actions</summary>
      <div class="grid-3">
        ${a.status==='draft' ? `<form method="post" action="/applications/${a.id}/submit"><button>Soumettre</button></form>`:''}
        ${req.session.user.role==='admin' && a.status==='submitted' ? `<form method="post" action="/applications/${a.id}/approve"><button>Approuver</button></form>`:''}
        ${req.session.user.role==='admin' && a.status==='submitted' ? `<form method="post" action="/applications/${a.id}/reject"><button class="secondary">Rejeter</button></form>`:''}
      </div>
    </details>
  </article>`;

  res.send(layout('Demande', body, req.session.user));
});

// Edit draft
app.get('/applications/:id/edit', requireAuth, (req,res)=>{
  const a = db.prepare('SELECT * FROM applications WHERE id = ?').get(req.params.id);
  if (!a) return res.status(404).send('Demande introuvable');
  if (a.status!=='draft') return res.status(400).send('Seuls les brouillons sont modifiables');
  if (req.session.user.role !== 'admin' && a.created_by !== req.session.user.id) return res.status(403).send('Interdit');
  const cats = db.prepare('SELECT * FROM categories ORDER BY name').all();
  const body = `
  <article>
    <h2>Modifier la demande</h2>
    <form method="post" action="/applications/${a.id}/edit" enctype="multipart/form-data">
      <div class="grid-2">
        <label>Prénom<input name="first_name" value="${a.first_name}" required /></label>
        <label>Nom<input name="last_name" value="${a.last_name}" required /></label>
      </div>
      <label>Adresse<textarea name="address" required>${a.address}</textarea></label>
      <div class="grid-3">
        <label>Date de naissance<input type="date" name="date_of_birth" value="${a.date_of_birth}" required /></label>
        <label>Lieu de naissance<input name="place_of_birth" value="${a.place_of_birth}" required /></label>
        <label>Pays de résidence<input name="country_of_residence" value="${a.country_of_residence}" required /></label>
      </div>
      <label>Catégorie
        <select name="category_id" required>
          ${cats.map(c=>`<option value="${c.id}" ${c.id===a.category_id?'selected':''}>${c.name}</option>`).join('')}
        </select>
      </label>
      <div class="grid-2">
        <label>Photo (laisser vide pour conserver)
          <input type="file" name="photo" accept="image/*" />
        </label>
        <label>Document (laisser vide pour conserver)
          <input type="file" name="document" accept="application/pdf,image/*" />
        </label>
      </div>
      <button type="submit">Enregistrer</button>
    </form>
  </article>`;
  res.send(layout('Modifier', body, req.session.user));
});

app.post('/applications/:id/edit', requireAuth, upload.fields([{name:'photo'},{name:'document'}]), (req,res)=>{
  const a = db.prepare('SELECT * FROM applications WHERE id = ?').get(req.params.id);
  if (!a) return res.status(404).send('Demande introuvable');
  if (a.status!=='draft') return res.status(400).send('Seuls les brouillons sont modifiables');
  if (req.session.user.role !== 'admin' && a.created_by !== req.session.user.id) return res.status(403).send('Interdit');
  const { first_name, last_name, address, date_of_birth, place_of_birth, country_of_residence, category_id } = req.body;
  const photo = (req.files && req.files.photo && req.files.photo[0]) ? `/uploads/${req.files.photo[0].filename}` : a.photo_path;
  const document = (req.files && req.files.document && req.files.document[0]) ? `/uploads/${req.files.document[0].filename}` : a.document_path;
  db.prepare(`UPDATE applications SET first_name=?, last_name=?, address=?, date_of_birth=?, place_of_birth=?, country_of_residence=?, category_id=?, photo_path=?, document_path=?, updated_at=datetime('now') WHERE id=?`)
    .run(first_name, last_name, address, date_of_birth, place_of_birth, country_of_residence, category_id, photo, document, a.id);
  res.redirect(`/applications/${a.id}`);
});

// Submit, approve, reject
app.post('/applications/:id/submit', requireAuth, (req,res)=>{
  const a = db.prepare('SELECT * FROM applications WHERE id = ?').get(req.params.id);
  if (!a) return res.status(404).send('Demande introuvable');
  if (a.created_by !== req.session.user.id && req.session.user.role!=='admin') return res.status(403).send('Interdit');
  if (a.status!=='draft') return res.status(400).send('Statut invalide');
  db.prepare(`UPDATE applications SET status='submitted', updated_at=datetime('now') WHERE id=?`).run(a.id);
  res.redirect(`/applications/${a.id}`);
});

app.post('/applications/:id/approve', requireAuth, requireAdmin, (req,res)=>{
  const a = db.prepare('SELECT * FROM applications WHERE id = ?').get(req.params.id);
  if (!a) return res.status(404).send('Demande introuvable');
  if (a.status!=='submitted') return res.status(400).send('Statut invalide');
  db.prepare(`UPDATE applications SET status='approved', updated_at=datetime('now') WHERE id=?`).run(a.id);
  res.redirect(`/applications/${a.id}`);
});

app.post('/applications/:id/reject', requireAuth, requireAdmin, (req,res)=>{
  const a = db.prepare('SELECT * FROM applications WHERE id = ?').get(req.params.id);
  if (!a) return res.status(404).send('Demande introuvable');
  if (a.status!=='submitted') return res.status(400).send('Statut invalide');
  db.prepare(`UPDATE applications SET status='rejected', updated_at=datetime('now') WHERE id=?`).run(a.id);
  res.redirect(`/applications/${a.id}`);
});

// --- Admin area ---
app.get('/admin', requireAuth, requireAdmin, (req,res)=>{
  const cats = db.prepare('SELECT * FROM categories ORDER BY name').all();
  const codes = db.prepare('SELECT * FROM access_codes ORDER BY code').all();
  const mappings = db.prepare(`
    SELECT c.name as category, ac.code as code
    FROM category_access ca
    JOIN categories c ON c.id = ca.category_id
    JOIN access_codes ac ON ac.id = ca.access_code_id
    ORDER BY c.name, ac.code
  `).all();

  const body = `
  <article>
    <h2>Administration</h2>
    <section>
      <h3>Catégories</h3>
      <form method="post" action="/admin/categories">
        <div class="grid-2">
          <label>Nom<input name="name" required /></label>
          <label>Description<input name="description" /></label>
        </div>
        <button>Ajouter</button>
      </form>
      <ul>
        ${cats.map(c=>`<li>${c.name} – ${c.description || ''}</li>`).join('')}
      </ul>
    </section>

    <section>
      <h3>Codes d'accès</h3>
      <form method="post" action="/admin/codes">
        <div class="grid-2">
          <label>Code<input name="code" required /></label>
          <label>Libellé<input name="label" required /></label>
        </div>
        <button>Ajouter</button>
      </form>
      <ul>
        ${codes.map(c=>`<li><strong>${c.code}</strong> — ${c.label}</li>`).join('')}
      </ul>
    </section>

    <section>
      <h3>Mapper Catégorie ↔ Codes</h3>
      <form method="post" action="/admin/map">
        <div class="grid-3">
          <label>Catégorie
            <select name="category_id">
              ${cats.map(c=>`<option value="${c.id}">${c.name}</option>`).join('')}
            </select>
          </label>
          <label>Code d'accès
            <select name="access_code_id">
              ${codes.map(c=>`<option value="${c.id}">${c.code} — ${c.label}</option>`).join('')}
            </select>
          </label>
          <label>&nbsp;<button>Associer</button></label>
        </div>
      </form>
      <p>${mappings.map(m=>`<span class="chip">${m.category}: ${m.code}</span>`).join(' ')}</p>
    </section>

    <section>
      <h3>Changer le mot de passe admin</h3>
      <form method="post" action="/admin/change-password">
        <div class="grid-2">
          <label>Nouveau mot de passe
            <input type="password" name="new_password" required minlength="6" />
          </label>
          <label>Confirmer le mot de passe
            <input type="password" name="confirm_password" required minlength="6" />
          </label>
        </div>
        <button type="submit">Changer le mot de passe</button>
      </form>
    </section>
  </article>`;

  res.send(layout('Admin', body, req.session.user));
});

app.post('/admin/categories', requireAuth, requireAdmin, (req,res)=>{
  const { name, description='' } = req.body;
  try {
    db.prepare('INSERT INTO categories (id,name,description) VALUES (?,?,?)').run(uuidv4(), name, description);
    res.redirect('/admin');
  } catch (e) { res.status(400).send('Erreur: '+e.message); }
});

app.post('/admin/codes', requireAuth, requireAdmin, (req,res)=>{
  const { code, label } = req.body;
  try {
    db.prepare('INSERT INTO access_codes (id,code,label) VALUES (?,?,?)').run(uuidv4(), code, label);
    res.redirect('/admin');
  } catch (e) { res.status(400).send('Erreur: '+e.message); }
});

app.post('/admin/map', requireAuth, requireAdmin, (req,res)=>{
  const { category_id, access_code_id } = req.body;
  try {
    db.prepare('INSERT INTO category_access (category_id, access_code_id) VALUES (?,?)').run(category_id, access_code_id);
    res.redirect('/admin');
  } catch (e) { res.status(400).send('Erreur: '+e.message); }
});

app.post('/admin/change-password', requireAuth, requireAdmin, (req,res)=>{
  const { new_password, confirm_password } = req.body;
  
  if (!new_password || !confirm_password) {
    return res.status(400).send('Tous les champs sont requis');
  }
  
  if (new_password !== confirm_password) {
    return res.status(400).send('Les mots de passe ne correspondent pas');
  }
  
  if (new_password.length < 6) {
    return res.status(400).send('Le mot de passe doit contenir au moins 6 caractères');
  }
  
  try {
    const hash = bcrypt.hashSync(new_password, 10);
    db.prepare('UPDATE users SET password_hash = ? WHERE email = ?').run(hash, 'admin@example.com');
    res.redirect('/admin');
  } catch (e) {
    res.status(400).send('Erreur: '+e.message);
  }
});

// --- Minimal health route ---
app.get('/health', (req,res)=>res.json({ ok: true }));

app.listen(PORT, ()=>{
  console.log(`ACR-Lite running on http://localhost:${PORT}`);
});
