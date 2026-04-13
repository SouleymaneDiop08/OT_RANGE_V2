const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'talixman-portal-secret-2024-icshub';
const DATA_FILE = '/data/users.json';

// Ensure data directory
if (!fs.existsSync('/data')) fs.mkdirSync('/data', { recursive: true });

// Initialize users store
function loadUsers() {
  if (fs.existsSync(DATA_FILE)) {
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  }
  // Default admin user
  const defaultUsers = [
    {
      id: '1',
      username: 'admin',
      password: bcrypt.hashSync('admin', 10),
      role: 'admin',
      displayName: 'Administrateur'
    },
    {
      id: '2',
      username: 'superadmin',
      password: bcrypt.hashSync('superadmin', 10),
      role: 'superadmin',
      displayName: 'Super Administrateur'
    }
  ];
  fs.writeFileSync(DATA_FILE, JSON.stringify(defaultUsers, null, 2));
  return defaultUsers;
}

function saveUsers(users) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(users, null, 2));
}

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiting
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Trop de tentatives. Réessayez dans 15 minutes.' }
});

// Auth middleware
function requireAuth(req, res, next) {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Non authentifié' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Session expirée' });
  }
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin' && req.user.role !== 'superadmin') return res.status(403).json({ error: 'Accès refusé' });
  next();
}

// === AUTH ROUTES ===

app.post('/api/login', loginLimiter, (req, res) => {
  const { username, password } = req.body;
  const users = loadUsers();
  const user = users.find(u => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Identifiants invalides' });
  }
  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role, displayName: user.displayName },
    JWT_SECRET,
    { expiresIn: '8h' }
  );
  res.cookie('token', token, { httpOnly: true, sameSite: 'strict', maxAge: 8 * 3600 * 1000 });
  res.json({ success: true, user: { username: user.username, role: user.role, displayName: user.displayName } });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// === USER MANAGEMENT ROUTES ===

app.get('/api/users', requireAuth, requireAdmin, (req, res) => {
  const users = loadUsers();
  res.json(users.map(u => ({ id: u.id, username: u.username, role: u.role, displayName: u.displayName })));
});

app.post('/api/users', requireAuth, requireAdmin, (req, res) => {
  const { username, password, role, displayName } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username et password requis' });
  const users = loadUsers();
  if (users.find(u => u.username === username)) {
    return res.status(409).json({ error: 'Utilisateur déjà existant' });
  }
  const newUser = {
    id: Date.now().toString(),
    username,
    password: bcrypt.hashSync(password, 10),
    role: role || 'user',
    displayName: displayName || username
  };
  users.push(newUser);
  saveUsers(users);
  res.json({ success: true, user: { id: newUser.id, username: newUser.username, role: newUser.role } });
});

app.put('/api/users/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  // Non-admin can only edit themselves
  if (req.user.role !== 'admin' && req.user.id !== id) {
    return res.status(403).json({ error: 'Accès refusé' });
  }
  const users = loadUsers();
  const idx = users.findIndex(u => u.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Utilisateur non trouvé' });

  const { username, password, role, displayName } = req.body;
  // Prevent duplicate username
  if (username && users.find(u => u.username === username && u.id !== id)) {
    return res.status(409).json({ error: 'Nom d\'utilisateur déjà utilisé' });
  }
  if (username) users[idx].username = username;
  if (password) users[idx].password = bcrypt.hashSync(password, 10);
  if (role && req.user.role === 'admin') users[idx].role = role;
  if (displayName) users[idx].displayName = displayName;
  saveUsers(users);
  res.json({ success: true });
});

app.delete('/api/users/:id', requireAuth, requireAdmin, (req, res) => {
  const { id } = req.params;
  if (req.user.id === id) return res.status(400).json({ error: 'Impossible de supprimer votre propre compte' });
  let users = loadUsers();
  const before = users.length;
  users = users.filter(u => u.id !== id);
  if (users.length === before) return res.status(404).json({ error: 'Utilisateur non trouvé' });
  saveUsers(users);
  res.json({ success: true });
});

// SPA fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/index.html'));
});

app.listen(PORT, () => console.log(`Talixman Portal running on port ${PORT}`));
