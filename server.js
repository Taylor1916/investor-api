const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');

// Config
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const INVESTOR_PASSWORD = process.env.INVESTOR_PASSWORD;
const TOKEN_EXPIRY = '1h';
const SALT_ROUNDS = 10;

if (!JWT_SECRET || !ADMIN_PASSWORD || !INVESTOR_PASSWORD) {
  throw new Error('Set JWT_SECRET, ADMIN_PASSWORD and INVESTOR_PASSWORD.');
}

const ROLES = { INVESTOR: 'investor', ADMIN: 'admin' };
const STATUSES = ['active', 'frozen', 'pending_verification'];
const TX_TYPES = ['deposit', 'withdrawal', 'profit', 'loss'];

// In-memory database (resets on restart; swap for a real DB before real use)
const users = [
  {
    id: 1,
    email: 'investor@example.com',
    passwordHash: bcrypt.hashSync(INVESTOR_PASSWORD, SALT_ROUNDS),
    role: ROLES.INVESTOR,
    allowedAssets: ['BTC', 'ETH', 'AAPL'],
    accountStatus: 'active',
    ledger: [],
  },
  {
    id: 2,
    email: 'admin@example.com',
    passwordHash: bcrypt.hashSync(ADMIN_PASSWORD, SALT_ROUNDS),
    role: ROLES.ADMIN,
  },
];

const findUserById = (id) => users.find((u) => u.id === Number(id));
const findUserByEmail = (email) =>
  users.find((u) => u.email.toLowerCase() === String(email).toLowerCase());

// Balances are always derived from the ledger, never typed in directly
const round2 = (n) => Math.round(n * 100) / 100;

const summarize = (user) => {
  let deposited = 0;
  let withdrawn = 0;
  let profit = 0;
  for (const tx of user.ledger) {
    if (tx.type === 'deposit') deposited += tx.amount;
    else if (tx.type === 'withdrawal') withdrawn += tx.amount;
    else if (tx.type === 'profit') profit += tx.amount;
    else if (tx.type === 'loss') profit -= tx.amount;
  }
  return {
    totalDeposited: round2(deposited),
    totalWithdrawn: round2(withdrawn),
    totalProfit: round2(profit),
    portfolioValue: round2(deposited - withdrawn + profit),
  };
};

// Middleware
const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: 'Access denied. Token missing.' });
  }
  jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] }, (err, payload) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token.' });
    }
    req.user = payload;
    next();
  });
};

const requireAdmin = (req, res, next) => {
  const current = findUserById(req.user.id);
  if (!current || current.role !== ROLES.ADMIN) {
    return res.status(403).json({ message: 'Admin access required.' });
  }
  next();
};

// App setup
const app = express();
app.use(express.json());
app.use(cors());

// Auth
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required.' });
    }
    const user = findUserByEmail(email);
    const valid = user && (await bcrypt.compare(password, user.passwordHash));
    if (!valid) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }
    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, {
      expiresIn: TOKEN_EXPIRY,
    });
    res.json({ token, role: user.role });
  } catch (err) {
    res.status(500).json({ message: 'Internal server error during login.' });
  }
});

// Investor: sees balance, profit and their full transaction history
app.get('/api/dashboard', authenticateToken, (req, res) => {
  const user = findUserById(req.user.id);
  if (!user) return res.status(404).json({ message: 'User not found.' });
  if (user.role === ROLES.ADMIN) {
    return res.status(403).json({ message: 'Admins must use management endpoints.' });
  }
  res.json({
    ...summarize(user),
    allowedAssets: user.allowedAssets,
    status: user.accountStatus,
    transactions: [...user.ledger].reverse(),
  });
});

// Admin: list investors with derived balances
app.get('/api/admin/investors', authenticateToken, requireAdmin, (req, res) => {
  const investors = users
    .filter((u) => u.role === ROLES.INVESTOR)
    .map((u) => ({
      id: u.id,
      email: u.email,
      status: u.accountStatus,
      ...summarize(u),
    }));
  res.json({ investors });
});

// Admin: record a deposit, withdrawal, profit or loss (note is required)
app.post('/api/admin/transaction', authenticateToken, requireAdmin, (req, res) => {
  const { userId, type, amount, note } = req.body;
  const user = findUserById(userId);

  if (!user || user.role !== ROLES.INVESTOR) {
    return res.status(404).json({ message: 'Investor not found.' });
  }
  if (!TX_TYPES.includes(type)) {
    return res.status(400).json({ message: `Type must be one of: ${TX_TYPES.join(', ')}.` });
  }
  const value = Number(amount);
  if (!Number.isFinite(value) || value <= 0) {
    return res.status(400).json({ message: 'Amount must be a positive number.' });
  }
  if (!note || !String(note).trim()) {
    return res.status(400).json({ message: 'A note is required for every entry.' });
  }
  if ((type === 'withdrawal' || type === 'loss') &&
      value > summarize(user).portfolioValue) {
    return res.status(400).json({ message: 'Amount exceeds current balance.' });
  }

  user.ledger.push({
    id: user.ledger.length + 1,
    date: new Date().toISOString(),
    type,
    amount: round2(value),
    note: String(note).trim(),
    recordedBy: req.user.id,
  });

  res.json({ message: 'Entry recorded.', ...summarize(user) });
});

// Admin: change account status
app.post('/api/admin/status', authenticateToken, requireAdmin, (req, res) => {
  const { userId, status } = req.body;
  const user = findUserById(userId);
  if (!user || user.role !== ROLES.INVESTOR) {
    return res.status(404).json({ message: 'Investor not found.' });
  }
  if (!STATUSES.includes(status)) {
    return res.status(400).json({ message: `Status must be one of: ${STATUSES.join(', ')}.` });
  }
  user.accountStatus = status;
  res.json({ message: 'Status updated.', status });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
