const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

// Config
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || 'admin@example.com').toLowerCase();
const DATABASE_URL = process.env.DATABASE_URL;
const ALLOWED_ORIGIN =
  process.env.ALLOWED_ORIGIN || 'https://my-investor-dashboard.netlify.app';

if (!JWT_SECRET || !ADMIN_PASSWORD || !DATABASE_URL) {
  throw new Error('Set JWT_SECRET, ADMIN_PASSWORD and DATABASE_URL.');
}

const TOKEN_EXPIRY = '1h';
const SALT_ROUNDS = 10;
const ROLES = { INVESTOR: 'investor', ADMIN: 'admin' };
const STATUSES = ['active', 'frozen', 'pending_verification'];
const TX_TYPES = ['deposit', 'withdrawal', 'profit', 'loss'];
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_AMOUNT = 10000000;
const MAX_PENDING = 5;

// Database
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});
// Neon closes idle connections; without this handler the process would crash
pool.on('error', (err) => {
  console.error('Unexpected database error:', err.message);
});


async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'investor',
      account_status TEXT NOT NULL DEFAULT 'pending_verification',
      allowed_assets TEXT[] NOT NULL DEFAULT ARRAY['BTC','ETH','AAPL'],
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS ledger (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      type TEXT NOT NULL,
      amount NUMERIC(14,2) NOT NULL CHECK (amount > 0),
      note TEXT NOT NULL,
      recorded_by INTEGER NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS requests (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      type TEXT NOT NULL CHECK (type IN ('deposit', 'withdrawal')),
      amount NUMERIC(14,2) NOT NULL CHECK (amount > 0),
      note TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ,
      reviewed_by INTEGER
    );
  `);

  const hash = await bcrypt.hash(ADMIN_PASSWORD, SALT_ROUNDS);
  await pool.query(
    `INSERT INTO users (email, password_hash, role, account_status)
     VALUES ($1, $2, 'admin', 'active')
     ON CONFLICT (email)
     DO UPDATE SET password_hash = EXCLUDED.password_hash, role = 'admin'`,
    [ADMIN_EMAIL, hash]
  );
}

// Balances are always derived from the ledger, never typed in directly
const SUMMARY_SQL = `
  COALESCE(SUM(CASE WHEN l.type = 'deposit' THEN l.amount END), 0) AS deposited,
  COALESCE(SUM(CASE WHEN l.type = 'withdrawal' THEN l.amount END), 0) AS withdrawn,
  COALESCE(SUM(CASE WHEN l.type = 'profit' THEN l.amount
                    WHEN l.type = 'loss' THEN -l.amount END), 0) AS profit
`;

const toSummary = (row) => {
  const deposited = Number(row.deposited);
  const withdrawn = Number(row.withdrawn);
  const profit = Number(row.profit);
  return {
    totalDeposited: deposited,
    totalWithdrawn: withdrawn,
    totalProfit: profit,
    portfolioValue: Math.round((deposited - withdrawn + profit) * 100) / 100,
  };
};

const getSummary = async (client, userId) => {
  const { rows } = await client.query(
    `SELECT ${SUMMARY_SQL} FROM ledger l WHERE l.user_id = $1`,
    [userId]
  );
  return toSummary(rows[0]);
};

// Middleware & helpers
const wrap = (fn) => (req, res, next) =>
  fn(req, res, next).catch((err) => {
    console.error(err);
    res.status(500).json({ message: 'Internal server error.' });
  });

const signToken = (user) =>
  jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, {
    expiresIn: TOKEN_EXPIRY,
  });

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

const requireAdmin = wrap(async (req, res, next) => {
  const { rows } = await pool.query('SELECT role FROM users WHERE id = $1', [
    req.user.id,
  ]);
  if (!rows[0] || rows[0].role !== ROLES.ADMIN) {
    return res.status(403).json({ message: 'Admin access required.' });
  }
  next();
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many attempts. Please try again in 15 minutes.' },
});

// App setup
const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use(cors({ origin: ALLOWED_ORIGIN }));

// Auth routes
app.post('/api/signup', authLimiter, wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  if (!EMAIL_RE.test(email) || email.length > 254) {
    return res.status(400).json({ message: 'Enter a valid email address.' });
  }
  if (password.length < 8 || password.length > 72) {
    return res
      .status(400)
      .json({ message: 'Password must be 8 to 72 characters.' });
  }

  const hash = await bcrypt.hash(password, SALT_ROUNDS);
  try {
    const { rows } = await pool.query(
      `INSERT INTO users (email, password_hash, role, account_status)
       VALUES ($1, $2, 'investor', 'pending_verification')
       RETURNING id, role`,
      [email, hash]
    );
    res.status(201).json({ token: signToken(rows[0]), role: rows[0].role });
  } catch (err) {
    if (err.code === '23505') {
      return res
        .status(409)
        .json({ message: 'An account with this email already exists.' });
    }
    throw err;
  }
}));

app.post('/api/login', authLimiter, wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required.' });
  }

  const { rows } = await pool.query(
    'SELECT id, role, password_hash FROM users WHERE email = $1',
    [email]
  );
  const user = rows[0];
  const valid = user && (await bcrypt.compare(password, user.password_hash));

  if (!valid) {
    return res.status(401).json({ message: 'Invalid email or password.' });
  }
  res.json({ token: signToken(user), role: user.role });
}));

// Investor routes
app.get('/api/dashboard', authenticateToken, wrap(async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id, role, account_status, allowed_assets FROM users WHERE id = $1',
    [req.user.id]
  );
  const user = rows[0];

  if (!user) return res.status(404).json({ message: 'User not found.' });
  if (user.role === ROLES.ADMIN) {
    return res
      .status(403)
      .json({ message: 'Admins must use management endpoints.' });
  }

  const summary = await getSummary(pool, user.id);
  const tx = await pool.query(
    `SELECT id, type, amount, note, created_at AS date
     FROM ledger WHERE user_id = $1 ORDER BY id DESC`,
    [user.id]
  );

  const reqs = await pool.query(
    `SELECT id, type, amount, note, status, created_at AS date
     FROM requests WHERE user_id = $1 ORDER BY id DESC LIMIT 20`,
    [user.id]
  );

  res.json({
    ...summary,
    allowedAssets: user.allowed_assets,
    status: user.account_status,
    transactions: tx.rows.map((t) => ({ ...t, amount: Number(t.amount) })),
    requests: reqs.rows.map((r) => ({ ...r, amount: Number(r.amount) })),
  });
}));

app.post('/api/requests', authenticateToken, wrap(async (req, res) => {
  const { type, amount, note } = req.body;
  const value = Number(amount);

  if (!['deposit', 'withdrawal'].includes(type)) {
    return res.status(400).json({ message: 'Type must be deposit or withdrawal.' });
  }
  if (!Number.isFinite(value) || value <= 0 || value > MAX_AMOUNT) {
    return res.status(400).json({ message: 'Enter a valid amount.' });
  }
  const cleanNote = String(note || '').trim().slice(0, 200);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const found = await client.query(
      `SELECT id, account_status FROM users
       WHERE id = $1 AND role = 'investor' FOR UPDATE`,
      [req.user.id]
    );
    const user = found.rows[0];
    if (!user) {
      await client.query('ROLLBACK');
      return res.status(404).json({ message: 'Investor not found.' });
    }
    if (user.account_status !== 'active') {
      await client.query('ROLLBACK');
      return res.status(403).json({ message: 'Your account must be active to make requests.' });
    }

    const pending = await client.query(
      `SELECT COUNT(*)::int AS n,
              COALESCE(SUM(CASE WHEN type = 'withdrawal' THEN amount END), 0) AS withdrawals
       FROM requests WHERE user_id = $1 AND status = 'pending'`,
      [user.id]
    );
    if (pending.rows[0].n >= MAX_PENDING) {
      await client.query('ROLLBACK');
      return res.status(400).json({ message: 'You have too many pending requests. Please wait for a review.' });
    }

    if (type === 'withdrawal') {
      const summary = await getSummary(client, user.id);
      const available = summary.portfolioValue - Number(pending.rows[0].withdrawals);
      if (value > available) {
        await client.query('ROLLBACK');
        return res.status(400).json({ message: 'Amount exceeds your available balance.' });
      }
    }

    await client.query(
      `INSERT INTO requests (user_id, type, amount, note) VALUES ($1, $2, $3, $4)`,
      [user.id, type, value.toFixed(2), cleanNote]
    );
    await client.query('COMMIT');
    res.status(201).json({ message: 'Request submitted. You will see it here once it is reviewed.' });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}));

// Admin routes
app.get('/api/admin/investors', authenticateToken, requireAdmin, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT u.id, u.email, u.account_status AS status, ${SUMMARY_SQL}
     FROM users u
     LEFT JOIN ledger l ON l.user_id = u.id
     WHERE u.role = 'investor'
     GROUP BY u.id
     ORDER BY u.id`
  );
  res.json({
    investors: rows.map((r) => ({
      id: r.id,
      email: r.email,
      status: r.status,
      ...toSummary(r),
    })),
  });
}));

app.post('/api/admin/transaction', authenticateToken, requireAdmin, wrap(async (req, res) => {
  const { userId, type, amount, note } = req.body;
  const value = Number(amount);

  if (!TX_TYPES.includes(type)) {
    return res
      .status(400)
      .json({ message: `Type must be one of: ${TX_TYPES.join(', ')}.` });
  }
  if (!Number.isFinite(value) || value <= 0) {
    return res.status(400).json({ message: 'Amount must be a positive number.' });
  }
  if (!note || !String(note).trim()) {
    return res.status(400).json({ message: 'A note is required for every entry.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const found = await client.query(
      `SELECT id FROM users WHERE id = $1 AND role = 'investor' FOR UPDATE`,
      [Number(userId)]
    );
    if (!found.rows[0]) {
      await client.query('ROLLBACK');
      return res.status(404).json({ message: 'Investor not found.' });
    }

    const current = await getSummary(client, found.rows[0].id);
    if ((type === 'withdrawal' || type === 'loss') && value > current.portfolioValue) {
      await client.query('ROLLBACK');
      return res.status(400).json({ message: 'Amount exceeds current balance.' });
    }

    await client.query(
      `INSERT INTO ledger (user_id, type, amount, note, recorded_by)
       VALUES ($1, $2, $3, $4, $5)`,
      [found.rows[0].id, type, value.toFixed(2), String(note).trim(), req.user.id]
    );
    const updated = await getSummary(client, found.rows[0].id);
    await client.query('COMMIT');
    res.json({ message: 'Entry recorded.', ...updated });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}));

app.post('/api/admin/status', authenticateToken, requireAdmin, wrap(async (req, res) => {
  const { userId, status } = req.body;

  if (!STATUSES.includes(status)) {
    return res
      .status(400)
      .json({ message: `Status must be one of: ${STATUSES.join(', ')}.` });
  }
  const { rowCount } = await pool.query(
    `UPDATE users SET account_status = $1 WHERE id = $2 AND role = 'investor'`,
    [status, Number(userId)]
  );
  if (!rowCount) return res.status(404).json({ message: 'Investor not found.' });
  res.json({ message: 'Status updated.', status });
}));

app.get('/api/admin/requests', authenticateToken, requireAdmin, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT r.id, r.type, r.amount, r.note, r.created_at AS date, u.email
     FROM requests r JOIN users u ON u.id = r.user_id
     WHERE r.status = 'pending' ORDER BY r.id`
  );
  res.json({ requests: rows.map((r) => ({ ...r, amount: Number(r.amount) })) });
}));

app.post('/api/admin/requests/:id/decision', authenticateToken, requireAdmin, wrap(async (req, res) => {
  const { decision } = req.body;
  if (!['approve', 'decline'].includes(decision)) {
    return res.status(400).json({ message: 'Decision must be approve or decline.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const found = await client.query(
      `SELECT * FROM requests WHERE id = $1 AND status = 'pending' FOR UPDATE`,
      [Number(req.params.id)]
    );
    const request = found.rows[0];
    if (!request) {
      await client.query('ROLLBACK');
      return res.status(404).json({ message: 'Request not found or already reviewed.' });
    }

    if (decision === 'approve') {
      await client.query('SELECT id FROM users WHERE id = $1 FOR UPDATE', [request.user_id]);
      if (request.type === 'withdrawal') {
        const summary = await getSummary(client, request.user_id);
        if (Number(request.amount) > summary.portfolioValue) {
          await client.query('ROLLBACK');
          return res.status(400).json({ message: 'Amount exceeds the investor\'s current balance.' });
        }
      }
      await client.query(
        `INSERT INTO ledger (user_id, type, amount, note, recorded_by)
         VALUES ($1, $2, $3, $4, $5)`,
        [
          request.user_id,
          request.type,
          request.amount,
          `Approved request #${request.id}${request.note ? ': ' + request.note : ''}`,
          req.user.id,
        ]
      );
    }

    await client.query(
      `UPDATE requests SET status = $1, reviewed_at = NOW(), reviewed_by = $2 WHERE id = $3`,
      [decision === 'approve' ? 'approved' : 'declined', req.user.id, request.id]
    );
    await client.query('COMMIT');
    res.json({ message: decision === 'approve' ? 'Request approved and recorded.' : 'Request declined.' });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}));

// Start
initDb()
  .then(() => app.listen(PORT, () => console.log(`Server running on port ${PORT}`)))
  .catch((err) => {
    console.error('Failed to start:', err);
    process.exit(1);
  });
