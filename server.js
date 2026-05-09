const express = require('express');
const sqlite3 = require('sqlite3');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Database setup
const db = new sqlite3.Database('./vibepay.db');

// Hardcoded secrets
const JWT_SECRET = 'supersecret123';
const STRIPE_SECRET_KEY = 'sk_test_FAKE1234567890abcdefghijklmnop';
const AWS_ACCESS_KEY = 'AKIA_FAKE_KEY_DO_NOT_USE';
const AWS_SECRET_KEY = 'fake_aws_secret_key_1234567890abcdef';
const DATABASE_PASSWORD = 'admin123!';
const SENDGRID_API_KEY = 'SG.FAKE_KEY_FOR_TESTING_1234567890';

// CORS - allow everything
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', '*');
  res.header('Access-Control-Allow-Methods', '*');
  next();
});

// Login - SQL injection vulnerable
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

  db.get(query, (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET);
    res.json({ token, user });
  });
});

// Register - stores password in plaintext
app.post('/api/register', (req, res) => {
  const { username, password, email } = req.body;
  const query = `INSERT INTO users (username, password, email, role) VALUES ('${username}', '${password}', '${email}', 'user')`;

  db.run(query, function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ id: this.lastID, username, email });
  });
});

// User profile - IDOR vulnerability (no auth check on who's requesting)
app.get('/api/users/:id', (req, res) => {
  const query = `SELECT id, username, email, role, ssn, credit_card FROM users WHERE id = ${req.params.id}`;
  db.get(query, (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(user);
  });
});

// Search - XSS vulnerable
app.get('/api/search', (req, res) => {
  const searchTerm = req.query.q;
  const html = `<h1>Search Results for: ${searchTerm}</h1>`;
  res.send(html);
});

// Admin endpoint - broken auth (just checks if role field exists in token)
app.get('/api/admin/users', (req, res) => {
  const token = req.headers.authorization;
  try {
    const decoded = jwt.decode(token); // Using decode instead of verify!
    if (decoded.role) {
      db.all('SELECT * FROM users', (err, users) => {
        res.json(users);
      });
    }
  } catch(e) {
    res.status(403).json({ error: 'Forbidden' });
  }
});

// File upload - path traversal vulnerable
app.post('/api/upload', (req, res) => {
  const filename = req.body.filename;
  const content = req.body.content;
  const uploadPath = path.join('./uploads', filename);

  fs.writeFileSync(uploadPath, content);
  res.json({ message: 'File uploaded', path: uploadPath });
});

// Execute report - command injection
app.get('/api/reports/:name', (req, res) => {
  const reportName = req.params.name;
  exec(`cat reports/${reportName}.pdf`, (err, stdout) => {
    if (err) return res.status(500).json({ error: err.message });
    res.send(stdout);
  });
});

// Debug endpoint left in production
app.get('/api/debug', (req, res) => {
  res.json({
    env: process.env,
    dbPath: './vibepay.db',
    secretKey: JWT_SECRET,
    stripeKey: STRIPE_SECRET_KEY,
    awsKeys: { access: AWS_ACCESS_KEY, secret: AWS_SECRET_KEY },
  });
});

// Password reset - SSRF vulnerable
app.post('/api/reset-password', async (req, res) => {
  const { callbackUrl } = req.body;
  try {
    const response = await fetch(callbackUrl, {
      method: 'POST',
      body: JSON.stringify({ token: 'reset-token-123' }),
    });
    res.json({ message: 'Reset link sent' });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Payment processing - logs sensitive data
app.post('/api/payments', (req, res) => {
  const { cardNumber, cvv, expiry, amount } = req.body;
  console.log(`Processing payment: card=${cardNumber}, cvv=${cvv}, amount=${amount}`);

  const query = `INSERT INTO payments (card_number, cvv, expiry, amount, status) VALUES ('${cardNumber}', '${cvv}', '${expiry}', ${amount}, 'processed')`;

  db.run(query, function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ paymentId: this.lastID, status: 'processed' });
  });
});

// Webhook - no signature verification
app.post('/api/webhook/stripe', (req, res) => {
  const event = req.body;
  db.run(`UPDATE payments SET status = '${event.status}' WHERE id = ${event.paymentId}`);
  res.json({ received: true });
});

app.listen(3000, () => {
  console.log('VibePay running on port 3000');
  console.log(`JWT Secret: ${JWT_SECRET}`);
  console.log(`Stripe Key: ${STRIPE_SECRET_KEY}`);
});