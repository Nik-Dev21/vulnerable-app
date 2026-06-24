const express = require('express');
const sqlite3 = require('sqlite3');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const bcrypt = require('bcryptjs'); // Added bcryptjs for password hashing

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Database setup
const db = new sqlite3.Database('./vibepay.db');

// Hardcoded secrets -> FIXED: Using environment variables
const JWT_SECRET = process.env.JWT_SECRET;
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const AWS_ACCESS_KEY = process.env.AWS_ACCESS_KEY;
const AWS_SECRET_KEY = process.env.AWS_SECRET_KEY;
const DATABASE_PASSWORD = process.env.DATABASE_PASSWORD;
const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY;

// CORS - allow everything
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', '*');
  res.header('Access-Control-Allow-Methods', '*');
  next();
});

// Helper function for HTML escaping to prevent XSS
function escapeHtml(text) {
  var map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.replace(/[&<>"']/g, function(m) { return map[m]; });
}

// Auth Middleware
const authMiddleware = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.split(' ')[1]; // Assuming "Bearer TOKEN"
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET); // FIXED: Using verify instead of decode
        req.user = decoded; // Attach user payload to request
        next();
    } catch (err) {
        return res.status(403).json({ error: 'Failed to authenticate token', details: err.message });
    }
};

// Admin Middleware
const adminMiddleware = (req, res, next) => {
    if (req.user && req.user.role === 'admin') { // FIXED: Checking role from verified token
        next();
    } else {
        res.status(403).json({ error: 'Forbidden: Admin access required' });
    }
};

// Login - SQL injection vulnerable -> FIXED with parameterized queries and bcrypt for password verification
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  // Use parameterized query to prevent SQL injection
  db.get('SELECT id, username, password, email, role FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    // Compare provided password with hashed password using bcrypt
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET);
    // Remove password hash before sending user object in response
    const { password: _, ...userWithoutPassword } = user;
    res.json({ token, user: userWithoutPassword });
  });
});

// Register - stores password in plaintext -> FIXED with bcrypt hashing
app.post('/api/register', async (req, res) => {
  const { username, password, email } = req.body;

  try {
    // Hash password with a salt before storing
    const hashedPassword = await bcrypt.hash(password, 10); // 10 salt rounds

    // Use parameterized query to prevent SQL injection
    const query = 'INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)';
    db.run(query, [username, hashedPassword, email, 'user'], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID, username, email });
    });
  } catch (error) {
    res.status(500).json({ error: 'Error processing password', details: error.message });
  }
});

// User profile - IDOR vulnerability (no auth check on who's requesting) -> FIXED with authMiddleware and authorization logic
app.get('/api/users/:id', authMiddleware, (req, res) => {
  const requestedId = parseInt(req.params.id, 10);
  let selectFields = 'id, username, email, role'; // Default for non-admin/self-view
  let queryParams = [requestedId];

  // Admin users can view sensitive data (ssn, credit_card) for any user
  if (req.user.role === 'admin') {
    selectFields = 'id, username, email, role, ssn, credit_card';
  } else {
    // Non-admin users can only view their own profile, and only non-sensitive data
    if (req.user.id !== requestedId) {
      return res.status(403).json({ error: 'Forbidden: You can only view your own profile' });
    }
  }

  // Use parameterized query
  db.get(`SELECT ${selectFields} FROM users WHERE id = ?`, queryParams, (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user); // Password hash is not selected, so it won't be returned
  });
});

// Search - XSS vulnerable -> FIXED with HTML escaping
app.get('/api/search', (req, res) => {
  const searchTerm = req.query.q;
  // Sanitize searchTerm to prevent XSS
  const html = `<h1>Search Results for: ${escapeHtml(searchTerm || '')}</h1>`; // Handle undefined 'q'
  res.send(html);
});

// Admin endpoint - broken auth (just checks if role field exists in token) -> FIXED with jwt.verify and adminMiddleware
app.get('/api/admin/users', authMiddleware, adminMiddleware, (req, res) => {
  // Select only non-sensitive fields to prevent data leakage, even if admin
  db.all('SELECT id, username, email, role FROM users', (err, users) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(users); // Sensitive data like password, ssn, credit_card are not selected
  });
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
  // Removed logging of secrets as per fixing hardcoded secrets issue
});