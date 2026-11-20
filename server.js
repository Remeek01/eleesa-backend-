const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');

const mailTransporter =
  process.env.EMAIL_USER && process.env.EMAIL_PASS
    ? nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS,
        },
      })
    : null;
const app = express();
const PORT = process.env.PORT || 3000;
const AUTH_SECRET = process.env.JWT_SECRET || 'eleesa-portal-secret-2026';

// 1. PostgreSQL Connection Pool
const pool = new Pool(
  process.env.DATABASE_URL
    ? {
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false },
      }
    : {
        user: 'postgres',
        host: 'localhost',
        database: 'eleesa_db',
        password: 'Semeek02',
        port: 5432,
      }
);

// Ensure password reset columns exist in users table
pool
  .query(
    `ALTER TABLE public.users
     ADD COLUMN IF NOT EXISTS reset_token TEXT,
     ADD COLUMN IF NOT EXISTS reset_token_expires TIMESTAMP;`
  )
  .catch((err) => console.error('Schema check warning:', err.message));

// 2. Password & Token Helpers (Built-in Node crypto)
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
  if (!storedHash || !storedHash.includes(':')) {
    return password === storedHash;
  }
  const [salt, key] = storedHash.split(':');
  const hashBuffer = crypto.scryptSync(password, salt, 64);
  const keyBuffer = Buffer.from(key, 'hex');
  return (
    keyBuffer.length === hashBuffer.length &&
    crypto.timingSafeEqual(keyBuffer, hashBuffer)
  );
}

function createAuthToken(user) {
  const payload = Buffer.from(
    JSON.stringify({
      user_id: user.user_id,
      full_name: user.full_name,
      role: user.role,
      level: user.level,
      exp: Date.now() + 7 * 24 * 60 * 60 * 1000, // 7 days
    })
  ).toString('base64url');

  const signature = crypto
    .createHmac('sha256', AUTH_SECRET)
    .update(payload)
    .digest('base64url');

  return `${payload}.${signature}`;
}

function verifyAuthToken(token) {
  const parts = token.split('.');
  if (parts.length !== 2) return null;

  const [payload, signature] = parts;
  const expectedSig = crypto
    .createHmac('sha256', AUTH_SECRET)
    .update(payload)
    .digest('base64url');

  if (signature !== expectedSig) return null;

  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (data.exp && Date.now() > data.exp) return null;
    return data;
  } catch {
    return null;
  }
}

function formatUserResponse(dbUser, token) {
  return {
    id: dbUser.user_id,
    index_or_staff_id: dbUser.index_or_staff_id,
    fullName: dbUser.full_name,
    email: dbUser.email,
    role: dbUser.role === 'hod_admin' ? 'hod' : dbUser.role,
    level: dbUser.level,
    token,
  };
}

// 3. Global Middleware
app.use(cors());
app.use(express.json());

app.get('/api/health', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW() AS server_time');
    res.json({ status: 'ok', time: result.rows[0].server_time });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// AUTHENTICATION ENDPOINTS
// ==========================================

// POST /api/auth/signup
app.post('/api/auth/signup', async (req, res) => {
  const { full_name, email, password, role = 'student', index_or_staff_id, level } = req.body;

  if (!full_name || !email || !password) {
    return res.status(400).json({ message: 'Full name, email, and password are required.' });
  }
  if (password.length < 6) {
    return res.status(400).json({ message: 'Password must be at least 6 characters.' });
  }

  const roleMap = {
    student: 'student',
    executive: 'executive',
    lecturer: 'lecturer',
    hod: 'hod_admin',
    hod_admin: 'hod_admin',
  };
  const dbRole = roleMap[String(role).toLowerCase()];
  if (!dbRole) {
    return res.status(400).json({ message: 'Invalid role selected.' });
  }

  const cleanEmail = String(email).trim().toLowerCase();
  const prefix = dbRole === 'student' || dbRole === 'executive' ? 'STU' : 'STF';
  const generatedId =
    index_or_staff_id?.trim() ||
    `${prefix}-${Date.now().toString().slice(-6)}${Math.floor(10 + Math.random() * 90)}`;
  const validLevel = [100, 200, 300, 400].includes(Number(level)) ? Number(level) : null;

  try {
    const existing = await pool.query('SELECT user_id FROM public.users WHERE LOWER(email) = $1', [
      cleanEmail,
    ]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ message: 'An account with this email already exists.' });
    }

    const passwordHash = hashPassword(password);
    const result = await pool.query(
      `INSERT INTO public.users (index_or_staff_id, full_name, email, password_hash, role, level)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING user_id, index_or_staff_id, full_name, email, role, level`,
      [generatedId, full_name.trim(), cleanEmail, passwordHash, dbRole, validLevel]
    );

    const newUser = result.rows[0];
    const token = createAuthToken(newUser);
    res.status(201).json({
      message: 'Account created successfully.',
      user: formatUserResponse(newUser, token),
    });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ message: 'Email or Index/Staff ID is already registered.' });
    }
    res.status(500).json({ message: err.message });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required.' });
  }

  try {
    const result = await pool.query(
      `SELECT user_id, index_or_staff_id, full_name, email, password_hash, role, level, is_active
       FROM public.users
       WHERE LOWER(email) = $1`,
      [String(email).trim().toLowerCase()]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    const dbUser = result.rows[0];
    if (!dbUser.is_active) {
      return res.status(403).json({ message: 'This account is deactivated. Contact the HOD.' });
    }

    if (!verifyPassword(password, dbUser.password_hash)) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    const token = createAuthToken(dbUser);
    res.json({
      message: 'Login successful.',
      user: formatUserResponse(dbUser, token),
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// POST /api/auth/forgot-password
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: 'Please enter your account email address.' });
  }

  try {
    const cleanEmail = String(email).trim().toLowerCase();
    const result = await pool.query(
      'SELECT user_id, full_name FROM public.users WHERE LOWER(email) = $1',
      [cleanEmail]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'No ELEESA account found with that email.' });
    }

    const fullName = result.rows[0].full_name;
    const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    await pool.query(
      'UPDATE public.users SET reset_token = $1, reset_token_expires = $2 WHERE user_id = $3',
      [resetCode, expiresAt, result.rows[0].user_id]
    );

    if (process.env.BREVO_API_KEY && process.env.SENDER_EMAIL) {
      const safeName = escapeHtml(fullName);
      const htmlTemplate = `
        <!DOCTYPE html>
        <html>
        <body style="margin:0;padding:0;background-color:#070d19;font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#e2e8f0;">
          <table width="100%" cellpadding="0" cellspacing="0" style="padding:32px 16px;">
            <tr>
              <td align="center">
                <table width="100%" style="max-width:520px;background-color:#0f172a;border:1px solid #1e293b;border-radius:16px;overflow:hidden;">
                  <tr>
                    <td style="background:linear-gradient(135deg,#0b132b 0%,#1d4ed8 100%);padding:28px 24px;text-align:center;border-bottom:2px solid #00e5ff;">
                      <div style="display:inline-block;padding:6px 14px;border-radius:999px;background-color:rgba(0,229,255,0.14);border:1px solid #00e5ff;color:#00e5ff;font-size:12px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;">
                        &#9889; ELEESA Security Grid
                      </div>
                      <h1 style="margin:14px 0 4px;font-size:22px;color:#ffffff;letter-spacing:0.5px;">Password Recovery</h1>
                      <p style="margin:0;font-size:13px;color:#cbd5e1;">Electrical &amp; Electronic Engineering Students Association</p>
                    </td>
                  </tr>
                  <tr>
                    <td style="padding:28px 24px;">
                      <p style="margin:0 0 14px;font-size:15px;color:#f8fafc;">Hello <strong>${safeName}</strong>,</p>
                      <p style="margin:0 0 22px;font-size:14px;line-height:1.6;color:#94a3b8;">
                        We received a request to reset your ELEESA Portal password. Enter the 6-digit verification code below in the app to complete the reset:
                      </p>
                      <div style="background-color:#070d19;border:1px dashed #00e5ff;border-radius:12px;padding:18px;text-align:center;margin-bottom:22px;">
                        <span style="font-family:'Courier New',Courier,monospace;font-size:32px;font-weight:800;letter-spacing:10px;color:#ffb703;">
                          ${resetCode}
                        </span>
                      </div>
                      <p style="margin:0 0 8px;font-size:13px;color:#94a3b8;">
                        &#9201; This code remains active for <strong style="color:#e2e8f0;">15 minutes</strong>.
                      </p>
                      <p style="margin:0;font-size:12px;color:#64748b;">
                        If you did not request a password reset, you can safely ignore this message.
                      </p>
                    </td>
                  </tr>
                  <tr>
                    <td style="background-color:#090f1d;padding:16px 24px;text-align:center;border-top:1px solid #1e293b;font-size:11px;color:#64748b;">
                      ELEESA Mobile Portal &bull; Automated Authentication Dispatch
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
          </table>
        </body>
        </html>
      `;

      const emailRes = await fetch('https://api.brevo.com/v3/smtp/email', {
        method: 'POST',
        headers: {
          'accept': 'application/json',
          'api-key': process.env.BREVO_API_KEY,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          sender: { name: 'ELEESA Portal', email: process.env.SENDER_EMAIL },
          to: [{ email: cleanEmail, name: fullName }],
          subject: '⚡ ELEESA Password Recovery Code',
          htmlContent: htmlTemplate,
          textContent: `Hello ${fullName},\n\nYour ELEESA password recovery code is: ${resetCode}\n\nThis code expires in 15 minutes.`,
        }),
      });

      if (!emailRes.ok) {
        const errData = await emailRes.json().catch(() => ({}));
        throw new Error(errData.message || 'Brevo failed to send recovery email.');
      }

      return res.json({
        message: 'A 6-digit recovery code has been sent to your email.',
      });
    }

    res.json({
      message: `Recovery code: ${resetCode} (Set BREVO_API_KEY & SENDER_EMAIL on Render to email it)`,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
// POST /api/auth/reset-password
app.post('/api/auth/reset-password', async (req, res) => {
  const { email, reset_code, new_password } = req.body;

  if (!email || !reset_code || !new_password) {
    return res.status(400).json({ message: 'Email, reset code, and new password are required.' });
  }
  if (new_password.length < 6) {
    return res.status(400).json({ message: 'New password must be at least 6 characters.' });
  }

  try {
    const result = await pool.query(
      `SELECT user_id, reset_token, reset_token_expires
       FROM public.users
       WHERE LOWER(email) = $1`,
      [String(email).trim().toLowerCase()]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Account not found.' });
    }

    const user = result.rows[0];
    if (!user.reset_token || user.reset_token !== String(reset_code).trim()) {
      return res.status(400).json({ message: 'Invalid recovery code.' });
    }
    if (!user.reset_token_expires || new Date(user.reset_token_expires) < new Date()) {
      return res.status(400).json({ message: 'Recovery code has expired. Request a new one.' });
    }

    const newHash = hashPassword(new_password);
    await pool.query(
      `UPDATE public.users
       SET password_hash = $1, reset_token = NULL, reset_token_expires = NULL
       WHERE user_id = $2`,
      [newHash, user.user_id]
    );

    res.json({ message: 'Password updated successfully. You can now log in.' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// 4. Role-Based Access Control Middleware (Visitors need no token)
function authenticateUser(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    req.user = { user_id: null, full_name: 'Guest Visitor', role: 'visitor', level: null };
    return next();
  }

  const token = authHeader.split(' ')[1];

  // Keep demo tokens working alongside real signed tokens
  const demoUsers = {
    'student-token': { user_id: 3, full_name: 'Level 300 Student', role: 'student', level: 300 },
    'executive-token': { user_id: 3, full_name: 'Maxwell Amoah (ELEESA Exec)', role: 'executive', level: 300 },
    'lecturer-token': { user_id: 2, full_name: 'Dr. A. Mensah', role: 'lecturer', level: null },
    'hod-token': { user_id: 1, full_name: 'Prof. K. Boateng (HOD)', role: 'hod_admin', level: null },
  };

  if (demoUsers[token]) {
    req.user = demoUsers[token];
    return next();
  }

  const verifiedUser = verifyAuthToken(token);
  if (!verifiedUser) {
    return res.status(401).json({ error: 'Invalid or expired access token' });
  }

  req.user = verifiedUser;
  next();
}

function requireRoles(...allowedRoles) {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: `Access denied for role '${req.user.role}'. Allowed: ${allowedRoles.join(', ')}`,
      });
    }
    next();
  };
}

app.use(authenticateUser);

// ==========================================
// PUBLIC ENDPOINTS (Visitors, Students, Staff)
// ==========================================

app.get('/api/v1/public/about', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT association_name, history, vision, mission, hod_message,
              president_message, contact_email, location_description, office_hours
       FROM department_info LIMIT 1`
    );
    res.json(result.rows[0] || {});
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/v1/public/staff', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT staff_id, full_name, rank, email, office_location,
              research_interests, consultation_hours
       FROM staff_directory ORDER BY staff_id`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/v1/public/courses', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT c.course_code, c.title, c.level, c.semester, c.credit_hours, c.prerequisites,
              COALESCE(s.full_name, 'TBA') AS lecturer
       FROM courses c
       LEFT JOIN staff_directory s ON c.lecturer_id = s.staff_id
       ORDER BY c.level, c.course_code`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/v1/public/timetables', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT slot_id, course_code, schedule_type, level, day_or_date,
              TO_CHAR(start_time, 'HH24:MI') AS start_time,
              TO_CHAR(end_time, 'HH24:MI') AS end_time,
              venue
       FROM timetables ORDER BY level, slot_id`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/v1/public/labs', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT lab_id, lab_name, location, safety_rules FROM labs ORDER BY lab_id`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/v1/public/notices', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT notice_id, title, body, category,
              TO_CHAR(event_date, 'YYYY-MM-DD HH24:MI') AS event_date
       FROM notices_events
       WHERE approval_status = 'approved'
       ORDER BY notice_id DESC`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==========================================
// PROTECTED ENDPOINTS (Role-Based Access)
// ==========================================

app.get(
  '/api/v1/resources',
  requireRoles('student', 'executive', 'lecturer', 'hod_admin'),
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT resource_id, course_code, title, category, file_or_external_url
         FROM resources
         WHERE approval_status = 'approved'
         ORDER BY resource_id`
      );
      res.json({ user: req.user, resources: result.rows });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

app.post(
  '/api/v1/notices',
  requireRoles('executive', 'lecturer', 'hod_admin'),
  async (req, res) => {
    const { title, body, category = 'notice' } = req.body;
    const validCategories = ['notice', 'seminar', 'workshop', 'eleesa_event', 'career_alumni'];

    if (!title || !body) {
      return res.status(400).json({ error: 'Title and body are required.' });
    }
    if (!validCategories.includes(category)) {
      return res.status(400).json({ error: `Invalid category. Use: ${validCategories.join(', ')}` });
    }

    try {
      const result = await pool.query(
        `INSERT INTO notices_events (title, body, category, posted_by, approval_status)
         VALUES ($1, $2, $3, $4, 'approved')
         RETURNING notice_id, title, body, category, TO_CHAR(event_date, 'YYYY-MM-DD HH24:MI') AS event_date`,
        [title, body, category, req.user.user_id]
      );
      res.status(201).json(result.rows[0]);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// 5. Start Server & Verify Database Connection
const server = app.listen(PORT, (err) => {
  if (err) {
    console.error('Failed to start server:', err.message);
    process.exit(1);
  }
  console.log(`ELEESA API server running at http://localhost:${PORT}`);

  pool
    .query('SELECT current_database() AS db')
    .then((res) => console.log(`Connected to PostgreSQL database: ${res.rows[0].db}`))
    .catch((dbErr) => console.error('PostgreSQL connection error:', dbErr.message));
});

server.on('error', (err) => {
  console.error('Server error:', err.message);
  process.exit(1);
});