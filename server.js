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

// --- AES-256-GCM ENCRYPTION FOR SENSITIVE PII ---
function getEncryptionKey() {
  const secret =
    process.env.PROFILE_ENCRYPTION_KEY ||
    process.env.DATABASE_URL ||
    'eleesa-default-grid-key-2026';
  return crypto.createHash('sha256').update(String(secret)).digest();
}

function encryptSensitive(plainText) {
  if (!plainText) return '';
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', getEncryptionKey(), iv);
  const encrypted = Buffer.concat([
    cipher.update(String(plainText), 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
}

function decryptSensitive(cipherPayload) {
  if (!cipherPayload || !String(cipherPayload).includes(':')) {
    return cipherPayload || '';
  }
  try {
    const [ivHex, tagHex, dataHex] = String(cipherPayload).split(':');
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      getEncryptionKey(),
      Buffer.from(ivHex, 'hex')
    );
    decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(dataHex, 'hex')),
      decipher.final(),
    ]);
    return decrypted.toString('utf8');
  } catch (_) {
    return '[Encrypted Record]';
  }
}

const LEVEL_TABLES = {
  '100': 'level_100_students',
  '200': 'level_200_students',
  '300': 'level_300_students',
  '400': 'level_400_students',
};

// --- AUTO-CREATE 4 LEVEL TABLES & STAFF PROFILES IN NEON ---
async function ensureEleesaGridSchema() {
  try {
    await pool.query(`
      ALTER TABLE public.users
        ADD COLUMN IF NOT EXISTS profile_completed BOOLEAN DEFAULT FALSE,
        ADD COLUMN IF NOT EXISTS level VARCHAR(10),
        ADD COLUMN IF NOT EXISTS index_or_staff_id VARCHAR(50),
        ADD COLUMN IF NOT EXISTS avatar_data TEXT,
        ADD COLUMN IF NOT EXISTS bio TEXT;
    `);

    for (const tableName of Object.values(LEVEL_TABLES)) {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS public.${tableName} (
          student_record_id SERIAL PRIMARY KEY,
          user_id VARCHAR(100) UNIQUE NOT NULL,
          full_name VARCHAR(150) NOT NULL,
          email VARCHAR(150) NOT NULL,
          index_number VARCHAR(50) NOT NULL,
          specialization VARCHAR(120) DEFAULT 'General Electrical & Electronic Engineering',
          gender VARCHAR(20),
          dob_encrypted TEXT NOT NULL,
          phone_encrypted TEXT NOT NULL,
          emergency_contact_encrypted TEXT NOT NULL,
          hostel_encrypted TEXT NOT NULL,
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
      `);
    }

    await pool.query(`
      CREATE TABLE IF NOT EXISTS public.staff_profiles (
        staff_record_id SERIAL PRIMARY KEY,
        user_id VARCHAR(100) UNIQUE NOT NULL,
        full_name VARCHAR(150) NOT NULL,
        email VARCHAR(150) NOT NULL,
        role VARCHAR(30) NOT NULL,
        staff_id VARCHAR(50) NOT NULL,
        academic_title VARCHAR(80) NOT NULL,
        specialization VARCHAR(150) NOT NULL,
        office_hours VARCHAR(120),
        gender VARCHAR(20),
        dob_encrypted TEXT NOT NULL,
        phone_encrypted TEXT NOT NULL,
        office_line_encrypted TEXT NOT NULL,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('ELEESA 4-level & encrypted staff tables verified.');
  } catch (err) {
    console.error('Schema initialization error:', err.message); throw err;
  }
}
let _gridSchemaPromise = null;
function getGridSchemaReady() {
  if (!_gridSchemaPromise) {
    _gridSchemaPromise = Promise.resolve()
      .then(async () => {
        if (typeof ensureEleesaGridSchema === 'function') {
          try {
            await ensureEleesaGridSchema();
          } catch (e1) {
            console.error('Grid schema warning:', e1.message);
          }
        }
        if (typeof ensureWave2AcademicSchema === 'function') {
          try {
            await ensureWave2AcademicSchema();
          } catch (e2) {
            console.error('Wave 2 schema warning:', e2.message);
          }
        }
      })
      .catch((err) => {
        _gridSchemaPromise = null;
        console.error('Schema runner warning:', err.message);
      });
  }
  return _gridSchemaPromise;
}
getGridSchemaReady().catch(() => {});

// GET /api/profile?email=...
app.get('/api/profile', async (req, res) => {
  await getGridSchemaReady();
  const email = String(req.query.email || '').trim().toLowerCase();
  if (!email) {
    return res.status(400).json({ message: 'Email is required.' });
  }

  try {
    const userRes = await pool.query(
      'SELECT user_id, full_name, email, role, level, index_or_staff_id, avatar_data, bio, COALESCE(profile_completed, FALSE) AS profile_completed FROM public.users WHERE LOWER(email) = $1',
      [email]
    );
    if (userRes.rows.length === 0) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const user = userRes.rows[0];
    let profile = null;

    if (user.role === 'student' || user.role === 'executive') {
      const levelsToCheck = user.level && LEVEL_TABLES[user.level]
        ? [user.level, ...Object.keys(LEVEL_TABLES).filter((l) => l !== user.level)]
        : Object.keys(LEVEL_TABLES);

      for (const lvl of levelsToCheck) {
        const tbl = LEVEL_TABLES[lvl];
        const rowRes = await pool.query(
          `SELECT * FROM public.${tbl} WHERE user_id = $1`,
          [String(user.user_id)]
        );
        if (rowRes.rows.length > 0) {
          const r = rowRes.rows[0];
          profile = {
            table_name: tbl,
            level: lvl,
            full_name: r.full_name,
            email: r.email,
            index_number: r.index_number,
            specialization: r.specialization,
            gender: r.gender || '',
            dob: decryptSensitive(r.dob_encrypted),
            phone: decryptSensitive(r.phone_encrypted),
            emergency_contact: decryptSensitive(r.emergency_contact_encrypted),
            hostel: decryptSensitive(r.hostel_encrypted),
            updated_at: r.updated_at,
          };
          break;
        }
      }
    } else {
      const staffRes = await pool.query(
        'SELECT * FROM public.staff_profiles WHERE user_id = $1',
        [String(user.user_id)]
      );
      if (staffRes.rows.length > 0) {
        const s = staffRes.rows[0];
        profile = {
          table_name: 'staff_profiles',
          full_name: s.full_name,
          email: s.email,
          role: s.role,
          staff_id: s.staff_id,
          academic_title: s.academic_title,
          specialization: s.specialization,
          office_hours: s.office_hours || '',
          gender: s.gender || '',
          dob: decryptSensitive(s.dob_encrypted),
          phone: decryptSensitive(s.phone_encrypted),
          office_line: decryptSensitive(s.office_line_encrypted),
          updated_at: s.updated_at,
        };
      }
    }

    res.json({ user, profile });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST /api/profile/save (Routes student into level_100..400 or staff into staff_profiles)
app.post('/api/profile/save', async (req, res) => {
  await getGridSchemaReady();
  const {
    email,
    full_name,
    level,
    index_or_staff_id,
    gender,
    dob,
    phone,
    specialization,
    emergency_contact,
    hostel,
    academic_title,
    office_hours,
    office_line,
  } = req.body;

  if (!email || !full_name || !dob || !phone) {
    return res.status(400).json({
      message: 'Full name, date of birth, and phone number are required.',
    });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const cleanEmail = String(email).trim().toLowerCase();
    const userRes = await client.query(
      'SELECT user_id, role FROM public.users WHERE LOWER(email) = $1',
      [cleanEmail]
    );
    if (userRes.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ message: 'Account not found.' });
    }

    const { user_id, role } = userRes.rows[0];
    const cleanName = String(full_name).trim();
    const cleanId = String(index_or_staff_id || '').trim();

    if (role === 'student' || role === 'executive') {
      const cleanLevel = String(level || '').trim();
      const targetTable = LEVEL_TABLES[cleanLevel];
      if (!targetTable) {
        await client.query('ROLLBACK');
        return res.status(400).json({
          message: 'Please select a valid academic level (100, 200, 300, or 400).',
        });
      }
      if (!cleanId) {
        await client.query('ROLLBACK');
        return res.status(400).json({ message: 'Index number is required for students.' });
      }

      for (const [lvlKey, tblName] of Object.entries(LEVEL_TABLES)) {
        if (lvlKey !== cleanLevel) {
          await client.query(`DELETE FROM public.${tblName} WHERE user_id = $1`, [String(user_id)]);
        }
      }

      await client.query(
        `INSERT INTO public.${targetTable} (
          user_id, full_name, email, index_number, specialization, gender,
          dob_encrypted, phone_encrypted, emergency_contact_encrypted, hostel_encrypted, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CURRENT_TIMESTAMP)
        ON CONFLICT (user_id) DO UPDATE SET
          full_name = EXCLUDED.full_name,
          email = EXCLUDED.email,
          index_number = EXCLUDED.index_number,
          specialization = EXCLUDED.specialization,
          gender = EXCLUDED.gender,
          dob_encrypted = EXCLUDED.dob_encrypted,
          phone_encrypted = EXCLUDED.phone_encrypted,
          emergency_contact_encrypted = EXCLUDED.emergency_contact_encrypted,
          hostel_encrypted = EXCLUDED.hostel_encrypted,
          updated_at = CURRENT_TIMESTAMP`,
        [
          user_id,
          cleanName,
          cleanEmail,
          cleanId,
          String(specialization || 'General Electrical & Electronic Engineering').trim(),
          String(gender || '').trim(),
          encryptSensitive(dob),
          encryptSensitive(phone),
          encryptSensitive(emergency_contact || 'Not provided'),
          encryptSensitive(hostel || 'Not provided'),
        ]
      );

      await client.query(
        `UPDATE public.users
         SET full_name = $1, level = $2, index_or_staff_id = $3, profile_completed = TRUE
         WHERE user_id = $4`,
        [cleanName, cleanLevel, cleanId, user_id]
      );
    } else {
      if (!cleanId) {
        await client.query('ROLLBACK');
        return res.status(400).json({ message: 'Staff ID is required.' });
      }

      await client.query(
        `INSERT INTO public.staff_profiles (
          user_id, full_name, email, role, staff_id, academic_title,
          specialization, office_hours, gender, dob_encrypted, phone_encrypted, office_line_encrypted, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, CURRENT_TIMESTAMP)
        ON CONFLICT (user_id) DO UPDATE SET
          full_name = EXCLUDED.full_name,
          email = EXCLUDED.email,
          role = EXCLUDED.role,
          staff_id = EXCLUDED.staff_id,
          academic_title = EXCLUDED.academic_title,
          specialization = EXCLUDED.specialization,
          office_hours = EXCLUDED.office_hours,
          gender = EXCLUDED.gender,
          dob_encrypted = EXCLUDED.dob_encrypted,
          phone_encrypted = EXCLUDED.phone_encrypted,
          office_line_encrypted = EXCLUDED.office_line_encrypted,
          updated_at = CURRENT_TIMESTAMP`,
        [
          user_id,
          cleanName,
          cleanEmail,
          role,
          cleanId,
          String(academic_title || (role === 'hod_admin' ? 'Head of Department (EEE)' : 'Lecturer')).trim(),
          String(specialization || 'Electrical & Electronic Engineering').trim(),
          String(office_hours || 'Mon - Fri, 9:00 AM - 4:00 PM').trim(),
          String(gender || '').trim(),
          encryptSensitive(dob),
          encryptSensitive(phone),
          encryptSensitive(office_line || phone),
        ]
      );

      await client.query(
        `UPDATE public.users
         SET full_name = $1, index_or_staff_id = $2, profile_completed = TRUE
         WHERE user_id = $3`,
        [cleanName, cleanId, user_id]
      );
    }

    await client.query('COMMIT');
    res.json({ message: 'Encrypted profile saved to ELEESA Grid.' });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ message: err.message });
  } finally {
    client.release();
  }
});

// GET /api/hub/students-by-level?requester_email=... (Lecturer & HoD Only)
app.get('/api/hub/students-by-level', async (req, res) => {
  await getGridSchemaReady();
  const requesterEmail = String(req.query.requester_email || '').trim().toLowerCase();
  if (!requesterEmail) {
    return res.status(400).json({ message: 'Requester email is required.' });
  }

  try {
    const authRes = await pool.query(
      'SELECT role FROM public.users WHERE LOWER(email) = $1',
      [requesterEmail]
    );
    if (
      authRes.rows.length === 0 ||
      !['lecturer', 'hod_admin'].includes(authRes.rows[0].role)
    ) {
      return res.status(403).json({
        message: 'Access denied. Only Lecturers and the HoD can inspect the 4-level student database.',
      });
    }

    const levels = {};
    const counts = { '100': 0, '200': 0, '300': 0, '400': 0, total: 0 };

    for (const [lvl, tbl] of Object.entries(LEVEL_TABLES)) {
      const rowsRes = await pool.query(
        `SELECT * FROM public.${tbl} ORDER BY full_name ASC`
      );
      levels[lvl] = rowsRes.rows.map((r) => ({
        student_record_id: r.student_record_id,
        full_name: r.full_name,
        email: r.email,
        index_number: r.index_number,
        level: lvl,
        table_name: tbl,
        specialization: r.specialization,
        gender: r.gender || 'N/A',
        dob: decryptSensitive(r.dob_encrypted),
        phone: decryptSensitive(r.phone_encrypted),
        emergency_contact: decryptSensitive(r.emergency_contact_encrypted),
        hostel: decryptSensitive(r.hostel_encrypted),
      }));
      counts[lvl] = levels[lvl].length;
      counts.total += levels[lvl].length;
    }

    res.json({ counts, levels });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// GET /api/hub/staff-directory?requester_email=... (HoD & Lecturer Directory)
app.get('/api/hub/staff-directory', async (req, res) => {
  await getGridSchemaReady();
  const requesterEmail = String(req.query.requester_email || '').trim().toLowerCase();
  try {
    const authRes = await pool.query(
      'SELECT role FROM public.users WHERE LOWER(email) = $1',
      [requesterEmail]
    );
    if (
      authRes.rows.length === 0 ||
      !['lecturer', 'hod_admin'].includes(authRes.rows[0].role)
    ) {
      return res.status(403).json({ message: 'Staff access only.' });
    }

    const staffRes = await pool.query(
      'SELECT * FROM public.staff_profiles ORDER BY role DESC, full_name ASC'
    );
    const staff = staffRes.rows.map((s) => ({
      staff_id: s.staff_id,
      full_name: s.full_name,
      email: s.email,
      role: s.role,
      academic_title: s.academic_title,
      specialization: s.specialization,
      office_hours: s.office_hours,
      phone: decryptSensitive(s.phone_encrypted),
      office_line: decryptSensitive(s.office_line_encrypted),
    }));

    res.json({ staff });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST /api/profile/avatar (Wave 1: Student & Staff Profile Picture Upload)
app.post('/api/profile/avatar', async (req, res) => {
  await getGridSchemaReady();
  const cleanEmail = String(req.body.email || '').trim().toLowerCase();
  const avatarData = String(req.body.avatar_data || '').trim();

  if (!cleanEmail || !avatarData) {
    return res.status(400).json({ message: 'Email and avatar image data are required.' });
  }
  if (avatarData.length > 2500000) {
    return res.status(400).json({ message: 'Image is too large. Please choose a photo under 1.5 MB.' });
  }

  try {
    const result = await pool.query(
      'UPDATE public.users SET avatar_data = $1 WHERE LOWER(email) = $2 RETURNING user_id, full_name, email, avatar_data',
      [avatarData, cleanEmail]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found.' });
    }
    res.json({
      message: 'Profile picture updated on ELEESA Grid.',
      avatar_data: result.rows[0].avatar_data,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// GET /api/public/visitor-hub (Wave 1: No-Login Visitor Portal)
app.get('/api/public/visitor-hub', async (req, res) => {
  await getGridSchemaReady();
  try {
    const staffRes = await pool.query(`
      SELECT s.staff_id, s.full_name, s.email, s.role, s.academic_title,
             s.specialization, s.office_hours, u.avatar_data
      FROM public.staff_profiles s
      LEFT JOIN public.users u ON LOWER(u.email) = LOWER(s.email)
      ORDER BY s.role DESC, s.full_name ASC
    `);

    res.json({
      about: {
        department_name: 'Department of Electrical & Electronic Engineering',
        association: 'Electrical & Electronic Engineering Students Association (ELEESA)',
        institution: 'University of Mines and Technology (UMaT)',
        location: 'Faculty of Engineering Block, UMaT Main Campus, Tarkwa, Ghana',
        office_hours: 'Monday – Friday • 8:00 AM – 5:00 PM GMT',
        history:
          'Established to train world-class electrical and electronic engineers for Ghana’s power, mining, telecommunications, and industrial automation sectors, the department combines rigorous analytical theory with hands-on laboratory and substation training.',
        vision:
          'To be a premier centre of excellence in Electrical and Electronic Engineering education, sustainable energy systems, and applied technological innovation across Africa.',
        mission:
          'To produce ethically grounded, industry-ready engineers equipped with strong problem-solving, research, and leadership capabilities through modern laboratories and industry partnerships.',
        hod_message:
          'Welcome to the ELEESA Digital Grid. Whether you are a prospective student, visitor, faculty member, or undergraduate engineer, this platform connects our lecture halls, laboratories, and research community into one unified academic ecosystem.',
        programs: [
          {
            code: 'BSc. EEE',
            title: 'BSc. Electrical and Electronic Engineering (4-Year)',
            tracks: [
              'Power Systems & High Voltage Engineering',
              'Control Systems & Industrial Automation',
              'Telecommunications & Signal Processing',
              'Embedded Systems & Power Electronics',
            ],
          },
          {
            code: 'MSc / MPhil',
            title: 'Postgraduate Research in Electrical & Electronic Engineering',
            tracks: [
              'Renewable Energy & Smart Grids',
              'Instrumentation & Control Engineering',
            ],
          },
        ],
      },
      staff: staffRes.rows,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// 5. Start Server & Verify Database Connection
let _wave2ReadyPromise = null;
function ensureWave2Ready() {
  if (!_wave2ReadyPromise) {
    _wave2ReadyPromise = ensureWave2AcademicSchema().catch((err) => {
      _wave2ReadyPromise = null;
      console.error('Wave 2 schema error:', err.message);
      throw err;
    });
  }
  return _wave2ReadyPromise;
}
async function ensureWave2AcademicSchema() {
try {
await pool.query(`
  CREATE TABLE IF NOT EXISTS public.department_info (
    id INTEGER PRIMARY KEY DEFAULT 1,
    department_name VARCHAR(200) NOT NULL,
    institution VARCHAR(200) NOT NULL,
    location VARCHAR(250) NOT NULL,
    office_hours VARCHAR(150) NOT NULL,
    contact_email VARCHAR(150),
    contact_phone VARCHAR(80),
    history TEXT NOT NULL,
    vision TEXT NOT NULL,
    mission TEXT NOT NULL,
    hod_message TEXT NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
  )
`);

await pool.query(`
  CREATE TABLE IF NOT EXISTS public.eleesa_courses (
    course_id SERIAL PRIMARY KEY,
    course_code VARCHAR(30) UNIQUE NOT NULL,
    course_title VARCHAR(200) NOT NULL,
    level VARCHAR(10) NOT NULL,
    semester VARCHAR(10) NOT NULL,
    credit_hours INTEGER NOT NULL DEFAULT 3,
    prerequisites VARCHAR(200) DEFAULT 'None',
    syllabus TEXT NOT NULL,
    lecturer_name VARCHAR(150) NOT NULL,
    lecturer_email VARCHAR(150),
    updated_at TIMESTAMPTZ DEFAULT NOW()
  )
`);

await pool.query(`
  CREATE TABLE IF NOT EXISTS public.eleesa_timetables (
    entry_id SERIAL PRIMARY KEY,
    entry_type VARCHAR(20) NOT NULL DEFAULT 'lecture',
    level VARCHAR(10) NOT NULL,
    day_or_date VARCHAR(60) NOT NULL,
    time_slot VARCHAR(60) NOT NULL,
    course_code VARCHAR(30) NOT NULL,
    course_title VARCHAR(200) NOT NULL,
    venue VARCHAR(120) NOT NULL,
    lecturer_or_invigilator VARCHAR(150) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )
`);

await pool.query(`
  CREATE TABLE IF NOT EXISTS public.academic_calendar (
    event_id SERIAL PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    category VARCHAR(40) NOT NULL DEFAULT 'Academic',
    event_date VARCHAR(80) NOT NULL,
    target_level VARCHAR(20) NOT NULL DEFAULT 'ALL',
    description TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )
`);
} catch (tblErr) {
console.error('Wave 2 table creation error:', tblErr.message);
}

try {
await pool.query(`
  ALTER TABLE public.staff_profiles
    ADD COLUMN IF NOT EXISTS office_location VARCHAR(150) DEFAULT 'Engineering Block, 2nd Floor',
    ADD COLUMN IF NOT EXISTS courses_taught TEXT DEFAULT 'Core EEE Modules',
    ADD COLUMN IF NOT EXISTS research_interests TEXT DEFAULT 'Power Systems, Control & Embedded Electronics'
`);
} catch (alterErr) {
console.error('staff_profiles alter warning:', alterErr.message);
}

try {
const deptCheck = await pool.query('SELECT COUNT(*)::int AS cnt FROM public.department_info');
if ((deptCheck.rows[0]?.cnt ?? 0) === 0) {
  await pool.query(
    `INSERT INTO public.department_info
     (id, department_name, institution, location, office_hours, contact_email, contact_phone, history, vision, mission, hod_message)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
    [
      1,
      'Department of Electrical & Electronic Engineering',
      'University of Mines and Technology (UMaT)',
      'Faculty of Engineering Block, UMaT Main Campus, Tarkwa',
      'Monday – Friday • 8:00 AM – 5:00 PM GMT',
      'eee.dept@umat.edu.gh',
      '+233 (0) 312 320 324',
      'Established to train world-class electrical and electronic engineers for Ghana’s power, mining, telecommunications, and industrial automation sectors, the department combines analytical theory with hands-on laboratory and substation training.',
      'To be a premier centre of excellence in Electrical and Electronic Engineering education, sustainable energy systems, and applied technological innovation across Africa.',
      'To produce ethically grounded, industry-ready engineers equipped with strong problem-solving, research, and leadership capabilities through modern laboratories and industry partnerships.',
      'Welcome to the ELEESA Digital Grid. Whether you are a student, lecturer, or visitor, this hub connects our lecture halls, laboratories, and research groups into one unified engineering workspace.'
    ]
  );
}

const courseCount = await pool.query('SELECT COUNT(*)::int AS cnt FROM public.eleesa_courses');
if (courseCount.rows[0].cnt === 0) {
  const seedCourses = [
    ['EL 151', 'Applied Electricity & Circuit Fundamentals', '100', '1', 3, 'None', 'DC/AC network theorems, mesh and nodal analysis, phasors, resonance, and single-phase power circuits.', 'Dr. K. Mensah', 'kmensah@umat.edu.gh'],
    ['EL 152', 'Basic Electronics & Semiconductor Devices', '100', '2', 3, 'EL 151', 'PN junction diodes, rectifiers, BJT and MOSFET biasing, small-signal amplifiers, and operational amplifier basics.', 'Ing. A. Boateng', 'aboateng@umat.edu.gh'],
    ['EL 251', 'Electromagnetic Field Theory', '200', '1', 3, 'EL 151', 'Vector calculus, electrostatics, magnetostatics, Faraday’s law, Maxwell’s equations, and transmission line fundamentals.', 'Dr. E. Osei-Tutu', 'eoseitutu@umat.edu.gh'],
    ['EL 254', 'Digital Logic & Microprocessor Systems', '200', '2', 3, 'EL 152', 'Boolean algebra, combinational and sequential logic design, VHDL basics, and 8-bit/32-bit microcontroller architecture.', 'Ing. S. Owusu', 'sowusu@umat.edu.gh'],
    ['EL 351', 'Control Systems Engineering', '300', '1', 3, 'EL 251', 'Transfer functions, state-space modeling, time-domain stability, Routh-Hurwitz criterion, root locus, and Bode/Nyquist frequency design.', 'Dr. M. Asante', 'masante@umat.edu.gh'],
    ['EL 353', 'Power Systems Analysis & Protection', '300', '1', 3, 'EL 251', 'Per-unit system, symmetrical components, load flow studies (Gauss-Seidel & Newton-Raphson), fault analysis, and relay coordination.', 'Prof. J. K. Gyimah', 'jkgyimah@umat.edu.gh'],
    ['EL 356', 'Power Electronics & Electric Drives', '300', '2', 3, 'EL 152, EL 353', 'Controlled rectifiers, DC-DC choppers, PWM inverters, and variable-speed induction/DC motor drives.', 'Ing. R. Darko', 'rdarko@umat.edu.gh'],
    ['EL 451', 'High Voltage Engineering & Substations', '400', '1', 3, 'EL 353', 'Dielectric breakdown mechanisms, surge arresters, insulation coordination, switchgear, and primary substation design.', 'Prof. J. K. Gyimah', 'jkgyimah@umat.edu.gh'],
    ['EL 454', 'Industrial Automation & SCADA Systems', '400', '2', 3, 'EL 351', 'PLC ladder logic programming, industrial fieldbuses, SCADA telemetry, and smart grid instrumentation.', 'Dr. M. Asante', 'masante@umat.edu.gh']
  ];
  for (const c of seedCourses) {
    await pool.query(
      `INSERT INTO public.eleesa_courses
       (course_code, course_title, level, semester, credit_hours, prerequisites, syllabus, lecturer_name, lecturer_email)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (course_code) DO NOTHING`,
      c
    );
  }
}

const ttCount = await pool.query('SELECT COUNT(*)::int AS cnt FROM public.eleesa_timetables');
if (ttCount.rows[0].cnt === 0) {
  const seedSlots = [
    ['lecture', '100', 'Monday', '08:00 AM – 10:00 AM', 'EL 151', 'Applied Electricity & Circuit Fundamentals', 'LT 1 (Main Block)', 'Dr. K. Mensah'],
    ['lecture', '200', 'Monday', '10:30 AM – 12:30 PM', 'EL 251', 'Electromagnetic Field Theory', 'LT 2 (Eng. Block)', 'Dr. E. Osei-Tutu'],
    ['lecture', '300', 'Monday', '08:00 AM – 10:00 AM', 'EL 351', 'Control Systems Engineering', 'EEE Lecture Room 3', 'Dr. M. Asante'],
    ['lecture', '300', 'Wednesday', '01:30 PM – 03:30 PM', 'EL 353', 'Power Systems Analysis & Protection', 'Power Lab Seminar Room', 'Prof. J. K. Gyimah'],
    ['lecture', '400', 'Tuesday', '09:00 AM – 11:00 AM', 'EL 451', 'High Voltage Engineering & Substations', 'High Voltage Wing', 'Prof. J. K. Gyimah'],
    ['exam', '300', 'Dec 08, 2026', '09:00 AM – 12:00 PM', 'EL 351', 'Control Systems Engineering', 'Main Auditorium Hall A', 'Dr. M. Asante'],
    ['exam', '300', 'Dec 11, 2026', '09:00 AM – 12:00 PM', 'EL 353', 'Power Systems Analysis & Protection', 'Main Auditorium Hall A', 'Prof. J. K. Gyimah'],
    ['exam', '100', 'Dec 07, 2026', '09:00 AM – 12:00 PM', 'EL 151', 'Applied Electricity & Circuit Fundamentals', 'Engineering Exam Hall', 'Dr. K. Mensah'],
    ['exam', '200', 'Dec 09, 2026', '02:00 PM – 05:00 PM', 'EL 251', 'Electromagnetic Field Theory', 'Engineering Exam Hall', 'Dr. E. Osei-Tutu'],
    ['exam', '400', 'Dec 10, 2026', '09:00 AM – 12:00 PM', 'EL 451', 'High Voltage Engineering & Substations', 'Main Auditorium Hall B', 'Prof. J. K. Gyimah']
  ];
  for (const s of seedSlots) {
    await pool.query(
      `INSERT INTO public.eleesa_timetables
       (entry_type, level, day_or_date, time_slot, course_code, course_title, venue, lecturer_or_invigilator)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      s
    );
  }
}

const calCount = await pool.query('SELECT COUNT(*)::int AS cnt FROM public.academic_calendar');
if (calCount.rows[0].cnt === 0) {
  const seedEvents = [
    ['Course Registration & Add/Drop Window Closes', 'Deadline', 'Nov 28, 2026', 'ALL', 'Final deadline for confirming Semester 1 courses on the student portal.'],
    ['Mid-Semester Practical & Lab Assessment Week', 'Academic', 'Dec 01 – Dec 04, 2026', 'ALL', 'Mandatory laboratory practical evaluations across Machines, Power, and Electronics labs.'],
    ['End-of-Semester Written Examinations', 'Exams', 'Dec 07 – Dec 18, 2026', 'ALL', 'University-wide end-of-semester examinations. Bring student ID and approved non-programmable calculators.'],
    ['Final-Year Project Topic Defense', 'Deadline', 'Dec 15, 2026', '400', 'Level 400 students present project problem statements and block diagrams to faculty supervisors.'],
    ['Inter-Semester Break & Industrial Attachment Prep', 'Holiday', 'Dec 21, 2026 – Jan 10, 2027', 'ALL', 'Semester break and industrial placement letter collection at the departmental office.']
  ];
  for (const ev of seedEvents) {
    await pool.query(
      `INSERT INTO public.academic_calendar (title, category, event_date, target_level, description)
       VALUES ($1,$2,$3,$4,$5)`,
      ev
    );
  }
}
} catch (seedErr) {
console.error('Wave 2 seed warning:', seedErr.message);
}
}
// GET /api/academic/overview (Item #1: Home Dashboard Live Feed)
async function ensureTimetableAndCalendarSeeded() {
  const diagnostics = { timetableError: null, calendarError: null, timetableCount: 0, calendarCount: 0 };

  try {
    await pool.query(`
      CREATE SEQUENCE IF NOT EXISTS public.eleesa_timetables_entry_id_seq;
      ALTER TABLE public.eleesa_timetables
        ALTER COLUMN entry_id SET DEFAULT nextval('public.eleesa_timetables_entry_id_seq');
      SELECT setval('public.eleesa_timetables_entry_id_seq', COALESCE((SELECT MAX(entry_id) FROM public.eleesa_timetables), 0) + 1, false);
    `);
  } catch (e) {
    diagnostics.timetableError = 'seq: ' + e.message;
  }

  try {
    await pool.query(`
      CREATE SEQUENCE IF NOT EXISTS public.academic_calendar_event_id_seq;
      ALTER TABLE public.academic_calendar
        ALTER COLUMN event_id SET DEFAULT nextval('public.academic_calendar_event_id_seq');
      SELECT setval('public.academic_calendar_event_id_seq', COALESCE((SELECT MAX(event_id) FROM public.academic_calendar), 0) + 1, false);
    `);
  } catch (e) {
    diagnostics.calendarError = 'seq: ' + e.message;
  }

  try {
    const tRes = await pool.query('SELECT COUNT(*)::int AS cnt FROM public.eleesa_timetables');
    let cnt = tRes.rows[0]?.cnt ?? 0;
    if (cnt === 0) {
      const seedSlots = [
        ['lecture', '100', 'Monday', '08:00 AM – 10:00 AM', 'EL 151', 'Applied Electricity & Circuit Fundamentals', 'LT 1 (Main Block)', 'Dr. K. Mensah'],
        ['lecture', '200', 'Monday', '10:30 AM – 12:30 PM', 'EL 251', 'Electromagnetic Field Theory', 'LT 2 (Eng. Block)', 'Dr. E. Osei-Tutu'],
        ['lecture', '300', 'Monday', '08:00 AM – 10:00 AM', 'EL 351', 'Control Systems Engineering', 'EEE Lecture Room 3', 'Dr. M. Asante'],
        ['lecture', '300', 'Wednesday', '01:30 PM – 03:30 PM', 'EL 353', 'Power Systems Analysis & Protection', 'Power Lab Seminar Room', 'Prof. J. K. Gyimah'],
        ['lecture', '400', 'Tuesday', '09:00 AM – 11:00 AM', 'EL 451', 'High Voltage Engineering & Substations', 'High Voltage Wing', 'Prof. J. K. Gyimah'],
        ['exam', '300', 'Dec 08, 2026', '09:00 AM – 12:00 PM', 'EL 351', 'Control Systems Engineering', 'Main Auditorium Hall A', 'Dr. M. Asante'],
        ['exam', '300', 'Dec 11, 2026', '09:00 AM – 12:00 PM', 'EL 353', 'Power Systems Analysis & Protection', 'Main Auditorium Hall A', 'Prof. J. K. Gyimah'],
        ['exam', '100', 'Dec 07, 2026', '09:00 AM – 12:00 PM', 'EL 151', 'Applied Electricity & Circuit Fundamentals', 'Engineering Exam Hall', 'Dr. K. Mensah'],
        ['exam', '200', 'Dec 09, 2026', '02:00 PM – 05:00 PM', 'EL 251', 'Electromagnetic Field Theory', 'Engineering Exam Hall', 'Dr. E. Osei-Tutu'],
        ['exam', '400', 'Dec 10, 2026', '09:00 AM – 12:00 PM', 'EL 451', 'High Voltage Engineering & Substations', 'Main Auditorium Hall B', 'Prof. J. K. Gyimah']
      ];
      for (const s of seedSlots) {
        await pool.query(
          `INSERT INTO public.eleesa_timetables
           (entry_type, level, day_or_date, time_slot, course_code, course_title, venue, lecturer_or_invigilator)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
          s
        );
      }
      const afterT = await pool.query('SELECT COUNT(*)::int AS cnt FROM public.eleesa_timetables');
      cnt = afterT.rows[0]?.cnt ?? 0;
    }
    diagnostics.timetableCount = cnt;
  } catch (e) {
    diagnostics.timetableError = e.message;
  }

  try {
    const calRes = await pool.query('SELECT COUNT(*)::int AS cnt FROM public.academic_calendar');
    let cnt = calRes.rows[0]?.cnt ?? 0;
    if (cnt === 0) {
      const seedEvents = [
        ['Course Registration & Add/Drop Window Closes', 'Deadline', 'Nov 28, 2026', 'ALL', 'Final deadline for confirming Semester 1 courses on the student portal.'],
        ['Mid-Semester Practical & Lab Assessment Week', 'Academic', 'Dec 01 – Dec 04, 2026', 'ALL', 'Mandatory laboratory practical evaluations across Machines, Power, and Electronics labs.'],
        ['End-of-Semester Written Examinations', 'Exams', 'Dec 07 – Dec 18, 2026', 'ALL', 'University-wide end-of-semester examinations. Bring student ID and approved non-programmable calculators.'],
        ['Final-Year Project Topic Defense', 'Deadline', 'Dec 15, 2026', '400', 'Level 400 students present project problem statements and block diagrams to faculty supervisors.'],
        ['Inter-Semester Break & Industrial Attachment Prep', 'Holiday', 'Dec 21, 2026 – Jan 10, 2027', 'ALL', 'Semester break and industrial placement letter collection at the departmental office.']
      ];
      for (const ev of seedEvents) {
        await pool.query(
          `INSERT INTO public.academic_calendar (title, category, event_date, target_level, description)
           VALUES ($1,$2,$3,$4,$5)`,
          ev
        );
      }
      const afterC = await pool.query('SELECT COUNT(*)::int AS cnt FROM public.academic_calendar');
      cnt = afterC.rows[0]?.cnt ?? 0;
    }
    diagnostics.calendarCount = cnt;
  } catch (e) {
    diagnostics.calendarError = e.message;
  }

  return diagnostics;
}

app.get('/api/academic/overview', async (req, res) => {
  try {
    await pool.query(`
      ALTER TABLE public.department_info
        ADD COLUMN IF NOT EXISTS id INTEGER DEFAULT 1,
        ADD COLUMN IF NOT EXISTS department_name VARCHAR(200) DEFAULT 'Department of Electrical & Electronic Engineering',
        ADD COLUMN IF NOT EXISTS institution VARCHAR(200) DEFAULT 'University of Mines and Technology (UMaT)',
        ADD COLUMN IF NOT EXISTS location VARCHAR(250) DEFAULT 'Faculty of Engineering Block, UMaT Main Campus, Tarkwa',
        ADD COLUMN IF NOT EXISTS office_hours VARCHAR(150) DEFAULT 'Monday – Friday • 8:00 AM – 5:00 PM GMT',
        ADD COLUMN IF NOT EXISTS contact_email VARCHAR(150) DEFAULT 'eee.dept@umat.edu.gh',
        ADD COLUMN IF NOT EXISTS contact_phone VARCHAR(80) DEFAULT '+233 (0) 312 320 324',
        ADD COLUMN IF NOT EXISTS history TEXT DEFAULT '',
        ADD COLUMN IF NOT EXISTS vision TEXT DEFAULT '',
        ADD COLUMN IF NOT EXISTS mission TEXT DEFAULT '',
        ADD COLUMN IF NOT EXISTS hod_message TEXT DEFAULT '',
        ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW()
    `);
    await pool.query(`UPDATE public.department_info SET id = 1 WHERE id IS NULL`);
  } catch (e) {
    console.error('department_info migration warning:', e.message);
  }
  await ensureWave2Ready();
  await seedWave2DefaultsIfEmpty();
  const level = String(req.query.level || '100').trim();
  try {
    
  await seedWave2DefaultsIfEmpty();
  const seedDiagnostics = await ensureTimetableAndCalendarSeeded();
  const [deptRes, ttRes, calRes, courseRes] = await Promise.all([
      pool.query('SELECT * FROM public.department_info ORDER BY id ASC NULLS LAST LIMIT 1'),
      pool.query(
        `SELECT * FROM public.eleesa_timetables
         WHERE entry_type = 'lecture' AND (level = $1 OR $1 = 'ALL')
         ORDER BY entry_id ASC LIMIT 6`,
        [level]
      ),
      pool.query(
        `SELECT * FROM public.academic_calendar
         WHERE target_level = 'ALL' OR target_level = $1
         ORDER BY event_id ASC LIMIT 5`,
        [level]
      ),
      pool.query('SELECT COUNT(*)::int AS total FROM public.eleesa_courses'),
    ]);

    res.json({
      department: (deptRes.rows[0] && deptRes.rows[0].department_name) ? deptRes.rows[0] : {
        department_name: 'Department of Electrical & Electronic Engineering',
        institution: 'University of Mines and Technology (UMaT)',
        location: 'Faculty of Engineering Block, UMaT Main Campus, Tarkwa',
        office_hours: 'Monday – Friday • 8:00 AM – 5:00 PM GMT',
        contact_email: 'eee.dept@umat.edu.gh',
        contact_phone: '+233 (0) 312 320 324',
        history: 'Established to train world-class electrical and electronic engineers for Ghana’s power, mining, telecommunications, and industrial automation sectors, the department combines analytical theory with hands-on laboratory and substation training.',
        vision: 'To be a premier centre of excellence in Electrical and Electronic Engineering education, sustainable energy systems, and applied technological innovation across Africa.',
        mission: 'To produce ethically grounded, industry-ready engineers equipped with strong problem-solving, research, and leadership capabilities through modern laboratories and industry partnerships.',
        hod_message: 'Welcome to the ELEESA Digital Grid. Whether you are a student, lecturer, or visitor, this hub connects our lecture halls, laboratories, and research groups into one unified engineering workspace.'
      },
      schedule: ttRes.rows,
      calendar: calRes.rows,
      seedDiagnostics,
      course_count: courseRes.rows[0]?.total || 0,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST /api/academic/department-info (Item #2: HoD Edit About Department)
app.post('/api/academic/department-info', async (req, res) => {
  await ensureWave2Ready();
  const {
    requester_email,
    department_name,
    institution,
    location,
    office_hours,
    contact_email,
    contact_phone,
    history,
    vision,
    mission,
    hod_message,
  } = req.body;

  try {
    const userCheck = await pool.query(
      'SELECT role FROM public.users WHERE LOWER(email) = $1',
      [String(requester_email || '').trim().toLowerCase()]
    );
    if (userCheck.rows.length === 0 || userCheck.rows[0].role !== 'hod_admin') {
      return res.status(403).json({ message: 'Only the HoD/Admin can edit department information.' });
    }

    await pool.query(
      `UPDATE public.department_info
       SET department_name = COALESCE(NULLIF($1,''), department_name),
           institution = COALESCE(NULLIF($2,''), institution),
           location = COALESCE(NULLIF($3,''), location),
           office_hours = COALESCE(NULLIF($4,''), office_hours),
           contact_email = COALESCE(NULLIF($5,''), contact_email),
           contact_phone = COALESCE(NULLIF($6,''), contact_phone),
           history = COALESCE(NULLIF($7,''), history),
           vision = COALESCE(NULLIF($8,''), vision),
           mission = COALESCE(NULLIF($9,''), mission),
           hod_message = COALESCE(NULLIF($10,''), hod_message),
           updated_at = NOW()
       WHERE id = 1 OR id IS NULL`,
      [
        department_name || '',
        institution || '',
        location || '',
        office_hours || '',
        contact_email || '',
        contact_phone || '',
        history || '',
        vision || '',
        mission || '',
        hod_message || '',
      ]
    );

    res.json({ message: 'Department profile updated across all portals.' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// GET /api/academic/courses & POST /api/academic/courses (Item #4)
async function seedWave2DefaultsIfEmpty() {
  try {
    await pool.query(`
      DO $$
      DECLARE col RECORD;
      BEGIN
        FOR col IN
          SELECT table_name, column_name
          FROM information_schema.columns
          WHERE table_schema = 'public'
            AND table_name IN ('department_info', 'eleesa_timetables', 'academic_calendar')
            AND is_nullable = 'NO'
            AND column_default IS NULL
        LOOP
          EXECUTE format('ALTER TABLE public.%I ALTER COLUMN %I DROP NOT NULL', col.table_name, col.column_name);
        END LOOP;
      END $$;
    `);
  } catch (schemaRelaxErr) {
    console.error('Wave 2 schema relax warning:', schemaRelaxErr.message);
  }

  try {
    const deptRes = await pool.query('SELECT COUNT(*)::int AS cnt FROM public.department_info');
    if ((deptRes.rows[0]?.cnt ?? 0) === 0) {
      await pool.query(
        `INSERT INTO public.department_info
         (id, department_name, institution, location, office_hours, contact_email, contact_phone, history, vision, mission, hod_message)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [
          1,
          'Department of Electrical & Electronic Engineering',
          'University of Mines and Technology (UMaT)',
          'Faculty of Engineering Block, UMaT Main Campus, Tarkwa',
          'Monday – Friday • 8:00 AM – 5:00 PM GMT',
          'eee.dept@umat.edu.gh',
          '+233 (0) 312 320 324',
          'Established to train world-class electrical and electronic engineers for Ghana’s power, mining, telecommunications, and industrial automation sectors, the department combines analytical theory with hands-on laboratory and substation training.',
          'To be a premier centre of excellence in Electrical and Electronic Engineering education, sustainable energy systems, and applied technological innovation across Africa.',
          'To produce ethically grounded, industry-ready engineers equipped with strong problem-solving, research, and leadership capabilities through modern laboratories and industry partnerships.',
          'Welcome to the ELEESA Digital Grid. Whether you are a student, lecturer, or visitor, this hub connects our lecture halls, laboratories, and research groups into one unified engineering workspace.'
        ]
      );
    }
  } catch (deptErr) {
    console.error('seed department_info warning:', deptErr.message);
  }

  try {
    const tRes = await pool.query('SELECT COUNT(*)::int AS cnt FROM public.eleesa_timetables');
    if ((tRes.rows[0]?.cnt ?? 0) === 0) {
      const seedSlots = [
        ['lecture', '100', 'Monday', '08:00 AM – 10:00 AM', 'EL 151', 'Applied Electricity & Circuit Fundamentals', 'LT 1 (Main Block)', 'Dr. K. Mensah'],
        ['lecture', '200', 'Monday', '10:30 AM – 12:30 PM', 'EL 251', 'Electromagnetic Field Theory', 'LT 2 (Eng. Block)', 'Dr. E. Osei-Tutu'],
        ['lecture', '300', 'Monday', '08:00 AM – 10:00 AM', 'EL 351', 'Control Systems Engineering', 'EEE Lecture Room 3', 'Dr. M. Asante'],
        ['lecture', '300', 'Wednesday', '01:30 PM – 03:30 PM', 'EL 353', 'Power Systems Analysis & Protection', 'Power Lab Seminar Room', 'Prof. J. K. Gyimah'],
        ['lecture', '400', 'Tuesday', '09:00 AM – 11:00 AM', 'EL 451', 'High Voltage Engineering & Substations', 'High Voltage Wing', 'Prof. J. K. Gyimah'],
        ['exam', '300', 'Dec 08, 2026', '09:00 AM – 12:00 PM', 'EL 351', 'Control Systems Engineering', 'Main Auditorium Hall A', 'Dr. M. Asante'],
        ['exam', '300', 'Dec 11, 2026', '09:00 AM – 12:00 PM', 'EL 353', 'Power Systems Analysis & Protection', 'Main Auditorium Hall A', 'Prof. J. K. Gyimah'],
        ['exam', '100', 'Dec 07, 2026', '09:00 AM – 12:00 PM', 'EL 151', 'Applied Electricity & Circuit Fundamentals', 'Engineering Exam Hall', 'Dr. K. Mensah'],
        ['exam', '200', 'Dec 09, 2026', '02:00 PM – 05:00 PM', 'EL 251', 'Electromagnetic Field Theory', 'Engineering Exam Hall', 'Dr. E. Osei-Tutu'],
        ['exam', '400', 'Dec 10, 2026', '09:00 AM – 12:00 PM', 'EL 451', 'High Voltage Engineering & Substations', 'Main Auditorium Hall B', 'Prof. J. K. Gyimah']
      ];
      for (const s of seedSlots) {
        await pool.query(
          `INSERT INTO public.eleesa_timetables
           (entry_type, level, day_or_date, time_slot, course_code, course_title, venue, lecturer_or_invigilator)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
          s
        );
      }
    }
  } catch (ttErr) {
    console.error('seed eleesa_timetables warning:', ttErr.message);
  }

  try {
    const calRes = await pool.query('SELECT COUNT(*)::int AS cnt FROM public.academic_calendar');
    if ((calRes.rows[0]?.cnt ?? 0) === 0) {
      const seedEvents = [
        ['Course Registration & Add/Drop Window Closes', 'Deadline', 'Nov 28, 2026', 'ALL', 'Final deadline for confirming Semester 1 courses on the student portal.'],
        ['Mid-Semester Practical & Lab Assessment Week', 'Academic', 'Dec 01 – Dec 04, 2026', 'ALL', 'Mandatory laboratory practical evaluations across Machines, Power, and Electronics labs.'],
        ['End-of-Semester Written Examinations', 'Exams', 'Dec 07 – Dec 18, 2026', 'ALL', 'University-wide end-of-semester examinations. Bring student ID and approved non-programmable calculators.'],
        ['Final-Year Project Topic Defense', 'Deadline', 'Dec 15, 2026', '400', 'Level 400 students present project problem statements and block diagrams to faculty supervisors.'],
        ['Inter-Semester Break & Industrial Attachment Prep', 'Holiday', 'Dec 21, 2026 – Jan 10, 2027', 'ALL', 'Semester break and industrial placement letter collection at the departmental office.']
      ];
      for (const ev of seedEvents) {
        await pool.query(
          `INSERT INTO public.academic_calendar (title, category, event_date, target_level, description)
           VALUES ($1,$2,$3,$4,$5)`,
          ev
        );
      }
    }
  } catch (calErr) {
    console.error('seed academic_calendar warning:', calErr.message);
  }
}
app.get('/api/academic/courses', async (req, res) => {
  await ensureWave2Ready();
  let seedDebug = null;
  try {
    let result = await pool.query(
      'SELECT * FROM public.eleesa_courses ORDER BY level ASC, semester ASC, course_code ASC'
    );

    if (result.rows.length === 0) {
      const fallbackCourses = [
        ['EL 151', 'Applied Electricity & Circuit Fundamentals', '100', '1', 3, 'None', 'DC/AC network theorems, mesh and nodal analysis, phasors, resonance, and single-phase power circuits.', 'Dr. K. Mensah', 'kmensah@umat.edu.gh'],
        ['EL 152', 'Basic Electronics & Semiconductor Devices', '100', '2', 3, 'EL 151', 'PN junction diodes, rectifiers, BJT and MOSFET biasing, small-signal amplifiers, and operational amplifier basics.', 'Ing. A. Boateng', 'aboateng@umat.edu.gh'],
        ['EL 251', 'Electromagnetic Field Theory', '200', '1', 3, 'EL 151', 'Vector calculus, electrostatics, magnetostatics, Faraday’s law, Maxwell’s equations, and transmission line fundamentals.', 'Dr. E. Osei-Tutu', 'eoseitutu@umat.edu.gh'],
        ['EL 254', 'Digital Logic & Microprocessor Systems', '200', '2', 3, 'EL 152', 'Boolean algebra, combinational and sequential logic design, VHDL basics, and 8-bit/32-bit microcontroller architecture.', 'Ing. S. Owusu', 'sowusu@umat.edu.gh'],
        ['EL 351', 'Control Systems Engineering', '300', '1', 3, 'EL 251', 'Transfer functions, state-space modeling, time-domain stability, Routh-Hurwitz criterion, root locus, and Bode/Nyquist frequency design.', 'Dr. M. Asante', 'masante@umat.edu.gh'],
        ['EL 353', 'Power Systems Analysis & Protection', '300', '1', 3, 'EL 251', 'Per-unit system, symmetrical components, load flow studies (Gauss-Seidel & Newton-Raphson), fault analysis, and relay coordination.', 'Prof. J. K. Gyimah', 'jkgyimah@umat.edu.gh'],
        ['EL 356', 'Power Electronics & Electric Drives', '300', '2', 3, 'EL 152, EL 353', 'Controlled rectifiers, DC-DC choppers, PWM inverters, and variable-speed induction/DC motor drives.', 'Ing. R. Darko', 'rdarko@umat.edu.gh'],
        ['EL 451', 'High Voltage Engineering & Substations', '400', '1', 3, 'EL 353', 'Dielectric breakdown mechanisms, surge arresters, insulation coordination, switchgear, and primary substation design.', 'Prof. J. K. Gyimah', 'jkgyimah@umat.edu.gh'],
        ['EL 454', 'Industrial Automation & SCADA Systems', '400', '2', 3, 'EL 351', 'PLC ladder logic programming, industrial fieldbuses, SCADA telemetry, and smart grid instrumentation.', 'Dr. M. Asante', 'masante@umat.edu.gh']
      ];

      for (const row of fallbackCourses) {
        await pool.query(
          `INSERT INTO public.eleesa_courses
           (course_code, course_title, level, semester, credit_hours, prerequisites, syllabus, lecturer_name, lecturer_email)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
           ON CONFLICT (course_code) DO NOTHING`,
          row
        );
      }

      result = await pool.query(
        'SELECT * FROM public.eleesa_courses ORDER BY level ASC, semester ASC, course_code ASC'
      );
      seedDebug = { insertedAttempted: fallbackCourses.length, returnedCount: result.rows.length };
    }

    res.json({ courses: result.rows, seedDebug });
  } catch (err) {
    res.status(500).json({ message: err.message, seedDebug });
  }
});

app.post('/api/academic/courses', async (req, res) => {
  await ensureWave2Ready();
  const {
    requester_email,
    course_code,
    course_title,
    level,
    semester,
    credit_hours,
    prerequisites,
    syllabus,
    lecturer_name,
    lecturer_email,
  } = req.body;

  try {
    const u = await pool.query(
      'SELECT role, full_name, email FROM public.users WHERE LOWER(email) = $1',
      [String(requester_email || '').trim().toLowerCase()]
    );
    if (u.rows.length === 0 || !['lecturer', 'hod_admin'].includes(u.rows[0].role)) {
      return res.status(403).json({ message: 'Only Lecturers and HoD can publish courses or syllabi.' });
    }

    const code = String(course_code || '').trim().toUpperCase();
    const title = String(course_title || '').trim();
    if (!code || !title) {
      return res.status(400).json({ message: 'Course code and title are required.' });
    }

    await pool.query(
      `INSERT INTO public.eleesa_courses
       (course_code, course_title, level, semester, credit_hours, prerequisites, syllabus, lecturer_name, lecturer_email, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())
       ON CONFLICT (course_code) DO UPDATE SET
         course_title = EXCLUDED.course_title,
         level = EXCLUDED.level,
         semester = EXCLUDED.semester,
         credit_hours = EXCLUDED.credit_hours,
         prerequisites = EXCLUDED.prerequisites,
         syllabus = EXCLUDED.syllabus,
         lecturer_name = EXCLUDED.lecturer_name,
         lecturer_email = EXCLUDED.lecturer_email,
         updated_at = NOW()`,
      [
        code,
        title,
        String(level || '100'),
        String(semester || '1'),
        parseInt(credit_hours, 10) || 3,
        String(prerequisites || 'None').trim(),
        String(syllabus || 'Course outline to be updated.').trim(),
        String(lecturer_name || u.rows[0].full_name).trim(),
        String(lecturer_email || u.rows[0].email).trim(),
      ]
    );

    res.json({ message: `Course ${code} saved to curriculum.` });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// GET & POST /api/academic/timetable & /api/academic/calendar (Item #5)
app.get('/api/academic/timetable', async (req, res) => {
  await ensureWave2Ready();
  await seedWave2DefaultsIfEmpty();
  await ensureWave2Ready();
  await seedWave2DefaultsIfEmpty();
  try {
    const [ttRes, calRes] = await Promise.all([
      pool.query('SELECT * FROM public.eleesa_timetables ORDER BY level ASC, entry_id ASC'),
      pool.query('SELECT * FROM public.academic_calendar ORDER BY event_id ASC'),
    ]);
    res.json({
      timetables: ttRes.rows,
      calendar: calRes.rows,
      seedDiagnostics,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/academic/timetable', async (req, res) => {
  await ensureWave2Ready();
  const {
    requester_email,
    entry_type,
    level,
    day_or_date,
    time_slot,
    course_code,
    course_title,
    venue,
    lecturer_or_invigilator,
  } = req.body;

  try {
    const u = await pool.query(
      'SELECT role, full_name FROM public.users WHERE LOWER(email) = $1',
      [String(requester_email || '').trim().toLowerCase()]
    );
    if (u.rows.length === 0 || !['lecturer', 'hod_admin'].includes(u.rows[0].role)) {
      return res.status(403).json({ message: 'Only Lecturers and HoD can publish timetable entries.' });
    }

    await pool.query(
      `INSERT INTO public.eleesa_timetables
       (entry_type, level, day_or_date, time_slot, course_code, course_title, venue, lecturer_or_invigilator)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        entry_type === 'exam' ? 'exam' : 'lecture',
        String(level || '100'),
        String(day_or_date || 'Monday').trim(),
        String(time_slot || '08:00 AM – 10:00 AM').trim(),
        String(course_code || '').trim().toUpperCase(),
        String(course_title || '').trim(),
        String(venue || 'Main Engineering Block').trim(),
        String(lecturer_or_invigilator || u.rows[0].full_name).trim(),
      ]
    );

    res.json({ message: 'Timetable slot published.' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/academic/calendar', async (req, res) => {
  await ensureWave2Ready();
  const { requester_email, title, category, event_date, target_level, description } = req.body;

  try {
    const u = await pool.query(
      'SELECT role FROM public.users WHERE LOWER(email) = $1',
      [String(requester_email || '').trim().toLowerCase()]
    );
    if (u.rows.length === 0 || u.rows[0].role !== 'hod_admin') {
      return res.status(403).json({ message: 'Only the HoD/Admin can publish academic calendar dates.' });
    }

    await pool.query(
      `INSERT INTO public.academic_calendar (title, category, event_date, target_level, description)
       VALUES ($1,$2,$3,$4,$5)`,
      [
        String(title || '').trim(),
        String(category || 'Academic').trim(),
        String(event_date || '').trim(),
        String(target_level || 'ALL').trim(),
        String(description || '').trim(),
      ]
    );

    res.json({ message: 'Academic calendar milestone published.' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST /api/academic/staff-update (Item #3: Lecturer/HoD Staff Card Editor)
app.post('/api/academic/staff-update', async (req, res) => {
  await ensureWave2Ready();
  const {
    requester_email,
    target_email,
    academic_title,
    specialization,
    office_location,
    office_hours,
    courses_taught,
    research_interests,
  } = req.body;

  try {
    const reqClean = String(requester_email || '').trim().toLowerCase();
    const targetClean = String(target_email || reqClean).trim().toLowerCase();

    const u = await pool.query('SELECT role FROM public.users WHERE LOWER(email) = $1', [reqClean]);
    if (u.rows.length === 0 || !['lecturer', 'hod_admin'].includes(u.rows[0].role)) {
      return res.status(403).json({ message: 'Unauthorized staff update.' });
    }
    if (u.rows[0].role !== 'hod_admin' && reqClean !== targetClean) {
      return res.status(403).json({ message: 'Lecturers can only edit their own faculty profile.' });
    }

    await pool.query(
      `UPDATE public.staff_profiles
       SET academic_title = COALESCE(NULLIF($1,''), academic_title),
           specialization = COALESCE(NULLIF($2,''), specialization),
           office_location = COALESCE(NULLIF($3,''), office_location),
           office_hours = COALESCE(NULLIF($4,''), office_hours),
           courses_taught = COALESCE(NULLIF($5,''), courses_taught),
           research_interests = COALESCE(NULLIF($6,''), research_interests)
       WHERE LOWER(email) = $7`,
      [
        academic_title || '',
        specialization || '',
        office_location || '',
        office_hours || '',
        courses_taught || '',
        research_interests || '',
        targetClean,
      ]
    );

    res.json({ message: 'Faculty directory profile updated.' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ==================== WAVE 3: RESOURCES, 5 LABS, PROJECTS & ATTACHMENT ====================
let _wave3ReadyPromise = null;
function ensureWave3Ready() {
  if (!_wave3ReadyPromise) {
    _wave3ReadyPromise = initAndSeedWave3().catch((err) => {
      _wave3ReadyPromise = null;
      console.error('Wave 3 init error:', err.message);
      throw err;
    });
  }
  return _wave3ReadyPromise;
}

async function initAndSeedWave3() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS public.eleesa_resources (
        resource_id SERIAL PRIMARY KEY,
        title VARCHAR(220) NOT NULL,
        course_code VARCHAR(30) NOT NULL,
        level VARCHAR(10) NOT NULL DEFAULT '300',
        category VARCHAR(50) NOT NULL DEFAULT 'Lecture Notes',
        file_url TEXT NOT NULL,
        description TEXT DEFAULT '',
        uploaded_by VARCHAR(150) NOT NULL,
        uploader_role VARCHAR(30) NOT NULL DEFAULT 'student',
        status VARCHAR(20) NOT NULL DEFAULT 'approved',
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS public.eleesa_lab_equipment (
        equipment_id SERIAL PRIMARY KEY,
        lab_name VARCHAR(120) NOT NULL,
        equipment_name VARCHAR(180) NOT NULL,
        model_code VARCHAR(80) DEFAULT '',
        quantity INTEGER NOT NULL DEFAULT 1,
        status VARCHAR(30) NOT NULL DEFAULT 'Available',
        specs TEXT DEFAULT '',
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS public.eleesa_lab_bookings (
        booking_id SERIAL PRIMARY KEY,
        lab_name VARCHAR(120) NOT NULL,
        equipment_name VARCHAR(180) DEFAULT 'General Bench',
        student_name VARCHAR(150) NOT NULL,
        student_email VARCHAR(150) NOT NULL,
        index_number VARCHAR(50) DEFAULT '',
        booking_date VARCHAR(40) NOT NULL,
        time_slot VARCHAR(60) NOT NULL,
        purpose TEXT NOT NULL,
        status VARCHAR(25) NOT NULL DEFAULT 'Pending',
        reviewed_by VARCHAR(150),
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS public.eleesa_projects (
        project_id SERIAL PRIMARY KEY,
        title VARCHAR(240) NOT NULL,
        category VARCHAR(80) NOT NULL DEFAULT 'Power & Smart Grid',
        academic_year VARCHAR(20) NOT NULL DEFAULT '2025/2026',
        student_names VARCHAR(220) NOT NULL,
        supervisor_name VARCHAR(150) NOT NULL,
        abstract TEXT NOT NULL,
        status VARCHAR(30) NOT NULL DEFAULT 'Approved',
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS public.eleesa_attachments (
        attachment_id SERIAL PRIMARY KEY,
        company_name VARCHAR(180) NOT NULL,
        sector VARCHAR(80) NOT NULL DEFAULT 'Power & Energy',
        location VARCHAR(120) NOT NULL,
        student_name VARCHAR(150),
        student_email VARCHAR(150),
        level VARCHAR(10) DEFAULT '300',
        role_title VARCHAR(150) DEFAULT 'Electrical Engineering Intern',
        duration VARCHAR(60) DEFAULT '8 Weeks',
        supervisor_contact VARCHAR(150) DEFAULT '',
        status VARCHAR(30) NOT NULL DEFAULT 'Open Slot',
        logbook_summary TEXT DEFAULT '',
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
  } catch (ddlErr) {
    console.error('Wave 3 DDL warning:', ddlErr.message);
  }

  try {
    const rCnt = await pool.query('SELECT COUNT(*)::int AS cnt FROM public.eleesa_resources');
    if ((rCnt.rows[0]?.cnt ?? 0) === 0) {
      const resources = [
        ['Control Systems Bode & Root Locus Design Handbook', 'EL 351', '300', 'Lecture Notes', 'https://umat.edu.gh/eee/resources/el351-control-handbook.pdf', 'Worked stability examples, Routh arrays, and frequency compensation plots.', 'Dr. M. Asante', 'lecturer', 'approved'],
        ['Power Systems Load Flow & Fault Analysis Past Questions (2022–2025)', 'EL 353', '300', 'Past Questions', 'https://umat.edu.gh/eee/resources/el353-past-questions.pdf', 'Compiled end-of-semester exam papers with per-unit fault calculation solutions.', 'Prof. J. K. Gyimah', 'lecturer', 'approved'],
        ['PWM Inverter & Three-Phase Drive Lab Manual', 'EL 356', '300', 'Lab Manual', 'https://umat.edu.gh/eee/resources/el356-drive-lab.pdf', 'Safety checklist, oscilloscope probe setup, and duty-cycle measurement tables.', 'Ing. R. Darko', 'lecturer', 'approved'],
        ['Applied Electricity Mesh & Nodal Solved Problem Bank', 'EL 151', '100', 'Tutorial Sheet', 'https://umat.edu.gh/eee/resources/el151-tutorials.pdf', 'Step-by-step DC/AC circuit theorems and phasor diagrams for Level 100.', 'Dr. K. Mensah', 'lecturer', 'approved'],
        ['VHDL & Microcontroller Interfacing Reference Guide', 'EL 254', '200', 'Lecture Notes', 'https://umat.edu.gh/eee/resources/el254-microcontrollers.pdf', 'Timer interrupts, ADC register mapping, and combinational logic synthesis.', 'Ing. S. Owusu', 'lecturer', 'approved'],
        ['High Voltage Substation Insulation & Switchgear Notes', 'EL 451', '400', 'Lecture Notes', 'https://umat.edu.gh/eee/resources/el451-hv-substations.pdf', 'Surge arresters, SF6 circuit breakers, and primary substation busbar layouts.', 'Prof. J. K. Gyimah', 'lecturer', 'approved']
      ];
      for (const r of resources) {
        await pool.query(
          `INSERT INTO public.eleesa_resources
           (title, course_code, level, category, file_url, description, uploaded_by, uploader_role, status)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
          r
        );
      }
    }
  } catch (e) {
    console.error('Wave 3 resource seed warning:', e.message);
  }

  try {
    const eCnt = await pool.query('SELECT COUNT(*)::int AS cnt FROM public.eleesa_lab_equipment');
    if ((eCnt.rows[0]?.cnt ?? 0) === 0) {
      const equipment = [
        ['Power Systems & High Voltage Lab', 'Three-Phase Protective Relay & Transformer Test Bench', 'HV-REL-300', 4, 'Available', 'Overcurrent, differential, and distance relay coordination trainer with fault simulator.'],
        ['Power Systems & High Voltage Lab', '100kV AC/DC Dielectric Breakdown Test Kit', 'HV-DIE-100', 2, 'Supervised Only', 'High-voltage oil and solid insulation breakdown tester with safety interlock cage.'],
        ['Electrical Machines & Drives Lab', '1.5kW Three-Phase Induction & Synchronous Machine Set', 'EM-SYN-150', 6, 'Available', 'Coupled prime mover, torque transducer, and synchronizing panel for load tests.'],
        ['Electrical Machines & Drives Lab', 'Industrial Variable Frequency Drive (VFD) Trainer', 'EM-VFD-220', 4, 'Available', 'IGBT PWM inverter rack with regenerative braking and harmonic analyzer.'],
        ['Analog & Digital Electronics Lab', '100MHz 4-Channel Digital Storage Oscilloscope', 'EL-DSO-104', 12, 'Available', '1 GSa/s mixed-signal oscilloscope with FFT spectrum and arbitrary function generator.'],
        ['Analog & Digital Electronics Lab', 'FPGA & ARM Cortex-M4 Embedded Dev Station', 'EL-EMB-402', 10, 'Available', 'Xilinx Artix-7 FPGA & STM32 boards with logic analyzer probes.'],
        ['Control Systems & Instrumentation Lab', 'PID Servo Motor & Coupled Tank Process Rig', 'CS-PID-501', 5, 'Available', 'Real-time MATLAB/Simulink hardware-in-the-loop position and level control trainer.'],
        ['Control Systems & Instrumentation Lab', 'Siemens S7-1200 PLC & SCADA Automation Rack', 'CS-PLC-120', 4, 'In Use', 'Industrial ladder logic controller with HMI touchscreen and pneumatic actuators.'],
        ['Telecommunications & Microwave Lab', '3GHz RF Spectrum Analyzer & Vector Signal Generator', 'TC-RFS-300', 3, 'Available', 'AM/FM/QAM modulation analyzer and antenna radiation pattern test bench.'],
        ['Telecommunications & Microwave Lab', 'Optical Fiber & Software-Defined Radio (SDR) Kit', 'TC-SDR-210', 5, 'Available', 'Single-mode fiber attenuation bench and USRP SDR transceiver modules.']
      ];
      for (const eq of equipment) {
        await pool.query(
          `INSERT INTO public.eleesa_lab_equipment
           (lab_name, equipment_name, model_code, quantity, status, specs)
           VALUES ($1,$2,$3,$4,$5,$6)`,
          eq
        );
      }
    }
  } catch (e) {
    console.error('Wave 3 lab seed warning:', e.message);
  }

  try {
    const pCnt = await pool.query('SELECT COUNT(*)::int AS cnt FROM public.eleesa_projects');
    if ((pCnt.rows[0]?.cnt ?? 0) === 0) {
      const projects = [
        ['IoT-Enabled 11kV Distribution Feeder Fault Locator with GSM/LoRa Telemetry', 'Power & Smart Grid', '2025/2026', 'Kwame Mensah & Abena Osei', 'Prof. J. K. Gyimah', 'Designs a low-cost current-transformer sensor node that detects line-to-ground faults and transmits GPS pole coordinates to substation operators within 4 seconds.', 'Approved'],
        ['Solar-PV & Battery Hybrid Microgrid Energy Management System for Mining Host Communities', 'Renewable Energy', '2025/2026', 'Daniel Boateng & Efua Arthur', 'Dr. M. Asante', 'Implements fuzzy-logic load shedding and MPPT charge control to maintain uninterrupted power for clinics and schools during grid outages.', 'Approved'],
        ['PLC & SCADA Automated Conveyor Belt Slip and Over-Temperature Protection for Underground Mines', 'Industrial Automation', '2025/2026', 'Josephine Kyei & Samuel Tetteh', 'Ing. R. Darko', 'Integrates infrared thermal sensors, rotary encoders, and Siemens PLC interlocks to prevent conveyor fires in harsh mining environments.', 'Approved'],
        ['Smart Prepaid Energy Meter with Non-Intrusive Appliance Load Monitoring (NILM)', 'Embedded & IoT', '2024/2025', 'Emmanuel Quansah', 'Ing. S. Owusu', 'Uses harmonic current signatures on an ESP32-S3 microcontroller to disaggregate household appliance consumption and detect meter bypass.', 'Completed'],
        ['Condition Monitoring of Three-Phase Induction Motors via Vibration & Stator Current FFT', 'Electrical Machines', '2024/2025', 'Priscilla Donkor & Kelvin Appiah', 'Dr. K. Mensah', 'Detects early-stage rotor bar and bearing degradation using spectral sideband analysis.', 'Completed']
      ];
      for (const pr of projects) {
        await pool.query(
          `INSERT INTO public.eleesa_projects
           (title, category, academic_year, student_names, supervisor_name, abstract, status)
           VALUES ($1,$2,$3,$4,$5,$6,$7)`,
          pr
        );
      }
    }
  } catch (e) {
    console.error('Wave 3 projects seed warning:', e.message);
  }

  try {
    const aCnt = await pool.query('SELECT COUNT(*)::int AS cnt FROM public.eleesa_attachments');
    if ((aCnt.rows[0]?.cnt ?? 0) === 0) {
      const attachments = [
        ['Electricity Company of Ghana (ECG) – Sekondi-Takoradi', 'Power Distribution', 'Takoradi, Western Region', null, null, '300', 'Substation & Protection Intern', '8 Weeks', 'regional.eng@ecg.com.gh', 'Open Slot', 'Rotation across 33/11kV primary substations, switchgear maintenance, and feeder load balancing.'],
        ['Ghana Grid Company (GRIDCo) – Tarkwa Area', 'Power Transmission', 'Tarkwa, Western Region', null, null, '300', 'Transmission & SCADA Intern', '8 Weeks', 'tarkwa.ops@gridcogh.com', 'Open Slot', '161kV substation operations, protection relay testing, and grid telemetry monitoring.'],
        ['Volta River Authority (VRA) – Aboadze Thermal Complex', 'Power Generation', 'Aboadze, Western Region', null, null, '300', 'Electrical Maintenance Intern', '8 Weeks', 'hr.aboadze@vra.com', 'Open Slot', 'Combined-cycle gas turbine generator excitation, transformer oil testing, and plant instrumentation.'],
        ['Gold Fields Ghana Ltd – Tarkwa Mine', 'Mining & Automation', 'Tarkwa, Western Region', null, null, '300', 'Plant Electrical & PLC Intern', '8 Weeks', 'training.tarkwa@goldfields.com', 'Open Slot', 'High-voltage mill drives, PLC/SCADA process control, and underground power distribution.'],
        ['MTN Ghana – Western Technical Operations', 'Telecommunications', 'Takoradi, Western Region', null, null, '300', 'RF & Core Network Intern', '8 Weeks', 'tech.interns@mtn.com.gh', 'Open Slot', 'Base transceiver station power systems, fiber-optic transmission, and network optimization.']
      ];
      for (const at of attachments) {
        await pool.query(
          `INSERT INTO public.eleesa_attachments
           (company_name, sector, location, student_name, student_email, level, role_title, duration, supervisor_contact, status, logbook_summary)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
          at
        );
      }
    }
  } catch (e) {
    console.error('Wave 3 attachment seed warning:', e.message);
  }
}

app.get('/api/wave3/resources', async (req, res) => {
  await ensureWave3Ready();
  const level = String(req.query.level || '').trim();
  const includePending = req.query.includePending === 'true';
  try {
    const clauses = [];
    const params = [];
    if (!includePending) { clauses.push(`status = 'approved'`); }
    if (level && level !== 'ALL') {
      params.push(level);
      clauses.push(`level = $${params.length}`);
    }
    const whereSql = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
    const result = await pool.query(`SELECT * FROM public.eleesa_resources ${whereSql} ORDER BY resource_id DESC`, params);
    res.json({ resources: result.rows });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/wave3/resources', async (req, res) => {
  await ensureWave3Ready();
  const { title, course_code, level, category, file_url, description, uploaded_by, uploader_role } = req.body || {};
  if (!title || !course_code || !uploaded_by) {
    return res.status(400).json({ message: 'title, course_code, and uploaded_by are required.' });
  }
  const role = String(uploader_role || 'student').toLowerCase();
  const status = (role === 'lecturer' || role === 'hod' || role === 'admin') ? 'approved' : 'pending';
  try {
    const result = await pool.query(
      `INSERT INTO public.eleesa_resources
       (title, course_code, level, category, file_url, description, uploaded_by, uploader_role, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [
        title.trim(),
        course_code.trim().toUpperCase(),
        String(level || '300').trim(),
        String(category || 'Lecture Notes').trim(),
        String(file_url || 'https://umat.edu.gh/eee/resources/submission').trim(),
        String(description || '').trim(),
        uploaded_by.trim(),
        role,
        status
      ]
    );
    res.status(201).json({ resource: result.rows[0] });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.patch('/api/wave3/resources/:id/status', async (req, res) => {
  await ensureWave3Ready();
  const id = parseInt(req.params.id, 10);
  const status = String(req.body?.status || 'approved').trim();
  try {
    const result = await pool.query(
      'UPDATE public.eleesa_resources SET status = $1 WHERE resource_id = $2 RETURNING *',
      [status, id]
    );
    res.json({ resource: result.rows[0] || null });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/wave3/labs', async (req, res) => {
  await ensureWave3Ready();
  try {
    const [eqRes, bkRes] = await Promise.all([
      pool.query('SELECT * FROM public.eleesa_lab_equipment ORDER BY lab_name ASC, equipment_id ASC'),
      pool.query('SELECT * FROM public.eleesa_lab_bookings ORDER BY booking_id DESC LIMIT 50')
    ]);
    res.json({ equipment: eqRes.rows, bookings: bkRes.rows });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/wave3/labs/book', async (req, res) => {
  await ensureWave3Ready();
  const { lab_name, equipment_name, student_name, student_email, index_number, booking_date, time_slot, purpose } = req.body || {};
  if (!lab_name || !student_name || !booking_date || !time_slot || !purpose) {
    return res.status(400).json({ message: 'lab_name, student_name, booking_date, time_slot, and purpose are required.' });
  }
  try {
    const result = await pool.query(
      `INSERT INTO public.eleesa_lab_bookings
       (lab_name, equipment_name, student_name, student_email, index_number, booking_date, time_slot, purpose, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'Pending') RETURNING *`,
      [
        lab_name.trim(),
        String(equipment_name || 'General Lab Bench').trim(),
        student_name.trim(),
        String(student_email || '').trim(),
        String(index_number || '').trim(),
        booking_date.trim(),
        time_slot.trim(),
        purpose.trim()
      ]
    );
    res.status(201).json({ booking: result.rows[0] });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.patch('/api/wave3/labs/bookings/:id', async (req, res) => {
  await ensureWave3Ready();
  const id = parseInt(req.params.id, 10);
  const { status, reviewed_by } = req.body || {};
  try {
    const result = await pool.query(
      'UPDATE public.eleesa_lab_bookings SET status = $1, reviewed_by = $2 WHERE booking_id = $3 RETURNING *',
      [String(status || 'Approved').trim(), String(reviewed_by || 'Faculty Lab Coordinator').trim(), id]
    );
    res.json({ booking: result.rows[0] || null });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/wave3/projects', async (req, res) => {
  await ensureWave3Ready();
  try {
    const result = await pool.query('SELECT * FROM public.eleesa_projects ORDER BY project_id DESC');
    res.json({ projects: result.rows });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/wave3/projects', async (req, res) => {
  await ensureWave3Ready();
  const { title, category, academic_year, student_names, supervisor_name, abstract } = req.body || {};
  if (!title || !student_names || !supervisor_name || !abstract) {
    return res.status(400).json({ message: 'title, student_names, supervisor_name, and abstract are required.' });
  }
  try {
    const result = await pool.query(
      `INSERT INTO public.eleesa_projects
       (title, category, academic_year, student_names, supervisor_name, abstract, status)
       VALUES ($1,$2,$3,$4,$5,$6,'Proposed') RETURNING *`,
      [
        title.trim(),
        String(category || 'Power & Smart Grid').trim(),
        String(academic_year || '2026/2027').trim(),
        student_names.trim(),
        supervisor_name.trim(),
        abstract.trim()
      ]
    );
    res.status(201).json({ project: result.rows[0] });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/wave3/attachments', async (req, res) => {
  await ensureWave3Ready();
  try {
    const result = await pool.query('SELECT * FROM public.eleesa_attachments ORDER BY attachment_id DESC');
    res.json({ attachments: result.rows });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/wave3/attachments', async (req, res) => {
  await ensureWave3Ready();
  const { company_name, sector, location, student_name, student_email, level, role_title, duration, supervisor_contact, logbook_summary } = req.body || {};
  if (!company_name || !location || !student_name) {
    return res.status(400).json({ message: 'company_name, location, and student_name are required.' });
  }
  try {
    const result = await pool.query(
      `INSERT INTO public.eleesa_attachments
       (company_name, sector, location, student_name, student_email, level, role_title, duration, supervisor_contact, status, logbook_summary)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'Active Placement',$10) RETURNING *`,
      [
        company_name.trim(),
        String(sector || 'Power & Energy').trim(),
        location.trim(),
        student_name.trim(),
        String(student_email || '').trim(),
        String(level || '300').trim(),
        String(role_title || 'Electrical Engineering Intern').trim(),
        String(duration || '8 Weeks').trim(),
        String(supervisor_contact || '').trim(),
        String(logbook_summary || '').trim()
      ]
    );
    res.status(201).json({ attachment: result.rows[0] });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
// ==================== END WAVE 3 ====================


// ==================== WAVE 4: NOTICES/EVENTS, KNOW YOUR PEOPLE & JIJI STORE ====================
let _wave4ReadyPromise = null;
function ensureWave4Ready() {
  if (!_wave4ReadyPromise) {
    _wave4ReadyPromise = initAndSeedWave4().catch((err) => {
      _wave4ReadyPromise = null;
      console.error('Wave 4 init error:', err.message);
      throw err;
    });
  }
  return _wave4ReadyPromise;
}

async function initAndSeedWave4() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS public.eleesa_notices (
        notice_id SERIAL PRIMARY KEY,
        title VARCHAR(220) NOT NULL,
        category VARCHAR(60) NOT NULL DEFAULT 'Department Notice',
        event_date VARCHAR(60) DEFAULT '',
        venue VARCHAR(140) DEFAULT 'Faculty of Engineering Auditorium',
        body TEXT NOT NULL,
        posted_by VARCHAR(150) NOT NULL,
        poster_role VARCHAR(40) DEFAULT 'executive',
        rsvp_count INTEGER NOT NULL DEFAULT 0,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS public.eleesa_store_items (
        item_id SERIAL PRIMARY KEY,
        title VARCHAR(200) NOT NULL,
        category VARCHAR(60) NOT NULL DEFAULT 'Lab & Circuit Kits',
        price_ghs NUMERIC(10,2) NOT NULL DEFAULT 0,
        condition VARCHAR(40) NOT NULL DEFAULT 'Neatly Used',
        location VARCHAR(120) NOT NULL DEFAULT 'Tarkwa Campus',
        description TEXT NOT NULL,
        seller_name VARCHAR(150) NOT NULL,
        seller_contact VARCHAR(80) NOT NULL,
        seller_level VARCHAR(20) DEFAULT '300',
        status VARCHAR(30) NOT NULL DEFAULT 'Available',
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS public.eleesa_directory_people (
        person_id SERIAL PRIMARY KEY,
        full_name VARCHAR(160) NOT NULL,
        role_group VARCHAR(50) NOT NULL DEFAULT 'Student',
        title_or_level VARCHAR(100) NOT NULL DEFAULT 'Level 300',
        specialty_or_portfolio VARCHAR(160) DEFAULT 'Electrical & Electronic Engineering',
        email VARCHAR(160) DEFAULT '',
        phone VARCHAR(60) DEFAULT '',
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
  } catch (ddlErr) {
    console.error('Wave 4 DDL warning:', ddlErr.message);
  }

  try {
    const nCnt = await pool.query('SELECT COUNT(*)::int AS cnt FROM public.eleesa_notices');
    if ((nCnt.rows[0]?.cnt ?? 0) === 0) {
      const notices = [
        ['IEEE UMaT Student Branch & GhIE Technical Seminar: Smart Grid Protection', 'IEEE / GhIE Event', 'Nov 29, 2026 • 10:00 AM', 'Engineering Auditorium, UMaT Tarkwa', 'Hands-on workshop covering 11kV/33kV feeder protection relays, SCADA telemetry, and student membership induction.', 'ELEESA Executive Council', 'executive', 34],
        ['Mandatory Level 300 & 400 Laboratory Safety & High-Voltage Briefing', 'Department Notice', 'Nov 26, 2026 • 02:00 PM', 'Power Systems & High Voltage Lab', 'All students booked for power and machines lab sessions must complete PPE inspection and interlock safety sign-off.', 'Prof. J. K. Gyimah', 'hod', 58],
        ['ELEESA Hackathon & Embedded Systems Design Challenge 2026', 'Competition', 'Dec 05, 2026 • 09:00 AM', 'Analog & Digital Electronics Lab', 'Form teams of 3 to build ESP32/STM32 industrial monitoring prototypes. Top 3 teams receive lab component grants.', 'Ing. R. Darko', 'lecturer', 41],
        ['Semester 1 Examination Clearance & Course Registration Reminder', 'Academic Alert', 'Nov 28, 2026 • 05:00 PM', 'Departmental Noticeboard / Portal', 'Verify all registered Level 100–400 courses before the add/drop portal closes.', 'Dr. M. Asante', 'lecturer', 76]
      ];
      for (const n of notices) {
        await pool.query(
          `INSERT INTO public.eleesa_notices (title, category, event_date, venue, body, posted_by, poster_role, rsvp_count)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
          n
        );
      }
    }
  } catch (e) {
    console.error('Wave 4 notice seed warning:', e.message);
  }

  try {
    const sCnt = await pool.query('SELECT COUNT(*)::int AS cnt FROM public.eleesa_store_items');
    if ((sCnt.rows[0]?.cnt ?? 0) === 0) {
      const items = [
        ['Casio fx-991EX ClassWiz Scientific Calculator (Original)', 'Calculators', 240.00, 'Brand New', 'Chamber of Mines Hall, Tarkwa', 'Complex matrix, vector, and base-n solver approved for all UMaT EEE examinations.', 'Kwame Mensah', '0244 812 390', '300', 'Available'],
        ['ESP32-S3 + Arduino Mega + 37-Sensor IoT Project Kit', 'Lab & Circuit Kits', 380.00, 'Neatly Used', 'Gold Refinery Hall, Tarkwa', 'Includes breadboard, jumper wires, ultrasonic, current sensor (ACS712), relay module, and OLED screen.', 'Daniel Boateng', '0553 419 208', '400', 'Available'],
        ['White Engineering Lab Coat + Insulated Safety Gloves', 'Safety & Apparel', 150.00, 'Brand New', 'KT Hall / Main Campus', 'Heavy-duty cotton laboratory coat (Size L) with IEC-rated electrical bench gloves.', 'Abena Osei', '0208 664 112', '200', 'Available'],
        ['Sadiku Fundamentals of Electric Circuits (6th Ed. Hardcopy)', 'Textbooks', 190.00, 'Neatly Used', 'New Site, Tarkwa', 'Clean copy with solved past tutorial sheets for EL 151 and EL 251.', 'Emmanuel Quansah', '0277 903 541', '300', 'Available'],
        ['PCB Etching, Soldering & Proteus Simulation Tutoring', 'Student Services', 60.00, 'Service', 'Electronics Lab Wing', 'One-on-one help with schematic capture, PCB layout, and microcontroller firmware debugging.', 'Priscilla Donkor', '0541 229 874', '400', 'Available']
      ];
      for (const it of items) {
        await pool.query(
          `INSERT INTO public.eleesa_store_items
           (title, category, price_ghs, condition, location, description, seller_name, seller_contact, seller_level, status)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
          it
        );
      }
    }
  } catch (e) {
    console.error('Wave 4 store seed warning:', e.message);
  }

  try {
    const pCnt = await pool.query('SELECT COUNT(*)::int AS cnt FROM public.eleesa_directory_people');
    if ((pCnt.rows[0]?.cnt ?? 0) === 0) {
      const people = [
        ['Prof. J. K. Gyimah', 'Lecturer', 'Head of Department (HoD)', 'High Voltage Engineering & Power Systems Protection', 'jgyimah@umat.edu.gh', '+233 312 320 324'],
        ['Dr. M. Asante', 'Lecturer', 'Senior Lecturer', 'Control Systems & Industrial Instrumentation', 'masante@umat.edu.gh', '+233 244 510 112'],
        ['Ing. R. Darko', 'Lecturer', 'Lecturer & Lab Coordinator', 'Power Electronics, Drives & PLC Automation', 'rdarko@umat.edu.gh', '+233 208 771 904'],
        ['Dr. K. Mensah', 'Lecturer', 'Lecturer', 'Applied Electricity & Machine Condition Monitoring', 'kmensah@umat.edu.gh', '+233 554 309 821'],
        ['Maxwell Amoah', 'Student', 'Level 300', 'Power Systems, Embedded IoT & Full-Stack Engineering', 'maxwell.amoah@st.umat.edu.gh', '+233 540 000 300'],
        ['Kwame Mensah', 'Executive', 'ELEESA President (Level 400)', 'Smart Grid & Renewable Microgrids', 'president@eleesa-umat.org', '+233 244 812 390'],
        ['Abena Osei', 'Executive', 'ELEESA General Secretary (Level 300)', 'Telecommunications & RF Systems', 'secretary@eleesa-umat.org', '+233 208 664 112'],
        ['Ing. Samuel Owusu-Ansah', 'Alumni', 'Class of 2022 • GRIDCo Protection Engineer', '161kV/330kV Substation Protection & SCADA', 's.owusu@gridcogh.com', '+233 243 998 410']
      ];
      for (const per of people) {
        await pool.query(
          `INSERT INTO public.eleesa_directory_people
           (full_name, role_group, title_or_level, specialty_or_portfolio, email, phone)
           VALUES ($1,$2,$3,$4,$5,$6)`,
          per
        );
      }
    }
  } catch (e) {
    console.error('Wave 4 people seed warning:', e.message);
  }
}

app.get('/api/wave4/notices', async (req, res) => {
  await ensureWave4Ready();
  try {
    const result = await pool.query('SELECT * FROM public.eleesa_notices ORDER BY notice_id DESC');
    res.json({ notices: result.rows });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/wave4/notices', async (req, res) => {
  await ensureWave4Ready();
  const { title, category, event_date, venue, body, posted_by, poster_role } = req.body || {};
  if (!title || !body || !posted_by) {
    return res.status(400).json({ message: 'title, body, and posted_by are required.' });
  }
  try {
    const result = await pool.query(
      `INSERT INTO public.eleesa_notices (title, category, event_date, venue, body, posted_by, poster_role, rsvp_count)
       VALUES ($1,$2,$3,$4,$5,$6,$7,1) RETURNING *`,
      [
        title.trim(),
        String(category || 'Department Notice').trim(),
        String(event_date || '').trim(),
        String(venue || 'UMaT Engineering Block').trim(),
        body.trim(),
        posted_by.trim(),
        String(poster_role || 'executive').trim()
      ]
    );
    res.status(201).json({ notice: result.rows[0] });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/wave4/notices/:id/rsvp', async (req, res) => {
  await ensureWave4Ready();
  const id = parseInt(req.params.id, 10);
  try {
    const result = await pool.query(
      'UPDATE public.eleesa_notices SET rsvp_count = rsvp_count + 1 WHERE notice_id = $1 RETURNING *',
      [id]
    );
    res.json({ notice: result.rows[0] || null });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/wave4/store', async (req, res) => {
  await ensureWave4Ready();
  try {
    const result = await pool.query('SELECT * FROM public.eleesa_store_items ORDER BY item_id DESC');
    res.json({ items: result.rows });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/wave4/store', async (req, res) => {
  await ensureWave4Ready();
  const { title, category, price_ghs, condition, location, description, seller_name, seller_contact, seller_level } = req.body || {};
  if (!title || !seller_name || !seller_contact) {
    return res.status(400).json({ message: 'title, seller_name, and seller_contact are required.' });
  }
  try {
    const result = await pool.query(
      `INSERT INTO public.eleesa_store_items
       (title, category, price_ghs, condition, location, description, seller_name, seller_contact, seller_level, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'Available') RETURNING *`,
      [
        title.trim(),
        String(category || 'Lab & Circuit Kits').trim(),
        Number(price_ghs) || 0,
        String(condition || 'Neatly Used').trim(),
        String(location || 'Tarkwa Campus').trim(),
        String(description || '').trim(),
        seller_name.trim(),
        seller_contact.trim(),
        String(seller_level || '300').trim()
      ]
    );
    res.status(201).json({ item: result.rows[0] });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.patch('/api/wave4/store/:id/status', async (req, res) => {
  await ensureWave4Ready();
  const id = parseInt(req.params.id, 10);
  const status = String(req.body?.status || 'Sold').trim();
  try {
    const result = await pool.query(
      'UPDATE public.eleesa_store_items SET status = $1 WHERE item_id = $2 RETURNING *',
      [status, id]
    );
    res.json({ item: result.rows[0] || null });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get('/api/wave4/people', async (req, res) => {
  await ensureWave4Ready();
  try {
    const dirRes = await pool.query('SELECT * FROM public.eleesa_directory_people ORDER BY person_id ASC');
    res.json({ people: dirRes.rows });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
// ==================== END WAVE 4 ====================


// ==================== WAVE 5: FEEDBACK, HELP DESK & TOOLS TELEMETRY ====================
let _wave5ReadyPromise = null;
function ensureWave5Ready() {
  if (!_wave5ReadyPromise) {
    _wave5ReadyPromise = initAndSeedWave5().catch((err) => {
      _wave5ReadyPromise = null;
      console.error('Wave 5 init error:', err.message);
      throw err;
    });
  }
  return _wave5ReadyPromise;
}

async function initAndSeedWave5() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS public.eleesa_feedback_tickets (
        ticket_id SERIAL PRIMARY KEY,
        category VARCHAR(60) NOT NULL DEFAULT 'Help Desk',
        subject VARCHAR(200) NOT NULL,
        message TEXT NOT NULL,
        submitted_by VARCHAR(150) NOT NULL,
        sender_role VARCHAR(40) DEFAULT 'student',
        sender_level VARCHAR(20) DEFAULT '300',
        status VARCHAR(30) NOT NULL DEFAULT 'Open',
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    const tCnt = await pool.query('SELECT COUNT(*)::int AS cnt FROM public.eleesa_feedback_tickets');
    if ((tCnt.rows[0]?.cnt ?? 0) === 0) {
      const seeds = [
        ['Help Desk', 'Request for Official 8-Week Industrial Attachment Intro Letter', 'Need signed departmental introductory letter addressed to ECG Sekondi-Takoradi Engineering Office.', 'Maxwell Amoah', 'student', '300', 'Open'],
        ['Lab & Facility', 'Oscilloscope Probe Calibration in Electronics Lab Bench 4', 'Channel 2 attenuator probe on Bench 4 reads ~8% low at 1kHz square wave test.', 'Kwame Mensah', 'student', '400', 'In Review'],
        ['Suggestion', 'Add Three-Phase Fault & Load Flow Quick Reference Cards', 'Helpful to have symmetrical components and per-unit conversion formulas alongside the CGPA calculator.', 'Abena Osei', 'executive', '300', 'Resolved']
      ];
      for (const s of seeds) {
        await pool.query(
          `INSERT INTO public.eleesa_feedback_tickets
           (category, subject, message, submitted_by, sender_role, sender_level, status)
           VALUES ($1,$2,$3,$4,$5,$6,$7)`,
          s
        );
      }
    }
  } catch (e) {
    console.error('Wave 5 init warning:', e.message);
  }
}

app.get('/api/wave5/feedback', async (req, res) => {
  await ensureWave5Ready();
  try {
    const result = await pool.query('SELECT * FROM public.eleesa_feedback_tickets ORDER BY ticket_id DESC');
    res.json({ tickets: result.rows });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/wave5/feedback', async (req, res) => {
  await ensureWave5Ready();
  const { category, subject, message, submitted_by, sender_role, sender_level } = req.body || {};
  if (!subject || !message || !submitted_by) {
    return res.status(400).json({ message: 'subject, message, and submitted_by are required.' });
  }
  try {
    const result = await pool.query(
      `INSERT INTO public.eleesa_feedback_tickets
       (category, subject, message, submitted_by, sender_role, sender_level, status)
       VALUES ($1,$2,$3,$4,$5,$6,'Open') RETURNING *`,
      [
        String(category || 'Help Desk').trim(),
        subject.trim(),
        message.trim(),
        submitted_by.trim(),
        String(sender_role || 'student').trim(),
        String(sender_level || '300').trim()
      ]
    );
    res.status(201).json({ ticket: result.rows[0] });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
// ==================== END WAVE 5 ====================

const activeHttpServer = app.listen(PORT, (err) => {
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

if (activeHttpServer && typeof activeHttpServer.on === 'function') activeHttpServer.on('error', (err) => {
  console.error('Server error:', err.message);
  process.exit(1);
});