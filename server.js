const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

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

// 2. Middleware
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
// 3. Role-Based Access Control Middleware (Visitors need no token)
function authenticateUser(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    req.user = { user_id: null, full_name: 'Guest Visitor', role: 'visitor', level: null };
    return next();
  }

  const token = authHeader.split(' ')[1];
  const demoUsers = {
    'student-token': { user_id: 3, full_name: 'Level 300 Student', role: 'student', level: 300 },
    'executive-token': { user_id: 3, full_name: 'Maxwell Amoah (ELEESA Exec)', role: 'executive', level: 300 },
    'lecturer-token': { user_id: 2, full_name: 'Dr. A. Mensah', role: 'lecturer', level: null },
    'hod-token': { user_id: 1, full_name: 'Prof. K. Boateng (HOD)', role: 'hod_admin', level: null },
  };

  if (!demoUsers[token]) {
    return res.status(401).json({ error: 'Invalid access token' });
  }

  req.user = demoUsers[token];
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

// 4. Start Server & Verify Database Connection
app.get('/api/health', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW() AS server_time');
    res.json({ status: 'ok', time: result.rows[0].server_time });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
const server = app.listen(PORT, (err) => {
  if (err) {
    console.error('Failed to start server:', err.message);
    process.exit(1);
  }
  console.log(`ELEESA API server running at http://localhost:${PORT}`);

  pool.query('SELECT current_database() AS db')
    .then((res) => console.log(`Connected to PostgreSQL database: ${res.rows[0].db}`))
    .catch((dbErr) => console.error('PostgreSQL connection error:', dbErr.message));
});

server.on('error', (err) => {
  console.error('Server error:', err.message);
  process.exit(1);
});