import bcrypt from 'bcrypt';
import cors from 'cors';
import dotenv from 'dotenv';
import express from 'express';
import jwt from 'jsonwebtoken';
import mysql from 'mysql2/promise';
import cron from 'node-cron';
import path from 'path';
import { fileURLToPath } from 'url';
import patientsRouter from './routes/patients.js';
import { sendResetOtpEmail } from './services/emailService.js';

dotenv.config();
const MYSQL_TZ = process.env.MYSQL_TZ || '+08:00';

const {
  DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME,
  JWT_SECRET = 'dev_secret',
  BACKFILL_ON_BOOT_DAYS = 2, 
} = process.env;

const app = express();
app.use(cors());
app.use(express.json());

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


const videosDir = path.join(__dirname, '..', 'public', 'videos');
console.log('[STATIC] videos dir =', videosDir);
function authRequired(req, res, next) {
  try {
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.startsWith('Bearer ')
      ? authHeader.slice(7)
      : null;

    if (!token) {
      return res.status(401).json({
        ok: false,
        message: '缺少登入憑證，請重新登入',
      });
    }

    const payload = jwt.verify(token, JWT_SECRET);
    if (!payload || !payload.pid) {
      return res.status(401).json({
        ok: false,
        message: '登入憑證無效，請重新登入',
      });
    }

    req.user = { id: payload.pid };
    next();
  } catch (err) {
    console.error('[authRequired] failed:', err);
    return res.status(401).json({
      ok: false,
      message: '登入已過期，請重新登入',
    });
  }
}
app.use('/videos', express.static(videosDir, { maxAge: '7d' }));


function localISODate(d = new Date()) {
  const tz = d.getTimezoneOffset();
  return new Date(d.getTime() - tz * 60_000).toISOString().slice(0, 10);
}
function localISODateOffset(days = 0) {
  const base = new Date();
  base.setHours(0, 0, 0, 0);
  return localISODate(new Date(base.getTime() - days * 86_400_000));
}
function normalizePhone(raw) {
  const s = String(raw || '').replace(/\s|-/g, '');
  if (/^\+8869\d{8}$/.test(s)) return s;
  if (/^09\d{8}$/.test(s)) return '+886' + s.slice(1);
  return s;
}

function parseList(mixed, fallback = []) {
  try {
    if (Array.isArray(mixed)) return mixed;
    const s = (mixed ?? '').toString().trim();
    if (!s) return [...fallback];
    if (s.startsWith('[') && s.endsWith(']')) {
      const arr = JSON.parse(s);
      return Array.isArray(arr) ? arr : [...fallback];
    }
    return s.split(/[,，、]/).map(x => x.trim()).filter(Boolean);
  } catch {
    return [...fallback];
  }
}
const AREA_NORMALIZE = (s) => {
  const raw = String(s || '').trim();
  const v = raw.toLowerCase();
  if (!v) return '';

  if (v.includes('頸') || v.includes('neck') || v.includes('cervical')) {
    return '頸椎';
  }

  if (v.includes('肩') || v.includes('shoulder')) {
    return '肩關節';
  }

  if (v.includes('腰') || v.includes('lumbar') || v.includes('lowerback') || v.includes('lower back') || v.includes('lowback')) {
    return '腰椎';
  }

  if (v.includes('膝') || v.includes('knee')) {
    return '膝關節';
  }

  if (v.includes('髖') || v.includes('hip')) {
    return '髖關節';
  }

  return raw;
};

const pool = mysql.createPool({
  host: DB_HOST || '127.0.0.1',
  port: Number(DB_PORT || 3306),
  user: DB_USER || 'root',
  password: DB_PASSWORD || '',
  database: DB_NAME || 'irehab',
  waitForConnections: true,
  connectionLimit: 10,
  dateStrings: true,
  ssl: (process.env.DB_SSL || '').toLowerCase() === 'true'
    ? { rejectUnauthorized: true }
    : undefined,
});
const q = (sql, params = []) => pool.query(sql, params);
const one = async (sql, params = []) => {
  const [rows] = await q(sql, params);
  return rows[0] || null;
};

if (patientsRouter) app.use('/api/patients', patientsRouter(pool));

app.get('/health', (req, res) => res.json({ ok: true, now: new Date().toISOString() }));


async function ensureIndex(table, indexName) {
  const row = await one(
    `SELECT 1 FROM information_schema.statistics
     WHERE table_schema = DATABASE() AND table_name=? AND index_name=? LIMIT 1`,
    [table, indexName]
  );
  return !!row;
}
async function ensureSchema() {
  await q(`CREATE TABLE IF NOT EXISTS patient_auth (
    id INT PRIMARY KEY AUTO_INCREMENT,
    patient_id INT NOT NULL,
    phone VARCHAR(20) NOT NULL,
    email VARCHAR(255) NULL,
    password_hash VARCHAR(255) NULL,
    password_updated_at DATETIME NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_patient (patient_id),
    UNIQUE KEY uniq_phone (phone),
    KEY idx_active (is_active)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`);

await q(`CREATE TABLE IF NOT EXISTS email_otps (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    code VARCHAR(6) NOT NULL,
    email VARCHAR(255) NOT NULL,
    purpose ENUM('reset') NOT NULL DEFAULT 'reset',
    expires_at DATETIME NOT NULL,
    used TINYINT(1) NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_email_purpose_used (email, purpose, used),
    KEY idx_email_created (email, created_at)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`);
  
  if (!await ensureIndex('records', 'uniq_user_date_area_task')) {
    await q(`CREATE UNIQUE INDEX uniq_user_date_area_task ON records (user_id, date, area, task)`);
  }
  if (!await ensureIndex('records', 'idx_user_date')) {
    await q(`CREATE INDEX idx_user_date ON records (user_id, date)`);
  }


  await q(`CREATE TABLE IF NOT EXISTS exercises (
    id INT PRIMARY KEY AUTO_INCREMENT,
    slug VARCHAR(255) NULL,
    area VARCHAR(50) NULL,
    task VARCHAR(255) NULL,
    name_zh VARCHAR(255) NULL,
    video_url VARCHAR(512) NULL,
    duration_min INT NULL,
    goals TEXT NULL,
    intensity VARCHAR(50) NULL,
    frequency VARCHAR(255) NULL, 
    intro TEXT NULL,
    steps_json JSON NULL,
    precautions_json JSON NULL,
    area_zh VARCHAR(50) NULL,
    task_zh VARCHAR(255) NULL,
    duration_desc VARCHAR(255) NULL,
    steps TEXT NULL,
    cautions TEXT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`);
}

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { reset_token, new_password } = req.body || {};
    if (!reset_token || !new_password) {
      return res.status(400).json({ ok: false, message: '缺少資料' });
    }

    if (String(new_password).length < 4) {
      return res
        .status(400)
        .json({ ok: false, message: '新密碼至少需要 4 碼' });
    }

    let payload;
    try {
      payload = jwt.verify(reset_token, JWT_SECRET);
    } catch {
      return res
        .status(400)
        .json({ ok: false, message: '重設連結已失效' });
    }

    if (payload.typ !== 'reset') {
      return res
        .status(400)
        .json({ ok: false, message: '無效的重設連結' });
    }

    let pid = payload.pid || null;
    const tokenPhone = payload.phone || null;
    const tokenEmail = payload.email || null;

    if (!pid) {
      if (tokenPhone) {
        const row = await one(
          `SELECT id
             FROM patients
            WHERE TRIM(phone) IN (?, ?)
            LIMIT 1`,
          [
            normalizePhone(tokenPhone),
            normalizePhone(tokenPhone).replace(/^\+886/, '0'),
          ]
        );
        pid = row?.id || null;
      } else if (tokenEmail) {
        const row = await one(
          `SELECT id FROM patients WHERE email = ? LIMIT 1`,
          [tokenEmail]
        );
        pid = row?.id || null;
      }
    }

    if (!pid) {
      return res
        .status(404)
        .json({ ok: false, message: '找不到重設目標的使用者' });
    }

    const patient = await one(
      `SELECT id, phone, email
         FROM patients
        WHERE id = ?
        LIMIT 1`,
      [pid]
    );

    if (!patient) {
      return res
        .status(404)
        .json({ ok: false, message: '找不到使用者資料' });
    }

    const normPhone = normalizePhone(patient.phone);
    const finalEmail = patient.email || tokenEmail || null;

    await q(
      `INSERT INTO patient_auth (patient_id, phone, email)
       VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE
         phone = VALUES(phone),
         email = VALUES(email)`,
      [patient.id, normPhone || null, finalEmail]
    );

    const hash = await bcrypt.hash(String(new_password), 10);
    await q(
      `UPDATE patient_auth
          SET password_hash = ?,
              password_updated_at = NOW(),
              updated_at = NOW()
        WHERE patient_id = ?`,
      [hash, patient.id]
    );

    return res.json({ ok: true, message: '密碼已更新' });
  } catch (err) {
    console.error('[reset-password] failed:', err);
    return res.status(500).json({ ok: false, message: 'server_error' });
  }
});

app.post('/api/auth/change-password', authRequired, async (req, res) => {
  try {
    const userId = req.user?.id; 
    const { oldPassword, newPassword } = req.body || {};

    if (!oldPassword || !newPassword) {
      return res.status(400).json({
        ok: false,
        message: '缺少舊密碼或新密碼',
      });
    }

    if (String(newPassword).length < 4) {
      return res.status(400).json({
        ok: false,
        message: '新密碼至少需要 4 碼',
      });
    }

    const patient = await one(
      `SELECT id, id_number, phone, email
         FROM patients
        WHERE id = ?
        LIMIT 1`,
      [userId]
    );

    if (!patient) {
      return res.status(404).json({
        ok: false,
        message: '找不到帳號',
      });
    }

    const authRow = await one(
      `SELECT password_hash
         FROM patient_auth
        WHERE patient_id = ?
          AND is_active = 1
        LIMIT 1`,
      [userId]
    );

    let passOK = false;

    if (authRow?.password_hash) {
      passOK = await bcrypt.compare(String(oldPassword), authRow.password_hash);
    } else {
      const last4 = String(patient.id_number || '').slice(-4);
      passOK = String(oldPassword) === last4;
    }

    if (!passOK) {
      return res.status(400).json({
        ok: false,
        message: '目前密碼錯誤',
      });
    }

    const normPhone = normalizePhone(patient.phone);
    await q(
      `INSERT INTO patient_auth (patient_id, phone, email)
       VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE
         phone = VALUES(phone),
         email = VALUES(email)`,
      [patient.id, normPhone || null, patient.email || null]
    );

    const newHash = await bcrypt.hash(String(newPassword), 10);
    await q(
      `UPDATE patient_auth
          SET password_hash = ?,
              password_updated_at = NOW(),
              updated_at = NOW()
        WHERE patient_id = ?`,
      [newHash, patient.id]
    );

    return res.json({
      ok: true,
      message: '密碼已成功修改',
    });
  } catch (err) {
    console.error('[change-password] failed:', err);
    return res.status(500).json({
      ok: false,
      message: 'server_error',
    });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { id_number, password } = req.body || {};

    console.log('=== [LOGIN] incoming ===');
    console.log('[LOGIN] body =', req.body);

    if (!id_number || !password) {
      console.log('[LOGIN] missing id_number or password');
      return res
        .status(400)
        .json({ ok: false, message: '缺少帳號或密碼', debug: 'missing_fields' });
    }

    const patient = await one(
      `SELECT id, id_number, name, email, phone
         FROM patients
        WHERE id_number = ?
        LIMIT 1`,
      [id_number]
    );
    console.log('[LOGIN] patient =', patient);

    if (!patient) {
      console.log('[LOGIN] no patient found for id_number =', id_number);
      return res.status(401).json({
        ok: false,
        message: '帳號或密碼錯誤',
        debug: 'no_patient',
      });
    }

    const auth = await one(
      `SELECT password_hash
         FROM patient_auth
        WHERE patient_id = ?
        LIMIT 1`,
      [patient.id]
    );
    console.log('[LOGIN] authRow =', auth);

    let passOK = false;
    let reason = '';

    if (auth?.password_hash) {
      passOK = await bcrypt.compare(String(password), auth.password_hash);
      reason = passOK ? 'hash_ok' : 'hash_mismatch';
      console.log('[LOGIN] compare bcrypt result =', passOK);
    } else {
      const last4 = String(patient.id_number || '').slice(-4);
      passOK = String(password) === last4;
      reason = passOK ? 'last4_ok' : 'last4_mismatch';
      console.log('[LOGIN] compare last4 result =', passOK, 'last4 =', last4);
    }

    if (!passOK) {
      console.log('[LOGIN] password not match, reason =', reason);
      return res.status(401).json({
        ok: false,
        message: '帳號或密碼錯誤',
        debug: {
          reason,
          id_number,
          patient_id: patient.id,
          hasAuth: !!auth,
        },
      });
    }

    const token = jwt.sign({ pid: patient.id }, JWT_SECRET, {
      expiresIn: '7d',
    });

    console.log('[LOGIN] SUCCESS for pid =', patient.id);

    return res.json({
      ok: true,
      user: {
        id: patient.id,
        name: patient.name,
        id_number: patient.id_number,
      },
      token,
    });
  } catch (err) {
    console.error('[LOGIN] unexpected error:', err);
    return res.status(500).json({ ok: false, message: 'server_error' });
  }
});

function parseMaybeJsonArray(v) {
  if (v == null) return [];
  try {
    if (Array.isArray(v)) return v;
    const s = String(v).trim();
    if (!s) return [];
    if ((s.startsWith('[') && s.endsWith(']')) || (s.startsWith('["') && s.endsWith('"]'))) {
      const arr = JSON.parse(s);
      return Array.isArray(arr) ? arr : [];
    }
    return s.split(/,|，/).map(x => x.trim()).filter(Boolean);
  } catch {
    return [];
  }
}

app.get('/api/v1/exercises', async (req, res) => {
  try {
    const rawArea = (req.query.area || '').toString().trim();
    const rawTask = (req.query.task || '').toString().trim();

    const area =
      !rawArea ? '' :
      rawArea.toLowerCase() === 'neck' ? 'neck' :
      rawArea.toLowerCase() === 'shoulder' ? 'shoulder' :
      rawArea.toLowerCase() === 'knee' ? 'knee' :
      rawArea;

    const row = await one(
      `SELECT id, slug, area, area_zh, task_zh, name_zh,
              duration_min, duration_desc,
              video_url, intro, goals, intensity, frequency,
              steps, steps_json, cautions, precautions_json
         FROM exercises
        WHERE (name_zh = ? OR task_zh = ? OR slug = ?)
           OR ( (? <> '') AND (area = ? OR area_zh LIKE CONCAT('%', ?, '%')) )
        ORDER BY (name_zh = ? OR task_zh = ? OR slug = ?) DESC, id ASC
        LIMIT 1`,
      [rawTask, rawTask, rawTask, area, area, area, rawTask, rawTask, rawTask]
    );

    if (!row) return res.status(404).json({ ok: false, message: 'exercise_not_found' });

    const steps = parseMaybeJsonArray(row.steps_json ?? row.steps);
    const precautions = parseMaybeJsonArray(row.precautions_json ?? row.cautions);

    const origin = `${req.protocol}://${req.get('host')}`;
    let videoUrl = (row.video_url || '').toString();
    if (videoUrl.startsWith('/')) videoUrl = origin + videoUrl;

    res.json({
      ok: true,
      area: row.area || area,
      task: row.name_zh || row.task_zh || rawTask,
      videoUrl,
      goals: row.goals || row.intro || '',
      intensity: row.intensity || '',
      duration_min: row.duration_min ? Number(row.duration_min) : undefined,
      duration_desc: row.duration_desc || '',
      frequency: row.frequency || '',
      steps,
      precautions
    });
  } catch (err) {
    console.error('[exercises] failed:', err);
    res.status(500).json({ ok: false, message: 'exercises query failed' });
  }
});

app.post('/api/v1/records/start', async (req, res) => {
  try {
    const userId = Number(req.headers['x-user-id'] || req.body?.user_id || 1); 
    const { date, area: areaRaw, task } = req.body || {};
    const area = AREA_NORMALIZE(areaRaw);

    if (!userId || !date || !area || !task) {
      return res.status(400).json({ ok: false, message: 'missing_fields' });
    }

    const [r] = await q(
      `INSERT INTO records (user_id, \`date\`, area, task, status, duration_min, created_at, updated_at)
       VALUES (?, ?, ?, ?, 'pending', 0, NOW(), NOW())
       ON DUPLICATE KEY UPDATE
         status = VALUES(status),
         updated_at = NOW()`,
      [userId, String(date).slice(0,10), area, String(task).trim()]
    );

    res.json({ ok: true, affected: r.affectedRows, user_id: userId, date, area, task, status: 'pending' });
  } catch (err) {
    console.error('[records/start] failed:', err);
    res.status(500).json({ ok: false, message: 'start record failed' });
  }
});

async function backfillMissedForDate(targetDate) {
  const date = String(targetDate || localISODate()).slice(0, 10);

  const [plans] = await q(
    `SELECT patient_id, body_parts, videos, dates, status
       FROM training_plans
      WHERE status IS NULL OR status <> 'archived'`
  );

  let inserted = 0;
  let skipped = 0;

  for (const p of plans || []) {
    const dates = parseList(p.dates, []);
    if (!dates.includes(date)) continue;

    const parts = parseList(p.body_parts, []);
    const items = parseList(p.videos, []);
    const area = AREA_NORMALIZE(parts[0] || '');

for (const task of items) {
  if (!task) continue;

  const [r] = await q(
    `INSERT IGNORE INTO records
       (user_id, \`date\`, area, task, status, duration_min, created_at, updated_at)
     VALUES
       (?, ?, ?, ?, 'missed', 0, NOW(), NOW())`,
    [p.patient_id, date, area, String(task).trim()]
  );
  
      if (r.affectedRows > 0) inserted++;
      else skipped++;
    }
  }
  return { date, inserted, skipped };
}

async function backfillRangeOnBoot(days = 2) {
  const results = [];
  for (let i = 1; i <= Number(days); i++) {
    const d = localISODateOffset(i);
    try {
      const r = await backfillMissedForDate(d);
      results.push({ date: d, ...r });
    } catch (err) {
      console.error(`[BootBackfill] failed on ${d}`, err);
    }
  }
  return results;
}

app.post('/api/v1/admin/backfill-missed', async (req, res) => {
  try {
    const date = (req.query?.date || req.body?.date || localISODate()).slice(0, 10);
    const result = await backfillMissedForDate(date);
    res.json({ ok: true, ...result });
  } catch (err) {
    console.error('[admin/backfill-missed] failed:', err);
    res.status(500).json({ ok: false, message: 'backfill failed' });
  }
});


function getRange(req) {
  const from = req.query.from || '1900-01-01';
  const to   = req.query.to   || '2999-12-31';
  return { from, to };
}


app.get('/api/v1/users/:id/plans', async (req, res) => {
  try {
    const pid = Number(req.params.id);
    const from = req.query.from || '1900-01-01';
    const to   = req.query.to   || '2999-12-31';

    const [rows] = await q(
      `SELECT id, plan_code, patient_id, patient_code, body_parts, videos, dates, notes, status, created_at
         FROM training_plans
        WHERE patient_id = ? AND (status IS NULL OR status <> 'archived')`,
      [pid]
    );

    const inRange = d => d >= from && d <= to;
    const bucket = new Map();

    for (const r of rows || []) {
      const dates  = parseList(r.dates, []);
      const items  = parseList(r.videos, []);
      const within = dates.filter(inRange);

      for (const d of within) {
        if (!bucket.has(d)) bucket.set(d, new Set());
        const set = bucket.get(d);
        for (const name of items) if (name && typeof name === 'string') set.add(name.trim());
      }
    }

    const list = Array.from(bucket.entries())
      .map(([date, set]) => ({ date, items: Array.from(set) }))
      .sort((a, b) => a.date.localeCompare(b.date));

    res.json(list);
  } catch (err) {
    console.error('[plans] failed:', err);
    res.status(500).json({ ok: false, message: 'plans query failed' });
  }
});

app.get('/api/v1/users/:id/records', async (req, res) => {
  try {
    const pid = Number(req.params.id);
    const { from, to } = getRange(req);

    const [rows] = await q(
      `SELECT
         id,
         user_id AS patient_id,
         \`date\` AS date,
         area,
         task,
         status,
         duration_min,
         accuracy,
         accuracy_best,
         accuracy_avg,
         analysis_summary,
         encouragement_text,
         session_id,
         created_at,
         updated_at
       FROM records
       WHERE user_id = ?
         AND \`date\` BETWEEN ? AND ?
       ORDER BY \`date\` ASC`,
      [pid, from, to]
    );

    res.json(rows || []);
  } catch (err) {
    console.error('[records] failed:', err);
    res.status(500).json({ ok: false, message: 'records query failed' });
  }
});

function parseDurationToSeconds(val) {
  if (val == null) return 0;
  if (typeof val === 'number') return val;
  const s = String(val).trim();
  if (!s) return 0;

  if (/^\d+$/.test(s)) return parseInt(s, 10) || 0;

  const parts = s.split(':').map((x) => parseInt(x, 10));

  if (parts.length === 3) {
    const [h, m, sec] = parts;
    if ([h, m, sec].some((x) => Number.isNaN(x))) return 0;
    return h * 3600 + m * 60 + sec;
  }

  if (parts.length === 2) {
    const [m, sec] = parts;
    if ([m, sec].some((x) => Number.isNaN(x))) return 0;
    return m * 60 + sec;
  }

  return 0;
}

function getHeaderUserId(req){
  return Number(req.headers['x-user-id'] || req.query.uid || req.body?.user_id || 0) || 1; // demo fallback: 1
}


app.get('/api/v1/sessions/test', (req, res) => {
  res.json({ ok: true, userId: getHeaderUserId(req) });
});


app.post('/api/v1/sessions', async (req, res) => {
  try {
    const userId = getHeaderUserId(req);
    const planId = (req.body && req.body.planId != null) ? Number(req.body.planId) : null;

    const [ret] = await q(
      `INSERT INTO sessions (user_id, plan_id, started_at) VALUES (?, ?, NOW())`,
      [userId, planId]
    );

    const row = await one(
      `SELECT DATE_FORMAT(started_at, '%Y-%m-%d %H:%i:%s') AS startedAt FROM sessions WHERE id = ?`,
      [ret.insertId]
    );
    res.json({ sessionId: ret.insertId, startedAt: row?.startedAt || null });
  } catch (err) {
    console.error('[sessions POST] failed:', err);
    res.status(500).json({ ok: false, message: 'create_session_failed' });
  }
});

app.patch('/api/v1/sessions/:id/finish', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const userId = getHeaderUserId(req);
    const sessionId = Number(req.params.id);

    const {
      durationSec,
      duration_sec,
      total_seconds,
      totalDuration,
      duration_hms,
      durationMin,
      duration_min,
      duration,
      area: areaRaw = null,
      task = null,
      total_reps = 0,
      reps_left = 0,
      reps_right = 0,
      accuracy_best = null,
      accuracy_avg = null,
      analysis_summary = null,
      encouragement_text = null,
    } = req.body || {};

    const area = AREA_NORMALIZE(areaRaw);

    const totalSec = parseDurationToSeconds(
      durationSec ??
      duration_sec ??
      total_seconds ??
      totalDuration ??
      duration_hms ??
      duration ??
      duration_min ??
      durationMin ??
      0
    );


    const localDate = new Date().toLocaleDateString('en-CA', {
      timeZone: 'Asia/Taipei',
    });

    await conn.beginTransaction();


    await conn.query(
      `UPDATE sessions SET finished_at = NOW()
       WHERE id = ? AND user_id = ?`,
      [sessionId, userId]
    );


    await conn.query(
      `INSERT INTO records (
         user_id, date, area, task, status,
         duration_min,
         total_reps, reps_left, reps_right,
         accuracy_best, accuracy_avg,
         analysis_summary, encouragement_text,
         session_id, created_at, updated_at
       )
       VALUES (
         ?, STR_TO_DATE(?, '%Y-%m-%d'), ?, ?, 'done',
         SEC_TO_TIME(?),
         ?, ?, ?,
         ?, ?,
         ?, ?,
         ?, NOW(), NOW()
       )
       ON DUPLICATE KEY UPDATE
         status             = 'done',
         duration_min       = VALUES(duration_min),
         total_reps         = VALUES(total_reps),
         reps_left          = VALUES(reps_left),
         reps_right         = VALUES(reps_right),
         accuracy_best      = VALUES(accuracy_best),
         accuracy_avg       = VALUES(accuracy_avg),
         analysis_summary   = VALUES(analysis_summary),
         encouragement_text = VALUES(encouragement_text),
         session_id         = VALUES(session_id),
         updated_at         = NOW()`,
      [
        userId,
        localDate,
        area,
        String(task || '').trim(),
        totalSec,
        Number(total_reps ?? 0),
        Number(reps_left ?? 0),
        Number(reps_right ?? 0),
        accuracy_best != null ? Number(accuracy_best) : null,
        accuracy_avg != null ? Number(accuracy_avg) : null,
        analysis_summary || null,
        encouragement_text || null,
        sessionId,
      ]
    );

    await conn.commit();
    res.json({ ok: true, date: localDate, sessionId, duration_sec: totalSec });
  } catch (err) {
    await (conn?.rollback?.());
    console.error('[sessions finish] failed:', err);
    res.status(500).json({ ok: false, message: 'finish_session_failed' });
  } finally {
    conn?.release?.();
  }
});


app.post('/api/auth/request-email-otp', async (req, res) => {
  try {
    const email = (req.body?.email || '').trim();
    if (!email) {
      return res.status(400).json({ ok: false, message: '缺少 email' });
    }

 
    const p = await one(
      `SELECT id FROM patients WHERE email = ? LIMIT 1`,
      [email]
    );
    const a = await one(
      `SELECT patient_id AS id FROM patient_auth WHERE email = ? LIMIT 1`,
      [email]
    );
    const pid = (a && a.id) || (p && p.id) || null;

    if (!pid) {
      return res
        .status(404)
        .json({ ok: false, message: '找不到此 email 的使用者' });
    }


    await q(
      `UPDATE email_otps
          SET used = 1
        WHERE email = ?
          AND purpose = 'reset'
          AND used = 0`,
      [email]
    );


    const code = String(Math.floor(100000 + Math.random() * 900000));

    await q(
      `INSERT INTO email_otps (code, email, purpose, expires_at, used)
       VALUES (?, ?, 'reset', NOW() + INTERVAL 10 MINUTE, 0)`,
      [code, email]
    );


    await sendResetOtpEmail(email, code);

    return res.json({
      ok: true,
      message: '驗證碼已寄出，請到信箱收信',
    });
  } catch (err) {
    console.error('[request-email-otp] failed:', err);
    return res.status(500).json({ ok: false, message: 'server_error' });
  }
});


app.post('/api/auth/verify-email-otp', async (req, res) => {
  try {
    const email = (req.body?.email || '').trim();
    const code = (req.body?.code || '').trim();

    if (!email || !code) {
      return res
        .status(400)
        .json({ ok: false, message: '缺少 email 或驗證碼' });
    }

    const row = await one(
      `SELECT id FROM email_otps
        WHERE email = ?
          AND code = ?
          AND purpose = 'reset'
          AND used = 0
          AND expires_at > NOW()
        ORDER BY created_at DESC
        LIMIT 1`,
      [email, code]
    );

    if (!row) {
      return res
        .status(400)
        .json({ ok: false, message: '驗證碼錯誤或已過期' });
    }

   
    await q(`UPDATE email_otps SET used = 1 WHERE id = ?`, [row.id]);

   
    const p = await one(
      `SELECT id FROM patients WHERE email = ? LIMIT 1`,
      [email]
    );
    const a = await one(
      `SELECT patient_id AS id FROM patient_auth WHERE email = ? LIMIT 1`,
      [email]
    );
    const pid = (a && a.id) || (p && p.id) || null;

    if (!pid) {
      return res
        .status(404)
        .json({ ok: false, message: '找不到此 email 的使用者' });
    }

   
    const resetToken = jwt.sign(
      { typ: 'reset', email, pid },
      JWT_SECRET,
      { expiresIn: '10m' }
    );

    return res.json({ ok: true, reset_token: resetToken });
  } catch (err) {
    console.error('[verify-email-otp] failed:', err);
    return res.status(500).json({ ok: false, message: 'server_error' });
  }
});


app.post('/api/auth/reset-password-email', async (req, res) => {
  try {
    const email = (req.body?.email || '').trim();
    const code = (req.body?.code || '').trim();
    const newPassword = (req.body?.newPassword || '').toString();

    if (!email || !code || !newPassword) {
      return res
        .status(400)
        .json({ ok: false, message: '缺少 email / 驗證碼 / 新密碼' });
    }

    if (newPassword.length < 4) {
      return res
        .status(400)
        .json({ ok: false, message: '新密碼至少需要 4 碼' });
    }

   
    const otpRow = await one(
      `SELECT id FROM email_otps
        WHERE email = ?
          AND code = ?
          AND purpose = 'reset'
          AND used = 0
          AND expires_at > NOW()
        ORDER BY created_at DESC
        LIMIT 1`,
      [email, code]
    );

    if (!otpRow) {
      return res
        .status(400)
        .json({ ok: false, message: '驗證碼錯誤或已過期' });
    }

   
    await q(`UPDATE email_otps SET used = 1 WHERE id = ?`, [otpRow.id]);

 
    const p = await one(
      `SELECT id, phone, email
         FROM patients
        WHERE email = ?
        LIMIT 1`,
      [email]
    );
    const a = await one(
      `SELECT patient_id AS id
         FROM patient_auth
        WHERE email = ?
          AND is_active = 1
        LIMIT 1`,
      [email]
    );

    const pid = (a && a.id) || (p && p.id) || null;
    if (!pid) {
      return res
        .status(404)
        .json({ ok: false, message: '找不到此 email 的使用者' });
    }

 
    const normPhone = p ? normalizePhone(p.phone) : null;
    await q(
      `INSERT INTO patient_auth (patient_id, phone, email)
       VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE
         phone = VALUES(phone),
         email = VALUES(email)`,
      [pid, normPhone || null, email]
    );

    const hash = await bcrypt.hash(newPassword, 10);
    await q(
      `UPDATE patient_auth
          SET password_hash = ?,
              password_updated_at = NOW(),
              updated_at = NOW()
        WHERE patient_id = ?`,
      [hash, pid]
    );

    return res.json({ ok: true, message: '密碼已更新' });
  } catch (err) {
    console.error('[reset-password-email] failed:', err);
    return res.status(500).json({ ok: false, message: 'server_error' });
  }
});

const listenPort = Number(process.env.PORT || 3000);
async function boot() {
  console.log('[BOOT] starting...');
  try {
    await pool.query('SELECT 1');
    await pool.query(`SET time_zone = '${MYSQL_TZ}'`);
    pool.on?.('connection', (conn) => conn.query(`SET time_zone = '${MYSQL_TZ}'`));
    console.log('[BOOT] DB OK]');
    await ensureSchema();
    console.log('[BOOT] schema OK');

    const bootResults = await backfillRangeOnBoot(BACKFILL_ON_BOOT_DAYS);
    console.log('[BootBackfill] done:', bootResults);

    app.listen(listenPort, '0.0.0.0', () => {
      console.log(`🚀 API running on http://0.0.0.0:${listenPort}`);
      console.log(`[DB] connected → ${DB_HOST}:${DB_PORT || 3306}/${DB_NAME}`);
    });

    cron.schedule('10 0 * * *', async () => {
      const y = localISODateOffset(1);
      try {
        const r = await backfillMissedForDate(y);
        console.log(`[Cron] backfill ${y}:`, r);
      } catch (err) {
        console.error(`[Cron] backfill failed ${y}`, err);
      }
    });
  } catch (err) {
    console.error('[BOOT] failed:', err);
    process.exit(1);
  }
}



if (process.env.NODE_ENV !== 'test') boot();
export { app, pool };
