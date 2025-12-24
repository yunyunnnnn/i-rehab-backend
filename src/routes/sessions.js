const express = require('express');
const router = express.Router();
const { pool } = require('../db');


router.get('/sessions/test', (req, res) => {
  res.json({ message: 'sessions route ok', userId: Number(req.header('x-user-id') || 1) });
});


router.post('/sessions', async (req, res) => {
  try {
    const userId = Number(req.header('x-user-id') || 1);
    const { planId = null } = req.body || {};

    const [ret] = await pool.execute(
      `
      INSERT INTO sessions (user_id, plan_id, started_at)
      VALUES (?, ?, NOW())
      `,
      [userId, planId]
    );

    const [rows] = await pool.execute(
      `SELECT DATE_FORMAT(started_at, '%Y-%m-%d %H:%i:%s') AS startedAt FROM sessions WHERE id = ?`,
      [ret.insertId]
    );

    res.json({ sessionId: ret.insertId, startedAt: rows[0]?.startedAt });
  } catch (e) {
    console.error('POST /sessions failed', e);
    res.status(500).json({ error: 'create_session_failed' });
  }
});


router.patch('/sessions/:id/finish', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const userId = Number(req.header('x-user-id') || 1);
    const sessionId = Number(req.params.id);
    const { durationMin = 0, area = null, task = null, accuracy = null } = req.body || {};

    const localDate = new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Taipei' });

    await conn.beginTransaction();

    await conn.execute(
      `UPDATE sessions SET finished_at = NOW() WHERE id = ? AND user_id = ?`,
      [sessionId, userId]
    );

    const [ret] = await conn.execute(
      `
      INSERT INTO records (user_id, date, area, task, duration_min, accuracy, session_id)
      VALUES (?, STR_TO_DATE(?, '%Y-%m-%d'), ?, ?, ?, ?, ?)
      `,
      [userId, localDate, area, task, durationMin, accuracy, sessionId]
    );

    await conn.commit();
    res.json({ ok: true, recordId: ret.insertId, date: localDate });
  } catch (e) {
    await (conn?.rollback?.());
    console.error('PATCH /sessions/:id/finish failed', e);
    res.status(500).json({ error: 'finish_session_failed' });
  } finally {
    conn?.release?.();
  }
});

module.exports = router;