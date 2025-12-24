const express = require('express');
const router = express.Router();
const { pool } = require('../db');

async function fetchPlans(userId, from, to) {
  const [rows] = await pool.execute(
    `
    SELECT
      id,
      user_id AS userId,
      DATE_FORMAT(date, '%Y-%m-%d')        AS date,
      area,
      task,
      TIME_FORMAT(scheduled_time, '%H:%i') AS scheduledTime
    FROM plans
    WHERE user_id = ?
      AND date BETWEEN ? AND ?
    ORDER BY date, scheduled_time
    `,
    [userId, from, to]
  );
  return rows;
}

router.get('/plans', async (req, res) => {
  try {
    const userId = Number(req.header('x-user-id') || req.query.userId);
    const { from, to } = req.query;
    if (!userId || !from || !to) {
      return res.status(400).json({ error: 'missing_params' });
    }
    const rows = await fetchPlans(userId, from, to);
    res.json(rows);
  } catch (e) {
    console.error('GET /plans failed', e);
    res.status(500).json({ error: 'DB error' });
  }
});


router.get('/users/:userId/plans', async (req, res) => {
  try {
    const userId = Number(req.params.userId);
    const { from, to } = req.query;
    if (!userId || !from || !to) {
      return res.status(400).json({ error: 'missing_params' });
    }
    const rows = await fetchPlans(userId, from, to);
    res.json(rows);
  } catch (e) {
    console.error('GET /users/:userId/plans failed', e);
    res.status(500).json({ error: 'DB error' });
  }
});


router.post('/plans', async (req, res) => {
  try {
    const { userId, date, area, task, scheduledTime } = req.body || {};
    if (!userId || !date || !task) {
      return res.status(400).json({ error: 'missing_params' });
    }
    const [ret] = await pool.execute(
      `
      INSERT INTO plans (user_id, date, area, task, scheduled_time)
      VALUES (?, STR_TO_DATE(?, '%Y-%m-%d'), ?, ?, STR_TO_DATE(?, '%H:%i:%s'))
      `,
      [userId, date, area || null, task, scheduledTime ? `${scheduledTime}:00` : null]
    );
    res.json({ planId: ret.insertId });
  } catch (e) {
    console.error('POST /plans failed', e);
    res.status(500).json({ error: 'create_plan_failed' });
  }
});

module.exports = router;