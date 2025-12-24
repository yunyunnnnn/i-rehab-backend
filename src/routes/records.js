const express = require('express');

module.exports = function (pool) {
  const router = express.Router();

  function getUserId(req) {
    return Number(req.headers['x-user-id'] || req.query.userId || req.params.userId || 1);
  }

  function normDate(s) {
    if (!s) return null;
    const m = String(s).match(/^(\d{4})-(\d{2})-(\d{2})$/);
    return m ? `${m[1]}-${m[2]}-${m[3]}` : null;
  }

  async function findExistingRecord({ userId, date, area, task }) {
    const [rows] = await pool.query(
      `SELECT id, status FROM records WHERE user_id=? AND date=? AND area=? AND task=? ORDER BY id DESC LIMIT 1`,
      [userId, date, area, task]
    );
    return rows[0] || null;
  }

  async function insertRecord({ userId, date, area, task, status }) {
    const [rs] = await pool.query(
      `INSERT INTO records (user_id, date, area, task, status)
       VALUES (?, ?, ?, ?, ?)`,
      [userId, date, area, task, status]
    );
    return rs.insertId;
  }


  router.post('/start', async (req, res) => {
    try {
      const userId = getUserId(req);
      const date = normDate(req.body?.date) || new Date().toISOString().slice(0, 10);
      const area = (req.body?.area || '').trim();
      const task = (req.body?.task || '').trim();
      if (!area || !task) return res.status(400).json({ error: 'area / task required' });

      const existing = await findExistingRecord({ userId, date, area, task });
      if (existing) {
        return res.json({ id: existing.id, status: existing.status, existed: true });
      }

      const id = await insertRecord({ userId, date, area, task, status: 'in_progress' });
      return res.status(201).json({ id, status: 'in_progress' });
    } catch (e) {
      console.error('[records/start] error', e);
      return res.status(500).json({ error: 'internal_error' });
    }
  });


  router.patch('/:id/finish', async (req, res) => {
    try {
      const id = Number(req.params.id);
      if (!id) return res.status(400).json({ error: 'invalid id' });

      const durationMin =
        req.body?.durationMin ??
        req.body?.duration_min ??
        null;

      let accuracy =
        req.body?.accuracy ??
        null;

      const accuracyBest =
        req.body?.accuracyBest ??
        req.body?.accuracy_best ??
        null;

      const accuracyAvg =
        req.body?.accuracyAvg ??
        req.body?.accuracy_avg ??
        null;

      if (accuracy == null && accuracyAvg != null) {
        accuracy = accuracyAvg;
      }

      const totalReps =
        req.body?.totalReps ??
        req.body?.total_reps ??
        null;

      const repsLeft =
        req.body?.repsLeft ??
        req.body?.reps_left ??
        null;

      const repsRight =
        req.body?.repsRight ??
        req.body?.reps_right ??
        null;

      const sessionId =
        req.body?.sessionId ??
        req.body?.session_id ??
        null;

      const analysisSummary =
        req.body?.analysisSummary ??
        req.body?.analysis_summary ??
        null;

      const encouragementText =
        req.body?.encouragementText ??
        req.body?.encouragement_text ??
        null;

      const [rs] = await pool.query(
        `UPDATE records
           SET status='done',             
               duration_min      = ?,
               accuracy          = ?,
               accuracy_best     = ?,
               accuracy_avg      = ?,
               total_reps        = ?,
               reps_left         = ?,
               reps_right        = ?,
               session_id        = ?,
               analysis_summary  = ?,
               encouragement_text= ?,
               updated_at        = NOW()
         WHERE id=?`,
        [
          durationMin,
          accuracy,
          accuracyBest,
          accuracyAvg,
          totalReps,
          repsLeft,
          repsRight,
          sessionId,
          analysisSummary,
          encouragementText,
          id
        ]
      );

      if (!rs.affectedRows) {
        return res.status(404).json({ error: 'not_found' });
      }
      return res.json({ ok: true });
    } catch (e) {
      console.error('[records/:id/finish] error', e);
      return res.status(500).json({ error: 'internal_error' });
    }
  });


  router.get('/', async (req, res) => {
    try {
      const userId = getUserId(req);
      const from = normDate(req.query.from);
      const to = normDate(req.query.to);
      if (!from || !to) {
        return res.status(400).json({ error: 'from/to required (YYYY-MM-DD)' });
      }

      const [rows] = await pool.query(
        `SELECT
           id,
           user_id,
           date,
           area,
           task,
           duration_min,
           accuracy,
           accuracy_best,
           accuracy_avg,
           total_reps,
           reps_left,
           reps_right,
           session_id,
           status,
           analysis_summary,
           encouragement_text
         FROM records
         WHERE user_id=? AND date BETWEEN ? AND ?
         ORDER BY date ASC, id ASC`,
        [userId, from, to]
      );
      return res.json(rows);
    } catch (e) {
      console.error('[records GET range] error', e);
      return res.status(500).json({ error: 'internal_error' });
    }
  });


  router.post('/fill-missed', async (req, res) => {
    const conn = await pool.getConnection();
    try {
      const userId = getUserId(req);
      const date = normDate(req.body?.date) || new Date().toISOString().slice(0, 10);

      const [todo] = await conn.query(
        `
        SELECT p.area, p.task
          FROM plans p
          LEFT JOIN records r
            ON r.user_id = p.user_id
           AND r.date = ?
           AND r.area = p.area
           AND r.task = p.task
         WHERE p.user_id = ?
           AND p.date = ?
           AND r.id IS NULL
        `,
        [date, userId, date]
      );

      let inserted = 0;
      for (const row of todo) {
        await conn.query(
          `INSERT INTO records (user_id, date, area, task, status)
           VALUES (?, ?, ?, ?, 'missed')`,
          [userId, date, row.area, row.task]
        );
        inserted++;
      }

      return res.json({ date, userId, inserted });
    } catch (e) {
      console.error('[records/fill-missed] error', e);
      return res.status(500).json({ error: 'internal_error' });
    } finally {
      conn.release();
    }
  });

  return router;
};