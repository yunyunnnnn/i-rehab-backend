const express = require('express');
const router = express.Router();
const { pool } = require('../db');


router.get('/exercises', async (req, res) => {
  const { slug, area, task } = req.query;

  const toArray = (v) => {
    try {
      if (Array.isArray(v)) return v;
      if (v == null) return [];
      if (Buffer.isBuffer(v)) v = v.toString('utf8');

      if (typeof v === 'string') {
        const s = v.trim();
        if (!s) return [];
        if ((s.startsWith('[') && s.endsWith(']')) || (s.startsWith('{') && s.endsWith('}'))) {
          try { return JSON.parse(s); } catch {}
          try { return JSON.parse(s.replace(/'/g, '"')); } catch {}
        }
        if (s.includes('、') || s.includes(',')) {
          return s.split(/[、,]/).map(x => x.trim()).filter(Boolean);
        }
        return [s];
      }
      if (typeof v === 'object') {
        return Array.isArray(v) ? v : [String(v)];
      }
      return [String(v)];
    } catch {
      return [];
    }
  };

  try {
    let sql = `
      SELECT
        e.*,
        COALESCE(
          JSON_UNQUOTE(JSON_EXTRACT(e.steps_json, '$')),
          CAST(e.steps_json AS CHAR),
          '[]'
        ) AS steps_raw,
        COALESCE(
          JSON_UNQUOTE(JSON_EXTRACT(e.precautions_json, '$')),
          CAST(e.precautions_json AS CHAR),
          '[]'
        ) AS precautions_raw
      FROM exercises e
      WHERE 1=1
    `;
    const params = [];
    if (slug) { sql += ' AND e.slug=?'; params.push(slug); }
    if (area) { sql += ' AND e.area=?'; params.push(area); }
    if (task) { sql += ' AND e.task=?'; params.push(task); }
    sql += ' LIMIT 1';

    const [rows] = await pool.execute(sql, params);
    if (!rows.length) {
      return res.status(404).json({ error: 'exercise_not_found' });
    }

    const row = rows[0];

    const steps = toArray(row.steps_raw ?? row.steps_json ?? '[]');
    const precautions = toArray(row.precautions_raw ?? row.precautions_json ?? '[]');

    res.json({
      id: row.id,
      slug: row.slug,
      area: row.area,
      task: row.task,
      level: row.level,

      duration_min: row.duration_min,
      durationMin: row.duration_min,

      video_url: row.video_url,
      videoUrl: row.video_url,

      intro: row.intro || '',
      goals: row.goals || '',
      intensity: row.intensity || '',
      frequency: row.frequency || '',

      steps,
      precautions,

      // for debugging
      steps_json: row.steps_json ?? null,
      precautions_json: row.precautions_json ?? null,
    });
  } catch (e) {
    console.error('GET /exercises error', e);
    res.status(500).json({ error: 'db_error' });
  }
});

module.exports = router;