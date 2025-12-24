import express from "express";

export default function patientsRouter(pool) {
  const router = express.Router();

  const one = async (sql, params = []) => {
    const [rows] = await pool.query(sql, params);
    return rows[0] || null;
  };

  router.get("/:id", async (req, res) => {
    const id = Number(req.params.id || 0);
    if (!id) {
      return res.status(400).json({ ok: false, message: "bad_id" });
    }

    try {
      const row = await one(
        `SELECT
           id,
           patient_code,
           name,
           gender,
           birthday,
           phone,
           height_cm,
           weight_kg,
           address,
           allergies,
           medical_history
         FROM patients
         WHERE id = ?
         LIMIT 1`,
        [id]
      );

      if (!row) {
        return res.status(404).json({ ok: false, message: "not_found" });
      }
      return res.json(row);
    } catch (err) {
      console.error("[patients GET /:id error]", err);
      return res
        .status(500)
        .json({ ok: false, message: "server_error", detail: String(err) });
    }
  });


router.put("/:id", async (req, res) => {
  const id = Number(req.params.id || 0);
  if (!id) {
    return res.status(400).json({ ok: false, message: "bad_id" });
  }

  const {
    name,
    gender,     
    birthday,  
    phone,
    height_cm,
    weight_kg,
  } = req.body || {};


  let dbGender = null;
  if (gender != null && gender !== "") {
    const g = String(gender).trim();

    if (["男", "女", "其他"].includes(g)) {
      dbGender = g;
    }
    else if (["male", "female", "other"].includes(g)) {
      const m = { male: "男", female: "女", other: "其他" };
      dbGender = m[g];
    }
    else if (g === "不願透露" || g === "prefer_not_say") {
      dbGender = null;
    } else {
      dbGender = null;
    }
  }

  try {
    const [result] = await pool.query(
      `UPDATE patients
         SET name       = ?,
             gender     = ?,
             birthday   = ?,
             phone      = ?,
             height_cm  = ?,
             weight_kg  = ?,
             updated_at = NOW()
       WHERE id = ?`,
      [
        name ?? null,
        dbGender, 
        birthday || null,
        phone ?? null,
        height_cm != null ? Number(height_cm) : null,
        weight_kg != null ? Number(weight_kg) : null,
        id,
      ]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ ok: false, message: "not_found" });
    }

    return res.json({ ok: true, message: "updated" });
  } catch (err) {
    console.error("[patients PUT /:id error]", err);
    return res
      .status(500)
      .json({ ok: false, message: "update_failed", detail: String(err) });
  }
});

  return router;
}