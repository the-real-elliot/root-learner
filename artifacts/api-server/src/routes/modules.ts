import { Router } from "express";
import { pool } from "@workspace/db";

const router = Router();

router.get("/modules", async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM modules ORDER BY "order"');
    res.json(result.rows);
  } catch (err: any) {
    console.error("MODULES RAW ERROR:", err.message, err.code, err.detail);
    res.status(500).json({ error: err.message, code: err.code });
  }
});

router.get("/modules/:id", async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: "Invalid id" });
    const mod = await pool.query('SELECT * FROM modules WHERE id = $1', [id]);
    if (!mod.rows[0]) return res.status(404).json({ error: "Not found" });
    const lessons = await pool.query('SELECT * FROM lessons WHERE module_id = $1 ORDER BY "order"', [id]);
    res.json({ ...mod.rows[0], lessons: lessons.rows });
  } catch (err: any) {
    console.error("MODULE DETAIL RAW ERROR:", err.message, err.code);
    res.status(500).json({ error: err.message, code: err.code });
  }
});

export default router;
