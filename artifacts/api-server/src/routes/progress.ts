import { Router } from "express";
import { pool } from "@workspace/db";

const router = Router();

router.get("/progress", async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM progress');
    res.json(result.rows);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/progress", async (req, res) => {
  try {
    const { lessonId } = req.body;
    const result = await pool.query(
      'INSERT INTO progress (lesson_id) VALUES ($1) RETURNING *',
      [lessonId]
    );
    res.json(result.rows[0]);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

export default router;
