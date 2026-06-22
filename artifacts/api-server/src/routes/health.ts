import { Router } from "express";
import { pool } from "@workspace/db";

const router = Router();

router.get("/healthz", async (_req, res) => {
  try {
    const result = await pool.query("SELECT version(), current_database()");
    res.json({ status: "ok", db: result.rows[0] });
  } catch (err: any) {
    res.status(500).json({ status: "error", error: err.message, code: err.code });
  }
});

export default router;
