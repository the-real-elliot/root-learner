import { Router } from "express";
import { pool } from "@workspace/db";

const router = Router();

const HACKER_TIPS = [
  { title: "Recon First", description: "Always enumerate before you exploit." },
  { title: "Know Your Tools", description: "nmap -sV reveals service versions." },
  { title: "Document Everything", description: "Real pentesters document every step." },
  { title: "Understand the Target", description: "Study the target before touching it." },
  { title: "Privilege Escalation", description: "linpeas.sh and winpeas.exe are your best friends." },
  { title: "OSINT is Underrated", description: "Shodan and theHarvester are essentials." },
  { title: "Burp Suite Mastery", description: "Learn the Repeater and Intruder tabs first." },
];

router.get("/stats", async (req, res) => {
  try {
    const lessons = await pool.query('SELECT COUNT(*) FROM lessons');
    const modules = await pool.query('SELECT COUNT(*) FROM modules');
    const progress = await pool.query('SELECT * FROM progress');
    res.json({
      totalLessons: parseInt(lessons.rows[0].count),
      completedLessons: progress.rows.length,
      totalModules: parseInt(modules.rows[0].count),
      completedModules: 0,
      totalHours: 0,
      currentStreak: 0,
      level: "Hacker",
      xp: progress.rows.length * 100,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/feed", async (req, res) => {
  try {
    const tipIdx = Math.floor(Date.now() / 3600000) % HACKER_TIPS.length;
    const tip = HACKER_TIPS[tipIdx];
    res.json([{
      id: 9000 + tipIdx,
      type: "tip",
      title: tip.title,
      description: tip.description,
      timestamp: new Date().toISOString(),
      lessonId: null,
    }]);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

export default router;
