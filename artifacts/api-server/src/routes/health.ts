import { Router } from 'express';
import { Request, Response } from 'express';

const router = Router();

const healthCheck = (req: Request, res: Response) => {
  res.status(200).json({
    status: "ok",
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    timestamp: new Date().toISOString()
  });
};

router.get('/healthz', healthCheck);
router.get('/api/healthz', healthCheck);   // extra safety

export default router;
