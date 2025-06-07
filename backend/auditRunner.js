// routes/audit.js — ESM version for Express
import express from 'express';
import { exec } from 'child_process';
import authRoutes from './auth.js';
import { runAudit, generateSummary } from '../routes/auditRunner.js'; // adjust path if needed

const router = express.Router();

router.post('/run', authenticateToken, requireAdmin, async (req, res) => {
  const { url, clientEmail, automated = false, durationHours = 24 } = req.body;

  if (!url) return res.status(400).json({ error: 'URL is required' });

  const command = `python3 scripts/audit_runner.py "${url}" ${clientEmail || ''} ${automated} ${durationHours}`;

  exec(command, (err, stdout, stderr) => {
    if (err) {
      console.error(`❌ Error running audit:`, err);
      return res.status(500).json({ error: 'Audit failed to start' });
    }

    console.log(`✅ Audit triggered for ${url}`);
    return res.json({
      message: 'Audit started successfully',
      logs: stdout
    });
  });
});

export default router;
