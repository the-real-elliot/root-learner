import { drizzle } from "drizzle-orm/node-postgres";
import pg from "pg";
import * as schema from "./schema";

const { Pool } = pg;

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL must be set");
}

export const pool = new Pool({ 
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Retry logic for Render free tier (cold starts)
const connectWithRetry = async (retries = 5) => {
  for (let i = 0; i < retries; i++) {
    try {
      await pool.query('SELECT 1');
      console.log("✅ Database Connected Successfully");
      return;
    } catch (e: any) {
      console.log(`❌ DB Connection Attempt ${i+1}/${retries} failed. Retrying...`);
      if (i === retries - 1) {
        console.error("❌ All DB connection attempts failed:", e.message);
        throw e;
      }
      await new Promise(r => setTimeout(r, 2000 * (i + 1)));
    }
  }
};

// Connect with retry on startup
connectWithRetry().catch(err => {
  console.error("Critical DB failure:", err);
  process.exit(1);
});

export const db = drizzle(pool, { schema });

export * from "./schema";
