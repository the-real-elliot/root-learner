import { drizzle } from "drizzle-orm/node-postgres";
import pg from "pg";
import * as schema from "./schema";

const { Pool } = pg;

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL must be set");
}

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' 
    ? { rejectUnauthorized: false } 
    : false,
  max: 5,
  idleTimeoutMillis: 30000,
});

const connectWithRetry = async () => {
  for (let i = 0; i < 6; i++) {
    try {
      await pool.query('SELECT 1');
      console.log("✅ Database Connected Successfully");
      return true;
    } catch (err: any) {
      console.error(`DB Attempt ${i+1}/6 failed:`, err.message);
      if (i === 5) throw err;
      await new Promise(r => setTimeout(r, 1500 * (i + 1)));
    }
  }
};

connectWithRetry().catch(err => {
  console.error("❌ Critical: Failed to connect to database", err);
});

export const db = drizzle(pool, { schema });

export * from "./schema";
