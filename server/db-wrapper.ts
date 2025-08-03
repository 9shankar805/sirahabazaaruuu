
import { pool } from './db';

export class DatabaseWrapper {
  static async query(text: string, params?: any[], retries = 2): Promise<any> {
    for (let attempt = 1; attempt <= retries + 1; attempt++) {
      try {
        const result = await pool.query(text, params);
        return result;
      } catch (error: any) {
        console.error(`Database query attempt ${attempt} failed:`, error.message);
        
        // Don't retry on syntax errors or similar
        if (error.code === '42601' || error.code === '42P01') {
          throw error;
        }
        
        if (attempt <= retries) {
          const delay = attempt * 1000;
          console.log(`⏳ Retrying query in ${delay}ms...`);
          await new Promise(resolve => setTimeout(resolve, delay));
        } else {
          throw error;
        }
      }
    }
  }

  static async transaction(callback: (client: any) => Promise<any>): Promise<any> {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const result = await callback(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  static async healthCheck(): Promise<boolean> {
    try {
      await this.query('SELECT 1');
      return true;
    } catch (error) {
      console.error('Database health check failed:', error);
      return false;
    }
  }
}

export const db = DatabaseWrapper;
