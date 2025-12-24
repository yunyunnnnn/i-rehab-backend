const mysql = require('mysql2/promise');
require('dotenv').config();

const base = {
  host: 'localhost',
  user: process.env.DB_USER || 'root',
  database: 'irehab',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
};

if (process.env.DB_PASSWORD && process.env.DB_PASSWORD.length > 0) {
  base.password = process.env.DB_PASSWORD;
}

console.log('[DB] connecting as user =', base.user);

const pool = mysql.createPool(base);
module.exports = { pool };