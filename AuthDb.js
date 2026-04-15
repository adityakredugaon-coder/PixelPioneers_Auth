const mysql = require('mysql');

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'pixelpioneers'
});

db.connect((err) => {
  if (err) {
    console.log("❌ Database connection failed", err);
  } else {
    console.log("✅ Database connected");
  }
});

module.exports = db;