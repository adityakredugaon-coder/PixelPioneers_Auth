const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const db = require('./AuthDb');

const app = express();
app.use(express.json());
app.use(cors());

//////////////// REGISTER ////////////////////
app.post('/register', async (req, res) => {
  const { name, email, phone, password } = req.body;

  const checkSql = "SELECT * FROM users WHERE email = ?";
  db.query(checkSql, [email], async (err, result) => {
    if (err) return res.status(500).send(err);

    if (result.length > 0) {
      return res.status(400).send("Email already exists");
    }

    try {
      // 🔐 Password hash
      const hashedPassword = await bcrypt.hash(password, 10);

      const insertSql =
        "INSERT INTO users (name, email, phone, password) VALUES (?, ?, ?, ?)";

      db.query(
        insertSql,
        [name, email, phone, hashedPassword],
        (err, result) => {
          if (err) return res.status(500).send(err);

          res.send("User Registered Successfully");
        }
      );
    } catch (error) {
      res.status(500).send(error);
    }
  });
});

//////////////// LOGIN ////////////////////
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  const sql = "SELECT * FROM users WHERE email = ?";
  db.query(sql, [email], async (err, results) => {
    if (err) return res.status(500).send(err);

    if (results.length === 0) {
      return res.send("User not found");
    }

    const user = results[0];

    try {
      const match = await bcrypt.compare(password, user.password);

      if (!match) {
        return res.send("Wrong Password");
      }

      const token = jwt.sign({ id: user.id }, "secretkey", {
        expiresIn: "1h",
      });

      res.send({
        message: "Login Successful",
        token: token,
      });
    } catch (error) {
      res.status(500).send(error);
    }
  });
});

//////////////// GET USERS ////////////////////
app.get('/users', (req, res) => {
  const sql = "SELECT * FROM users";

  db.query(sql, (err, results) => {
    if (err) return res.status(500).send(err);

    res.json({
      message: "Users Get Successfully",
      data: results,
    });
  });
});

//////////////// SERVER ////////////////////
const PORT = 3000;

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});