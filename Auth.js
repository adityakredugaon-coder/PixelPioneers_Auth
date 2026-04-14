const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const db = require('./AuthDb');
const app = express();
app.use(express.json());
app.use(cors());

///////////// Register User /////////////////////////////

app.post('/register', async (req, res) => {
  const { name, email, phone, password } = req.body;

  const checkSql = "SELECT * FROM users WHERE email = ?";
  db.query(checkSql, [email], async (err, result) => {

    if (result.length > 0) {
      return res.send("Email already exists");
    }


    const insertSql = "INSERT INTO users (name, email, phone, password) VALUES (?, ?, ?, ?)";

    db.query(insertSql, [name, email, phone, password], (err, result) => {
      if (err) return res.send(err);

      res.send("User Registered Successfully");
    });
  });
});


/////// Login User /////////////////////

app.post('/login', (req, res) => {
  const { email, password } = req.body;

  const sql = "SELECT * FROM users WHERE email = ?";
  db.query(sql, [email], async (err, results) => {

    if (results.length === 0) {
      return res.send("User not found");
    }

    const user = results[0];

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.send("Wrong Password");
    }

    const token = jwt.sign({ id: user.id }, "secretkey", {
      expiresIn: "1h"
    });

    res.send({
      message: "Login Successful",
      token: token
    });
  });
});

/////// get All Users ////////////

app.get('/users', (req, res) => {``
  const sql = "SELECT * FROM users"

  db.query(sql, (err, results) => {
    if (err) return res.send(err);

    res.status(200).json({
      message: "Users Get Successfully",
      data: results
    })
  })
})

app.listen(3000, () => {
  console.log("Server running on port 3000");
});