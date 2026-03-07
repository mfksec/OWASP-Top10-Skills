// vulnerable example for injection testing
const express = require('express');
const app = express();

app.get('/user', (req, res) => {
  // unsafe concatenation
  const q = "SELECT * FROM users WHERE id = " + req.query.id;
  db.query(q, (err, rows) => {
    res.json(rows);
  });
});
