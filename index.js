const express = require('express');
const jsonServer = require('json-server');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const DB_PATH = 'db.json';
const SECRET = 'chiave segreta';

const getUsers = function () {
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'))['users'];
};

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return next({ status: 403, message: 'Not authorized!' });

  jwt.verify(token, SECRET, (err, user) => {
    if (err) return next({ status: 403, message: 'Not authorized!' });
    req.body.userId = user.sub;
    next();
  });
}

const app = express();
app.use(express.json());

app.post('/login', (req, res, next) => {
  const users = getUsers();
  const { username, password } = req.body;

  const userFound = users.find(u => u.username === username && u.password === password);
  if (!userFound) {
    return next({ status: 401, message: 'User not found' });
  }
  const token = jwt.sign({ ...userFound, ...{ sub: userFound.id } }, SECRET, { expiresIn: '365d' });
  return res.json({ token });
});

// noinspection JSCheckFunctionSignatures
app.use('/', authenticateToken, jsonServer.router(DB_PATH));

function errorHandler(err, req, res, next) {
  const { message, status } = err;
  res.status(status || 500);
  return res.json({ message });
}

app.use(errorHandler);

app.listen(3000);
