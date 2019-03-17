const crypto = require("crypto");
const express = require("express");
const session = require("express-session");
const cors = require("cors");
const bodyParser = require("body-parser");
const Joi = require("joi");
const LRU = require("lru-cache");

const tokenCache = new LRU({
  max: 100,
  maxAge: 1000 * 30
});

function generateRandomToken() {
  return new Promise((resolve, reject) => {
    crypto.randomBytes(24, function(err, buffer) {
      if (err) {
        return reject(err);
      }

      resolve(buffer.toString("hex"));
    });
  });
}

const USERS = [
  {
    name: "Bob",
    email: "bob@example.com",
    password: "bob123"
  },
  {
    name: "Alice",
    email: "bob@example.com",
    password: "alice123"
  },
  {
    name: "Eve",
    email: "eve@example.com",
    password: "eve123"
  }
];

const authSchema = Joi.object().keys({
  email: Joi.string()
    .email({ minDomainAtoms: 2 })
    .required(),
  password: Joi.string().required()
});

const app = express();

app.use(cors());

app.use(bodyParser.json());

app.use((req, res, next) => {
  const authHeader = req.header("Authorization");

  if (!authHeader) {
    return next();
  }

  const parts = authHeader
    .trim()
    .toLowerCase()
    .split(" ");

  if (parts.length === 2 && parts[0] === "bearer") {
    req.token = parts[1] || null;
  }

  next();
});

app.get("/", (req, res) => {
  res.send("hello");
});

app.post("/auth", async (req, res) => {
  const result = Joi.validate(req.body, authSchema);

  if (result.error) {
    return res.status(400).json({
      status: "error",
      message: "invalid parameters"
    });
  }

  const { email, password } = req.body;

  const user = USERS.find(user => user.email === email);

  const loginSuccess = user && user.password === password;

  if (!loginSuccess) {
    return res.status(401).json({
      status: "error",
      message: "email or password is incorrect"
    });
  }

  try {
    const token = await generateRandomToken();

    tokenCache.set(token, email);

    res.json({
      status: "success",
      message: "login successful",
      token
    });
  } catch (err) {
    res.status(500).json({
      status: "error",
      message: "unable to generate token"
    });
  }
});

app.get("/me", (req, res) => {
  if (!req.token) {
    return res.status(401).json({
      status: "error",
      message: "token missing"
    });
  }

  if (!tokenCache.has(req.token)) {
    return res.status(401).json({
      status: "error",
      message: "token expired"
    });
  }

  const email = tokenCache.get(req.token);

  const user = USERS.find(x => x.email === email);

  if (!user) {
    return res.status(401).json({
      status: "error",
      message: "token invalid"
    });
  }

  const { password, ...userWithoutPassword } = user;

  res.json({
    status: "success",
    profile: userWithoutPassword
  });
});

app.listen(3000, () => console.log("Listening on port 3000"));
