const express = require("express");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const crypto = require("crypto");
const validator = require("validator");

const app = express();
app.use(express.json()); // Allows JSON input
app.use(cors()); // Enable CORS for all routes

//Connect to PostgreSQL
const pool = new Pool({
  user: "postgres",
  host: "localhost",
  database: "auth_system",
  password: "postgres123",
  port: 5432,
});

const SALT_ROUNDS = 12;
const MAX_FAILED_ATTEMPTS = 5;
const LOCK_TIME_MINUTES = 15;
const JWT_SECRET = "my_super_secret_key"

// Activity Logging Function
async function logActivity(email, action, status, role) {
  await pool.query(
    "INSERT INTO activity_logs (user_email, action, status, role) VALUES ($1, $2, $3, $4)",
    [email, action, status, role]
  );
}

//validate input
function validateEmailAndPassword(email, password) {
  if (!email || !password) {
    return "Email and password are required";
  }

  if (!validator.isEmail(email)) {
    return "Invalid email format";
  }

  if (password.length < 8) {
    return "Password must be at least 8 characters";
  }

  if (!validator.isStrongPassword(password, {
    minLength: 8,
    minLowercase: 1,
    minUppercase: 1,
    minNumbers: 1,
    minSymbols: 1
  })) {
    return "Password must contain uppercase, lowercase, number, and symbol";
  }

  return null; // valid
}

// REGISTER USER
app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    const validationError = validateEmailAndPassword(email, password);
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    //Check if the user already exist already
    const existingUser = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: "Email already registered!!" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // Store in DB
    await pool.query(
      "INSERT INTO users (email, password_hash) VALUES ($1, $2)",
      [email, hashedPassword]
    );

    await logActivity(email, "register", "success", "user");
    res.status(201).json({ message: "User registered successfully" });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Registration failed" });
  }
});

// FORGOT PASSWORD
//Generate reset token and set expiration
app.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    console.log("Forgot request for:", email);

    const user = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [email]
    );

    if (user.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const resetToken = crypto.randomBytes(32).toString("hex");
    const expires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    await pool.query(
      "UPDATE users SET reset_token = $1, reset_token_expires = $2 WHERE email = $3",
      [resetToken, expires, email]
    );
    await logActivity(email, "reset_request", "success", "user");

    res.json({
      message: "Password reset token generated",
      resetToken: resetToken
    });

  } catch (err) {
    console.error("Forgot password error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

//Reset password using token
app.post("/reset-password", async (req, res) => {
  const { token, newPassword } = req.body;

  //validate input
  const validationError = validateEmailAndPassword("test@test.com", newPassword);
  if (validationError) {
    return res.status(400).json({ error: validationError });
  }

  const user = await pool.query(
    "SELECT email FROM users WHERE reset_token = $1 AND reset_token_expires > NOW()",
    [token]
  );

  if (user.rows.length === 0) {
    await logActivity("unknown", "reset", "failed", "user");
    return res.status(400).json({ error: "Invalid or expired token" });
  }

  const hashed = await bcrypt.hash(newPassword, 12);

  await pool.query(
    "UPDATE users SET password_hash = $1, reset_token = NULL, reset_token_expires = NULL WHERE email = $2",
    [hashed, user.rows[0].email]
  );
  await logActivity(user.rows[0].email, "reset", "success", "user");

  res.json({ message: "Password reset successful" });
});


// LOGIN USER 
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Get user from DB
    const result = await pool.query(
      "SELECT password_hash, failed_login_attempts, account_locked_until,role FROM users WHERE email = $1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = result.rows[0];

    // Check if account is locked
    if (user.account_locked_until && new Date() < user.account_locked_until) {
      return res.status(403).json({ error: "Account locked. Try later." });
    }

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password_hash);

    // If password is wrong
    if (!isMatch) {
      const attempts = user.failed_login_attempts + 1;
      await logActivity(email, "login", "failed", user.role);

      // Lock account if max attempts reached
      if (attempts >= MAX_FAILED_ATTEMPTS) {
        const lockUntil = new Date();
        lockUntil.setMinutes(lockUntil.getMinutes() + LOCK_TIME_MINUTES);

        await pool.query(
          "UPDATE users SET failed_login_attempts = 0, account_locked_until = $1 WHERE email = $2",
          [lockUntil, email]
        );

        await logActivity(email, "login", "locked", user.role);
        return res.status(403).json({
          error: "Account locked due to multiple failed attempts"
        });
      }

      // Just update attempts
      await pool.query(
        "UPDATE users SET failed_login_attempts = $1 WHERE email = $2",
        [attempts, email]
      );

      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Successful login 
    await pool.query(
      "UPDATE users SET failed_login_attempts = 0, account_locked_until = NULL WHERE email = $1",
      [email]
    );
    await logActivity(email, "login", "success", user.role);

    const accessToken = jwt.sign(
      { email: email, role: user.role },
      JWT_SECRET,
      { expiresIn: "15m" }
    );

    const refreshToken = crypto.randomBytes(64).toString("hex");

    const refreshExpires = new Date();
    refreshExpires.setDate(refreshExpires.getDate() + 7);

    await pool.query(
      "UPDATE users SET refresh_token = $1, refresh_token_expires = $2 WHERE email = $3",
      [refreshToken, refreshExpires, email]
    );

    res.json({
      message: "Login successful",
      accessToken,
      refreshToken
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Login failed" });
  }
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Token missing" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Invalid token" });
    }

    req.user = user;
    next();
  });
}

app.post("/refresh-token", async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).json({ error: "Refresh token missing" });
  }

  const result = await pool.query(
    "SELECT email, role FROM users WHERE refresh_token = $1 AND refresh_token_expires > NOW()",
    [refreshToken]
  );

  if (result.rows.length === 0) {
    return res.status(403).json({ error: "Invalid refresh token" });
  }

  const user = result.rows[0];

  const newAccessToken = jwt.sign(
    { email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: "15m" }
  );

  res.json({ accessToken: newAccessToken });
});

app.get("/profile", authenticateToken, (req, res) => {
  res.json({
    message: "Welcome to your profile",
    user: req.user
  });
});

function authorizeRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({ error: "Access denied" });
    }
    next();
  };
}

app.get(
  "/admin",
  authenticateToken,
  authorizeRole("admin"),
  (req, res) => {
    res.json({ message: "Welcome Admin" });
  }
);

app.get("/admin/users", authenticateToken, authorizeRole("admin"), async (req, res) => {
  const users = await pool.query(
    "SELECT email, role FROM users ORDER BY email"
  );
  await logActivity(req.user.email, "admin_view", "success", "admin");
  res.json(users.rows);
});

app.get("/admin/logs", authenticateToken, authorizeRole("admin"), async (req, res) => {
  const limit = parseInt(req.query.limit) || 50;

  const logs = await pool.query(
    "SELECT user_email, action, status, role, created_at FROM activity_logs ORDER BY created_at DESC LIMIT $1",
    [limit]
  );

  res.json(logs.rows);
});

app.post("/logout", authenticateToken, async (req, res) => {
  await pool.query(
    "UPDATE users SET refresh_token = NULL, refresh_token_expires = NULL WHERE email = $1",
    [req.user.email]
  );

  res.json({ message: "Logged out securely" });
});

// START SERVER
app.listen(3000, () => {
  console.log("Server running on port 3000");
});
