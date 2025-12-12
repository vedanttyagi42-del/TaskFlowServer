const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const dotenv = require("dotenv");
dotenv.config();
const app = express();
app.use(cors({
  origin: "https://taskflow-pi-sepia.vercel.app",
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));


app.use(express.json());
app.use(cookieParser());
function auth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Not logged in" });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
}
// Postgres connection string from Supabase
const pool = new Pool({
  user: 'postgres',
  host: 'switchback.proxy.rlwy.net',
  database: 'railway',
  password: 'eWQWOEZqwWJBBZgELqWPOvMDUWluUycE',
  port: 15983,
});

// Register user
app.post("/signup", async (req, res) => {
  const { username, display_name, email, password } = req.body;

  try {
    // 1. Check if email already exists
    const existingUser = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({
        success: false,
        message: "Email already registered"
      });
    }

    // 2. Hash the password
    const hash = await bcrypt.hash(password, 10);

    // 3. Insert user
    await pool.query(
      `INSERT INTO users (username, display_name, email, password)
       VALUES ($1, $2, $3, $4)`,
      [username, display_name, email, hash]
    );
    const userResult = await pool.query(
      `SELECT * FROM users WHERE email = $1`,
      [email]
    );
    const user = userResult.rows[0];

    // 4. Create JWT
    const token = jwt.sign(
        {
            id: user.id,
            email: user.email,
            username: user.username,
        },
        process.env.JWT_SECRET
    );

    res.cookie("token", token, {
        httpOnly: true,   // frontend JS cannot read it (more secure)
        secure: true,    // true only in production (HTTPS)
        sameSite: "none",  // or "strict"
    });
    res.json({
      success: true,
      message: "User registered successfully"
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      success: false,
      message: "Server error"
    });
  }
});


// Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const result = await pool.query(
    "SELECT * FROM users WHERE email = $1 LIMIT 1",
    [email]
  );

  if (result.rowCount === 0)
    return res.status(400).json({ error: "User not found" });

  const user = result.rows[0];

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ error: "Invalid password" });

  // Create JWT
  const token = jwt.sign(
    {email: user.email, username: user.username, fullname: user.display_name},
    process.env.JWT_SECRET
  );

  res.cookie("token", token, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
  });

  res.json({ message: "Logged in" });
});

// Protected route
app.get("/me", async (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "Not logged in" });
  const authtoken = jwt.verify(token, process.env.JWT_SECRET);
  const result = await pool.query(
    `SELECT * FROM users WHERE email = $1 LIMIT 1`,
    [authtoken.email]
  );

  if (result.rowCount === 0)
    return res.status(400).json({ error: "User not found" });

  const user = result.rows[0];
  try {
    res.json({ username:user.username, display_name:user.display_name, email:user.email });
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
});
app.post("/tasks", auth, async (req, res) => {
  const { task_name } = req.body;

  const result = await pool.query(
    `INSERT INTO user_tasks (task_name, username, completed, created_at) 
     VALUES ($1, $2, false, NOW())
     RETURNING *`,
    [task_name, req.user.username]
  );

  res.json({ success: true, task: result.rows[0] });
});
async function deleteOldTasks() {
  try {
    await pool.query(
      `DELETE FROM user_tasks 
       WHERE created_at < NOW() - INTERVAL '1 day'`
    );
  } catch (err) {
    console.error("Error deleting old tasks:", err);
  }
}
// GET ALL TASKS FOR USER
app.get("/tasks", auth, async (req, res) => {
  deleteOldTasks();
  const tasks = await pool.query(
    `SELECT * FROM user_tasks WHERE username = $1 ORDER BY created_at DESC`,
    [req.user.username]
  );

  res.json(tasks.rows);
});
// MARK TASK COMPLETE
app.patch("/tasks/:id", auth, async (req, res) => {
  const { id } = req.params;

  const result = await pool.query(
    `UPDATE user_tasks 
     SET completed = NOT completed
     WHERE id = $1 AND username = $2
     RETURNING *`,
    [id, req.user.username]
  );

  if (result.rowCount === 0) {
    return res.status(404).json({ error: "Task not found" });
  }

  res.json({ success: true, task: result.rows[0] });
});
// DELETE TASK
app.delete("/tasks/:id", auth, async (req, res) => {
  try {
    const taskId = req.params.id;

    // Ensure user owns the task
    const result = await pool.query(
      `DELETE FROM user_tasks 
       WHERE id = $1 AND username = $2 
       RETURNING *`,
      [taskId, req.user.username]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Task not found or unauthorized" });
    }

    res.json({ success: true, message: "Task deleted", task: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: true,
    sameSite: "none"
  });

  res.json({ message: "Logged out successfully" });
});
app.listen(5000, () => console.log("Server running on 5000"));
