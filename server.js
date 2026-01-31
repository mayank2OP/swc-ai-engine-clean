import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";

dotenv.config();
const app = express();

/* =====================================================
   BASIC MIDDLEWARE
===================================================== */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/* =====================================================
   VIEW ENGINE
===================================================== */
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

/* =====================================================
   STATIC FILES
===================================================== */
app.use(express.static(path.join(__dirname, "public")));

/* =====================================================
   NO CACHE (SECURITY)
===================================================== */
app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
});

/* =====================================================
   AUTH MIDDLEWARE
===================================================== */
function requireAuth(req, res, next) {
  if (!req.cookies.token) {
    return res.redirect("/login");
  }
  next();
}

/* =====================================================
   ROUTES
===================================================== */

/* ---------- ROOT ---------- */
app.get("/", (req, res) => {
  res.redirect("/login");
});

app.get("/dashboard", (req, res) => {
  const token = req.headers.cookie || "";

  // Optional: block access if no token
  res.render("dashboard");
});

/* ---------- LOGIN ---------- */
app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

app.get("/", (req, res) => {
  res.render("index"); // MAIN LANDING PAGE
});

app.post("/login", async (req, res) => {
  try {
    const r = await fetch(`${process.env.SPRING_API_BASE}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(req.body)
    });

    if (!r.ok) {
      return res.render("login", { error: "Invalid credentials" });
    }

    const data = await r.json();

    res.cookie("token", data.token, {
      httpOnly: true,
      sameSite: "lax"
    });

    res.redirect("/dss");
  } catch (err) {
    res.render("login", { error: "Login failed" });
  }
});

/* ---------- REGISTER ---------- */
app.get("/register", (req, res) => {
  res.render("register", { error: null });
});

app.post("/register", async (req, res) => {
  try {
    const r = await fetch(`${process.env.SPRING_API_BASE}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(req.body)
    });

    if (!r.ok) {
      return res.render("register", { error: await r.text() });
    }

    res.redirect("/login");
  } catch {
    res.render("register", { error: "Registration failed" });
  }
});

/* ---------- OAUTH CALLBACK ---------- */
app.get("/oauth-success", (req, res) => {
  if (!req.query.token) return res.redirect("/login");

  res.cookie("token", req.query.token, {
    httpOnly: true,
    sameSite: "lax"
  });

  res.redirect("/dss");
});

/* ---------- LOGOUT ---------- */
app.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/login");
});

/* ---------- DSS MAIN PAGE ---------- */
app.get("/dss", requireAuth, (req, res) => {
  res.render("index");
});

/* ---------- BLOCK DIRECT RESULT ACCESS ---------- */
app.get("/result", requireAuth, (req, res) => {
  res.redirect("/dss");
});

/* =====================================================
   🔥 ANALYSIS PIPELINE (FINAL & CORRECT)
   Frontend → Spring Boot → Python → Render result.ejs
===================================================== */
app.post("/analyze", requireAuth, async (req, res) => {
  try {
    const r = await fetch(`${process.env.SPRING_API_BASE}/api/predict`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${req.cookies.token}`
      },
      body: JSON.stringify(req.body)
    });

    if (!r.ok) {
      throw new Error("Prediction API failed");
    }

    const data = await r.json();

    res.render("result", {
      erosionRisk: data.erosion_risk ?? null,
      factorsData: data.factors ?? {},
      recommendations:
        data.mechanical_measures?.measures ??
        data.recommendations ??
        [],
      reason: data.reason ?? null
    });

  } catch (err) {
    console.error("ANALYSIS ERROR:", err);

    res.render("result", {
      erosionRisk: null,
      factorsData: {},
      recommendations: [],
      reason: "Backend communication failed"
    });
  }
});

/* =====================================================
   START SERVER
===================================================== */
app.listen(3000, () => {
  console.log("✅ Frontend running at http://localhost:3000");
});
