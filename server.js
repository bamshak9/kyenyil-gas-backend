/* =============================================
   KYENYIL GAS — ORDER BACKEND
   File: server.js

   What this does:
   1. Accepts order submissions from purchase.js (POST /api/orders)
   2. Validates them on the server (never trust the browser alone)
   3. Saves them into a SQLite file (data/orders.db) that persists
      between restarts as long as it's on a persistent disk
   4. Lets you view all orders at /admin (password protected)
   ============================================= */

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const path = require("path");
const Database = require("better-sqlite3");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "changeme";

// ---------------------------------------------
// ALLOWED ORIGINS
// Add the URL(s) where your website is hosted.
// You can set this via the ALLOWED_ORIGINS env var
// as a comma-separated list, e.g.
//   ALLOWED_ORIGINS=https://kyenyilgas.com,https://www.kyenyilgas.com
// If not set, all origins are allowed (fine for testing,
// tighten it before going fully live).
// ---------------------------------------------
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(",").map((s) => s.trim())
  : null;

app.use(
  cors({
    origin: function (origin, callback) {
      if (!allowedOrigins || !origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      return callback(new Error("Not allowed by CORS"));
    },
  })
);

app.use(express.json({ limit: "100kb" }));

// ---------------------------------------------
// DATABASE SETUP
// ---------------------------------------------
const DB_PATH = path.join(__dirname, "data", "orders.db");
const db = new Database(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS orders (
    id              TEXT PRIMARY KEY,
    cylinderSize    TEXT,
    isCustomSize    INTEGER,
    customSizeNote  TEXT,
    quantity        INTEGER,
    cylinderType    TEXT,
    firstName       TEXT,
    lastName        TEXT,
    phone           TEXT,
    address         TEXT,
    area            TEXT,
    deliveryDate    TEXT,
    notes           TEXT,
    paymentMethod   TEXT,
    status          TEXT,
    createdAt       TEXT
  )
`);

// ---------------------------------------------
// RATE LIMITING — prevents someone from spamming
// your order endpoint with thousands of fake orders.
// ---------------------------------------------
const orderLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // max 20 order attempts per IP per window
  message: { message: "Too many orders submitted. Please try again later." },
});

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: { message: "Too many attempts. Please try again later." },
});

// ---------------------------------------------
// VALIDATION HELPERS
// Mirrors the rules already in purchase.js, but
// enforced server-side since client-side validation
// can always be bypassed.
// ---------------------------------------------
const VALID_SIZES = ["1kg", "2kg", "5kg", "12.5kg", "25kg", "50kg", "custom"];
const VALID_TYPES = ["refill", "new"];
const VALID_PAYMENT = ["cash", "transfer"];

function validateOrder(body) {
  const errors = [];

  if (!body.cylinderType || !VALID_TYPES.includes(body.cylinderType)) {
    errors.push("Invalid or missing cylinder action.");
  }

  const qty = Number(body.quantity);
  if (!Number.isInteger(qty) || qty < 1 || qty > 20) {
    errors.push("Quantity must be a whole number between 1 and 20.");
  }

  if (!body.firstName || !String(body.firstName).trim()) {
    errors.push("First name is required.");
  }
  if (!body.lastName || !String(body.lastName).trim()) {
    errors.push("Last name is required.");
  }
  if (!body.address || !String(body.address).trim()) {
    errors.push("Delivery address is required.");
  }
  if (!body.area || !String(body.area).trim()) {
    errors.push("Delivery area is required.");
  }

  const phone = String(body.phone || "").replace(/\s/g, "");
  if (!/^[0-9]{10,14}$/.test(phone)) {
    errors.push("A valid phone number (10–14 digits) is required.");
  }

  if (!body.deliveryDate || isNaN(new Date(body.deliveryDate).getTime())) {
    errors.push("A valid delivery date is required.");
  } else {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const chosen = new Date(body.deliveryDate);
    if (chosen < today) {
      errors.push("Delivery date cannot be in the past.");
    }
  }

  if (!body.paymentMethod || !VALID_PAYMENT.includes(body.paymentMethod)) {
    errors.push("Invalid or missing payment method.");
  }

  // Cylinder size: either one of the fixed sizes, or "custom" with a
  // valid customSizeKg value baked into cylinderSize by the front end
  // (e.g. "3 kg (custom)"). We just check it's a non-empty string here
  // since the front end formats it before sending.
  if (!body.cylinderSize || !String(body.cylinderSize).trim()) {
    errors.push("Cylinder size is required.");
  }

  return errors;
}

function escapeHtml(str) {
  return String(str ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[c]));
}

// ---------------------------------------------
// ROUTES
// ---------------------------------------------

// Health check — useful to confirm the server is alive
app.get("/", (req, res) => {
  res.json({ status: "ok", service: "Kyenyil Gas backend" });
});

// Create a new order
app.post("/api/orders", orderLimiter, (req, res) => {
  try {
    const errors = validateOrder(req.body);
    if (errors.length > 0) {
      return res.status(400).json({ message: errors.join(" ") });
    }

    const id = "KG-" + Date.now() + "-" + crypto.randomBytes(3).toString("hex").toUpperCase();

    const stmt = db.prepare(`
      INSERT INTO orders (
        id, cylinderSize, isCustomSize, customSizeNote, quantity, cylinderType,
        firstName, lastName, phone, address, area, deliveryDate, notes,
        paymentMethod, status, createdAt
      ) VALUES (
        @id, @cylinderSize, @isCustomSize, @customSizeNote, @quantity, @cylinderType,
        @firstName, @lastName, @phone, @address, @area, @deliveryDate, @notes,
        @paymentMethod, @status, @createdAt
      )
    `);

    stmt.run({
      id,
      cylinderSize: String(req.body.cylinderSize || ""),
      isCustomSize: req.body.isCustomSize ? 1 : 0,
      customSizeNote: String(req.body.customSizeNote || ""),
      quantity: Number(req.body.quantity),
      cylinderType: String(req.body.cylinderType || ""),
      firstName: String(req.body.firstName || "").trim(),
      lastName: String(req.body.lastName || "").trim(),
      phone: String(req.body.phone || "").trim(),
      address: String(req.body.address || "").trim(),
      area: String(req.body.area || "").trim(),
      deliveryDate: String(req.body.deliveryDate || ""),
      notes: String(req.body.notes || "").trim(),
      paymentMethod: String(req.body.paymentMethod || ""),
      status: "pending",
      createdAt: new Date().toISOString(),
    });

    res.status(201).json({ message: "Order received", orderId: id });
  } catch (err) {
    console.error("Error saving order:", err);
    res.status(500).json({ message: "Server error. Please try again." });
  }
});

// ---------------------------------------------
// ADMIN — view orders
// Visit /admin in your browser, enter the password
// you set as ADMIN_PASSWORD, and see every order.
// This uses simple HTTP Basic Auth.
// ---------------------------------------------
function requireAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Basic ")) {
    res.set("WWW-Authenticate", 'Basic realm="Kyenyil Admin"');
    return res.status(401).send("Authentication required.");
  }
  const decoded = Buffer.from(authHeader.split(" ")[1], "base64").toString();
  const [, password] = decoded.split(":");
  if (password !== ADMIN_PASSWORD) {
    res.set("WWW-Authenticate", 'Basic realm="Kyenyil Admin"');
    return res.status(401).send("Invalid password.");
  }
  next();
}

app.get("/admin", adminLimiter, requireAdmin, (req, res) => {
  const orders = db
    .prepare("SELECT * FROM orders ORDER BY createdAt DESC")
    .all();

  const rows = orders
    .map(
      (o) => `
    <tr>
      <td>${escapeHtml(o.id)}</td>
      <td>${escapeHtml(o.createdAt)}</td>
      <td>${escapeHtml(o.firstName)} ${escapeHtml(o.lastName)}</td>
      <td>${escapeHtml(o.phone)}</td>
      <td>${escapeHtml(o.cylinderSize)}${o.isCustomSize && o.customSizeNote ? " — " + escapeHtml(o.customSizeNote) : ""}</td>
      <td>${escapeHtml(o.quantity)}</td>
      <td>${escapeHtml(o.cylinderType)}</td>
      <td>${escapeHtml(o.address)}, ${escapeHtml(o.area)}</td>
      <td>${escapeHtml(o.deliveryDate)}</td>
      <td>${escapeHtml(o.paymentMethod)}</td>
      <td>${escapeHtml(o.notes)}</td>
      <td><span class="badge badge-${escapeHtml(o.status)}">${escapeHtml(o.status)}</span></td>
    </tr>`
    )
    .join("");

  res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>Kyenyil Gas — Orders</title>
<style>
  body { font-family: -apple-system, Arial, sans-serif; background: #f5f2f2; padding: 2rem; color: #3c3232; }
  h1 { margin-bottom: 0.25rem; }
  p.sub { color: #756; margin-bottom: 1.5rem; color: #696060;}
  table { width: 100%; border-collapse: collapse; background: #fff; box-shadow: 0 2px 12px rgba(0,0,0,0.08); border-radius: 8px; overflow: hidden; }
  th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #eee; font-size: 0.85rem; vertical-align: top; }
  th { background: rgb(105,94,94); color: #fff; position: sticky; top: 0; }
  tr:hover { background: #faf8f8; }
  .badge { padding: 3px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 600; }
  .badge-pending { background: #fde7d2; color: #a05500; }
  .badge-confirmed { background: #d2f0e0; color: #0a7a4f; }
  .badge-cancelled { background: #f8d4d4; color: #a02020; }
  .count { font-weight: 600; }
  .wrap { overflow-x: auto; }
</style>
</head>
<body>
  <h1>🔥 Kyenyil Gas — Orders</h1>
  <p class="sub"><span class="count">${orders.length}</span> total order(s). Refresh this page to see new orders.</p>
  <div class="wrap">
  <table>
    <thead>
      <tr>
        <th>Order ID</th><th>Placed</th><th>Customer</th><th>Phone</th>
        <th>Cylinder</th><th>Qty</th><th>Action</th><th>Delivery to</th>
        <th>Pref. date</th><th>Payment</th><th>Notes</th><th>Status</th>
      </tr>
    </thead>
    <tbody>
      ${rows || '<tr><td colspan="12" style="text-align:center;color:#999;">No orders yet.</td></tr>'}
    </tbody>
  </table>
  </div>
</body>
</html>
  `);
});

// Optional: raw JSON of all orders, useful if you ever want to
// export or pipe into a spreadsheet.
app.get("/admin/orders.json", adminLimiter, requireAdmin, (req, res) => {
  const orders = db
    .prepare("SELECT * FROM orders ORDER BY createdAt DESC")
    .all();
  res.json(orders);
});

app.listen(PORT, () => {
  console.log(`Kyenyil Gas backend running on port ${PORT}`);
});
