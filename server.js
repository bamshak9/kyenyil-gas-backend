/* =============================================
   KYENYIL GAS — ORDER BACKEND
   File: server.js

   What this does:
   1. Accepts order submissions from purchase.js (POST /api/orders)
   2. Validates them on the server (never trust the browser alone)
   3. Saves them into a JSON file (data/orders.json) that persists
      between restarts as long as it's on a persistent disk
   4. Lets you view all orders at /admin (password protected)

   Storage note: orders are stored as plain JSON rather than a
   SQL database. This avoids any native module / Node-version
   compilation issues on hosts like Render, at the cost of being
   a little less efficient at very large scale — which is not a
   concern for an order volume like this.
   ============================================= */

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
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
// STORAGE SETUP — plain JSON file
// ---------------------------------------------
const DATA_DIR = path.join(__dirname, "data");
const DB_PATH = path.join(DATA_DIR, "orders.json");

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}
if (!fs.existsSync(DB_PATH)) {
  fs.writeFileSync(DB_PATH, "[]", "utf8");
}

// Simple in-process lock so two requests arriving at the exact
// same moment can't both read-modify-write and clobber each other.
let writeQueue = Promise.resolve();

function readOrders() {
  try {
    const raw = fs.readFileSync(DB_PATH, "utf8");
    return JSON.parse(raw || "[]");
  } catch (err) {
    console.error("Error reading orders file, starting fresh:", err);
    return [];
  }
}

function appendOrder(order) {
  // Queue writes so they always happen one at a time, in order.
  // We chain off writeQueue but always resolve it (via .catch(()=>{})
  // for the shared chain) so one failed write never blocks every
  // write that comes after it — the caller of THIS function still
  // gets the real success/failure via the returned promise.
  const result = writeQueue.then(() => {
    const orders = readOrders();
    orders.push(order);
    fs.writeFileSync(DB_PATH, JSON.stringify(orders, null, 2), "utf8");
  });
  writeQueue = result.catch(() => {});
  return result;
}

const VALID_STATUSES = ["pending", "confirmed", "cancelled"];

function updateOrderStatus(orderId, newStatus) {
  const result = writeQueue.then(() => {
    const orders = readOrders();
    const order = orders.find((o) => o.id === orderId);
    if (!order) {
      throw new Error("Order not found");
    }
    order.status = newStatus;
    fs.writeFileSync(DB_PATH, JSON.stringify(orders, null, 2), "utf8");
  });
  writeQueue = result.catch(() => {});
  return result;
}

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
app.post("/api/orders", orderLimiter, async (req, res) => {
  try {
    const errors = validateOrder(req.body);
    if (errors.length > 0) {
      return res.status(400).json({ message: errors.join(" ") });
    }

    const id = "KG-" + Date.now() + "-" + crypto.randomBytes(3).toString("hex").toUpperCase();

    const order = {
      id,
      cylinderSize: String(req.body.cylinderSize || ""),
      isCustomSize: !!req.body.isCustomSize,
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
    };

    await appendOrder(order);

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
  const orders = readOrders().slice().sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));

  const rows = orders
    .map(
      (o) => `
    <tr data-order-id="${escapeHtml(o.id)}">
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
      <td>
        <span class="badge badge-${escapeHtml(o.status)} status-label">${escapeHtml(o.status)}</span>
        <div class="status-actions">
          <button class="status-btn confirm" data-status="confirmed" ${o.status === "confirmed" ? "disabled" : ""}>Mark Confirmed</button>
          <button class="status-btn cancel" data-status="cancelled" ${o.status === "cancelled" ? "disabled" : ""}>Mark Cancelled</button>
          <button class="status-btn reset" data-status="pending" ${o.status === "pending" ? "disabled" : ""}>Reset to Pending</button>
        </div>
      </td>
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
  .badge { padding: 3px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 600; display: inline-block; margin-bottom: 6px; }
  .badge-pending { background: #fde7d2; color: #a05500; }
  .badge-confirmed { background: #d2f0e0; color: #0a7a4f; }
  .badge-cancelled { background: #f8d4d4; color: #a02020; }
  .count { font-weight: 600; }
  .wrap { overflow-x: auto; }
  .status-actions { display: flex; flex-direction: column; gap: 4px; min-width: 140px; }
  .status-btn { font-size: 0.72rem; padding: 4px 8px; border-radius: 5px; border: 1px solid #ddd; background: #fafafa; cursor: pointer; text-align: left; transition: background 0.15s ease; }
  .status-btn:hover:not(:disabled) { background: #eee; }
  .status-btn:disabled { opacity: 0.4; cursor: default; }
  .status-btn.confirm { color: #0a7a4f; }
  .status-btn.cancel { color: #a02020; }
  .status-btn.reset { color: #555; }
  .toast { position: fixed; bottom: 20px; right: 20px; background: #333; color: #fff; padding: 10px 18px; border-radius: 6px; font-size: 0.85rem; opacity: 0; transition: opacity 0.3s ease; pointer-events: none; }
  .toast.show { opacity: 1; }
</style>
</head>
<body>
  <h1>🔥 Kyenyil Gas — Orders</h1>
  <p class="sub"><span class="count">${orders.length}</span> total order(s). Click a button below to update an order's status — no refresh needed.</p>
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
  <div class="toast" id="toast"></div>

  <script>
    function showToast(msg, isError) {
      const toast = document.getElementById('toast');
      toast.textContent = msg;
      toast.style.background = isError ? '#a02020' : '#333';
      toast.classList.add('show');
      setTimeout(() => toast.classList.remove('show'), 2500);
    }

    document.querySelectorAll('.status-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        const row = btn.closest('tr');
        const orderId = row.getAttribute('data-order-id');
        const newStatus = btn.getAttribute('data-status');

        btn.disabled = true;
        btn.textContent = 'Updating...';

        try {
          const res = await fetch('/admin/orders/' + encodeURIComponent(orderId) + '/status', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: newStatus }),
          });

          if (!res.ok) {
            const data = await res.json().catch(() => ({}));
            throw new Error(data.message || 'Failed to update status');
          }

          // Update the badge text/class
          const badge = row.querySelector('.status-label');
          badge.textContent = newStatus;
          badge.className = 'badge badge-' + newStatus + ' status-label';

          // Re-enable all buttons in this row, then disable the one matching the new status
          row.querySelectorAll('.status-btn').forEach(b => {
            b.disabled = (b.getAttribute('data-status') === newStatus);
          });

          showToast('Order ' + orderId + ' marked as ' + newStatus + '.');
        } catch (err) {
          showToast(err.message, true);
          btn.disabled = false;
        } finally {
          // restore original button labels
          row.querySelectorAll('.status-btn').forEach(b => {
            const s = b.getAttribute('data-status');
            b.textContent = s === 'confirmed' ? 'Mark Confirmed' : s === 'cancelled' ? 'Mark Cancelled' : 'Reset to Pending';
          });
        }
      });
    });
  </script>
</body>
</html>
  `);
});

// Optional: raw JSON of all orders, useful if you ever want to
// export or pipe into a spreadsheet.
app.get("/admin/orders.json", adminLimiter, requireAdmin, (req, res) => {
  const orders = readOrders().slice().sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
  res.json(orders);
});

// Update an order's status (pending / confirmed / cancelled).
// Used by the buttons on the /admin page.
app.post("/admin/orders/:id/status", adminLimiter, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  if (!VALID_STATUSES.includes(status)) {
    return res.status(400).json({ message: "Invalid status value." });
  }

  try {
    await updateOrderStatus(id, status);
    res.json({ message: "Status updated", id, status });
  } catch (err) {
    if (err.message === "Order not found") {
      return res.status(404).json({ message: "Order not found." });
    }
    console.error("Error updating order status:", err);
    res.status(500).json({ message: "Server error. Please try again." });
  }
});

app.listen(PORT, () => {
  console.log(`Kyenyil Gas backend running on port ${PORT}`);
});
