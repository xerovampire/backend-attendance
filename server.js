// ========== DEPENDENCIES & SETUP ==========
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { createClient } = require("@supabase/supabase-js");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// Generate random admin panel endpoint (changes on each restart for security)
const ADMIN_PANEL_ID = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
console.log(`🔒 Admin panel endpoint: /admin-panel-${ADMIN_PANEL_ID}`);

// ========== SUPABASE CLIENT SETUP ==========
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// ========== MIDDLEWARE SETUP ==========
app.use(helmet());

// CORS configuration for Render deployment
app.use(
  cors({
    origin: [
      "http://localhost:3000",
      "http://localhost:5500",
      "http://127.0.0.1:5500",
      "https://onremote-attendance.netlify.app",
      "https://onremote-attendance.netlify.app/",
      process.env.FRONTEND_URL, // Add your frontend URL in environment variables
    ].filter(Boolean), // Remove any undefined values
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "Accept"],
  })
);

app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW || "15") * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX || "100"),
  message: "Too many requests, please try again later.",
});
app.use(limiter);

// ========== UTILITIES ==========
// Haversine formula for distance calculation
function calculateDistance(lat1, lon1, lat2, lon2) {
  const R = 6371000; // Earth's radius in meters
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLon = ((lon2 - lon1) * Math.PI) / 180;
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos((lat1 * Math.PI) / 180) *
      Math.cos((lat2 * Math.PI) / 180) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c; // Distance in meters
}

// Check if location is within office geofence
function isWithinOffice(userLat, userLon) {
  const officeLat = parseFloat(process.env.OFFICE_LATITUDE);
  const officeLon = parseFloat(process.env.OFFICE_LONGITUDE);
  const officeRadius = parseFloat(process.env.OFFICE_RADIUS);

  const distance = calculateDistance(userLat, userLon, officeLat, officeLon);
  return distance <= officeRadius;
}

// JWT token generation
function generateToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || "24h",
  });
}

// Password hashing
async function hashPassword(password) {
  const rounds = parseInt(process.env.BCRYPT_ROUNDS || "12");
  return await bcrypt.hash(password, rounds);
}

// ========== AUTHENTICATION MIDDLEWARE ==========
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res
      .status(401)
      .json({ success: false, error: "Access token required" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res
        .status(403)
        .json({ success: false, error: "Invalid or expired token" });
    }
    req.user = user;
    next();
  });
};

const authenticateAdmin = (req, res, next) => {
  if (req.user.role !== "admin") {
    return res
      .status(403)
      .json({ success: false, error: "Admin access required" });
  }
  next();
};

// ========== AUDIT LOGGING ==========
async function logAdminAction(adminId, action, details) {
  try {
    await supabase.from("audit_logs").insert([
      {
        admin_id: adminId,
        action: action,
        details: details,
        timestamp: new Date().toISOString(),
      },
    ]);
  } catch (error) {
    console.error("Audit log error:", error);
  }
}

// ========== ROOT ROUTE (IMPORTANT FOR RENDER) ==========
app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "Attendance System API is running!",
    version: "1.0.0",
    endpoints: {
      health: "/health",
      admin: {
        login: "POST /admin/login",
        employees: "GET /employees-public",
        addEmployee: "POST /employees-public",
        updateEmployee: "PUT /employees-public/:id",
        deleteEmployee: "DELETE /employees-public/:id",
        allAttendance: "GET /attendance-public",
        panel: `/admin-panel-${ADMIN_PANEL_ID}`,
      },
      employee: {
        login: "POST /auth/login",
        punch: "POST /attendance/punch",
        attendance: "GET /attendance/:id",
      },
      settings: {
        office: "GET /settings/office",
      },
    },
  });
});

// Health check
app.get("/health", (req, res) => {
  res.json({
    success: true,
    message: "Attendance system is running",
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || "development",
  });
});

// ========== SECURE ADMIN PANEL ENDPOINT ==========
app.get(`/admin-panel-${ADMIN_PANEL_ID}`, (req, res) => {
  res.json({
    success: true,
    message: "Admin panel access granted",
    adminPanelId: ADMIN_PANEL_ID,
    timestamp: new Date().toISOString(),
    endpoints: {
      employees: "/employees-public",
      attendance: "/attendance-public",
      addEmployee: "POST /employees-public",
      updateEmployee: "PUT /employees-public/:id",
      deleteEmployee: "DELETE /employees-public/:id"
    }
  });
});

// ========== OFFICE SETTINGS ENDPOINT ==========
app.get("/settings/office", authenticateToken, (req, res) => {
  res.json({
    success: true,
    settings: {
      latitude: parseFloat(process.env.OFFICE_LATITUDE),
      longitude: parseFloat(process.env.OFFICE_LONGITUDE),
      radius: parseFloat(process.env.OFFICE_RADIUS),
    },
  });
});

// ========== PUBLIC ADMIN ROUTES (NO AUTHENTICATION) ==========
// Get all employees (Public for admin panel)
app.get("/employees-public", async (req, res) => {
  try {
    const { data: employees, error } = await supabase
      .from("employees")
      .select("id, name, email, role, created_at")
      .order("name");

    if (error) throw error;
    res.json({ success: true, employees });
  } catch (error) {
    console.error("Get employees error:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Add employee (Public for admin panel)
app.post("/employees-public", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password || !role) {
      return res
        .status(400)
        .json({ success: false, error: "All fields required" });
    }

    if (!["office_only", "flexible"].includes(role)) {
      return res.status(400).json({ success: false, error: "Invalid role" });
    }

    // Check if employee exists
    const { data: existing } = await supabase
      .from("employees")
      .select("email")
      .eq("email", email)
      .single();

    if (existing) {
      return res
        .status(400)
        .json({ success: false, error: "Employee already exists" });
    }

    const passwordHash = await hashPassword(password);

    const { data: employee, error } = await supabase
      .from("employees")
      .insert([
        {
          name,
          email,
          password_hash: passwordHash,
          role,
        },
      ])
      .select()
      .single();

    if (error) throw error;

    res.json({
      success: true,
      employee: {
        id: employee.id,
        name: employee.name,
        email: employee.email,
        role: employee.role,
      },
    });
  } catch (error) {
    console.error("Add employee error:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Update employee (Public for admin panel)
app.put("/employees-public/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { name, email, role, password } = req.body;

    const updates = {};
    if (name) updates.name = name;
    if (email) updates.email = email;
    if (role && ["office_only", "flexible"].includes(role)) updates.role = role;
    if (password) updates.password_hash = await hashPassword(password);

    const { data: employee, error } = await supabase
      .from("employees")
      .update(updates)
      .eq("id", id)
      .select()
      .single();

    if (error) throw error;

    res.json({
      success: true,
      employee: {
        id: employee.id,
        name: employee.name,
        email: employee.email,
        role: employee.role,
      },
    });
  } catch (error) {
    console.error("Update employee error:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Delete employee (Public for admin panel)
app.delete("/employees-public/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const { error } = await supabase.from("employees").delete().eq("id", id);

    if (error) throw error;

    res.json({ success: true, message: "Employee deleted successfully" });
  } catch (error) {
    console.error("Delete employee error:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Get all attendance (Public for admin panel)
app.get("/attendance-public", async (req, res) => {
  try {
    const { data: attendance, error } = await supabase
      .from("attendance")
      .select(
        `
        *,
        employees (
          name,
          email
        )
      `
      )
      .order("timestamp", { ascending: false })
      .limit(100);

    if (error) throw error;

    // Format the response to match frontend expectations
    const formattedAttendance = attendance.map((record) => ({
      ...record,
      employee_name: record.employees?.name,
      email: record.employees?.email,
    }));

    res.json({ success: true, attendance: formattedAttendance });
  } catch (error) {
    console.error("Get all attendance error:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// ========== ORIGINAL ADMIN ROUTES (WITH AUTHENTICATION) ==========
// Admin login
app.post("/admin/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res
        .status(400)
        .json({ success: false, error: "Username and password required" });
    }

    const { data: admin, error } = await supabase
      .from("admins")
      .select("*")
      .eq("username", username)
      .single();

    if (error || !admin) {
      return res
        .status(401)
        .json({ success: false, error: "Invalid credentials" });
    }

    const validPassword = await bcrypt.compare(password, admin.password_hash);
    if (!validPassword) {
      return res
        .status(401)
        .json({ success: false, error: "Invalid credentials" });
    }

    const token = generateToken({
      id: admin.id,
      username: admin.username,
      role: "admin",
    });

    res.json({
      success: true,
      token,
      admin: {
        id: admin.id,
        username: admin.username,
      },
    });
  } catch (error) {
    console.error("Admin login error:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Get all employees (Admin only - with auth)
app.get(
  "/employees",
  authenticateToken,
  authenticateAdmin,
  async (req, res) => {
    try {
      const { data: employees, error } = await supabase
        .from("employees")
        .select("id, name, email, role, created_at")
        .order("name");

      if (error) throw error;

      res.json({ success: true, employees });
    } catch (error) {
      console.error("Get employees error:", error);
      res.status(500).json({ success: false, error: "Server error" });
    }
  }
);

// Add employee (Admin only - with auth)
app.post(
  "/employees",
  authenticateToken,
  authenticateAdmin,
  async (req, res) => {
    try {
      const { name, email, password, role } = req.body;

      if (!name || !email || !password || !role) {
        return res
          .status(400)
          .json({ success: false, error: "All fields required" });
      }

      if (!["office_only", "flexible"].includes(role)) {
        return res.status(400).json({ success: false, error: "Invalid role" });
      }

      // Check if employee exists
      const { data: existing } = await supabase
        .from("employees")
        .select("email")
        .eq("email", email)
        .single();

      if (existing) {
        return res
          .status(400)
          .json({ success: false, error: "Employee already exists" });
      }

      const passwordHash = await hashPassword(password);

      const { data: employee, error } = await supabase
        .from("employees")
        .insert([
          {
            name,
            email,
            password_hash: passwordHash,
            role,
          },
        ])
        .select()
        .single();

      if (error) throw error;

      // Log admin action
      await logAdminAction(req.user.id, "ADD_EMPLOYEE", {
        employee_id: employee.id,
        name,
        email,
        role,
      });

      res.json({
        success: true,
        employee: {
          id: employee.id,
          name: employee.name,
          email: employee.email,
          role: employee.role,
        },
      });
    } catch (error) {
      console.error("Add employee error:", error);
      res.status(500).json({ success: false, error: "Server error" });
    }
  }
);

// Update employee (Admin only - with auth)
app.put(
  "/employees/:id",
  authenticateToken,
  authenticateAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { name, email, role, password } = req.body;

      const updates = {};
      if (name) updates.name = name;
      if (email) updates.email = email;
      if (role && ["office_only", "flexible"].includes(role))
        updates.role = role;
      if (password) updates.password_hash = await hashPassword(password);

      const { data: employee, error } = await supabase
        .from("employees")
        .update(updates)
        .eq("id", id)
        .select()
        .single();

      if (error) throw error;

      // Log admin action
      await logAdminAction(req.user.id, "UPDATE_EMPLOYEE", {
        employee_id: id,
        updates,
      });

      res.json({
        success: true,
        employee: {
          id: employee.id,
          name: employee.name,
          email: employee.email,
          role: employee.role,
        },
      });
    } catch (error) {
      console.error("Update employee error:", error);
      res.status(500).json({ success: false, error: "Server error" });
    }
  }
);

// Delete employee (Admin only - with auth)
app.delete(
  "/employees/:id",
  authenticateToken,
  authenticateAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      const { error } = await supabase.from("employees").delete().eq("id", id);

      if (error) throw error;

      // Log admin action
      await logAdminAction(req.user.id, "DELETE_EMPLOYEE", {
        employee_id: id,
      });

      res.json({ success: true, message: "Employee deleted successfully" });
    } catch (error) {
      console.error("Delete employee error:", error);
      res.status(500).json({ success: false, error: "Server error" });
    }
  }
);

// Get all attendance for admin (with auth)
app.get(
  "/admin/attendance",
  authenticateToken,
  authenticateAdmin,
  async (req, res) => {
    try {
      const { data: attendance, error } = await supabase
        .from("attendance")
        .select(
          `
        *,
        employees (
          name,
          email
        )
      `
        )
        .order("timestamp", { ascending: false })
        .limit(100);

      if (error) throw error;

      // Format the response to match frontend expectations
      const formattedAttendance = attendance.map((record) => ({
        ...record,
        employee_name: record.employees?.name,
        email: record.employees?.email,
      }));

      res.json({ success: true, attendance: formattedAttendance });
    } catch (error) {
      console.error("Get all attendance error:", error);
      res.status(500).json({ success: false, error: "Server error" });
    }
  }
);

// ========== EMPLOYEE AUTH ROUTES ==========
// Employee login
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ success: false, error: "Email and password required" });
    }

    const { data: employee, error } = await supabase
      .from("employees")
      .select("*")
      .eq("email", email)
      .single();

    if (error || !employee) {
      return res
        .status(401)
        .json({ success: false, error: "Invalid credentials" });
    }

    const validPassword = await bcrypt.compare(
      password,
      employee.password_hash
    );
    if (!validPassword) {
      return res
        .status(401)
        .json({ success: false, error: "Invalid credentials" });
    }

    const token = generateToken({
      id: employee.id,
      email: employee.email,
      role: employee.role,
    });

    res.json({
      success: true,
      token,
      employee: {
        id: employee.id,
        name: employee.name,
        email: employee.email,
        role: employee.role,
      },
    });
  } catch (error) {
    console.error("Employee login error:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// ========== ATTENDANCE ROUTES ==========
// Punch in/out
app.post("/attendance/punch", authenticateToken, async (req, res) => {
  try {
    const { latitude, longitude, type } = req.body;

    if (!latitude || !longitude || !type) {
      return res
        .status(400)
        .json({ success: false, error: "Location and punch type required" });
    }

    if (!["in", "out"].includes(type)) {
      return res
        .status(400)
        .json({ success: false, error: "Invalid punch type" });
    }

    // Get employee details
    const { data: employee, error: empError } = await supabase
      .from("employees")
      .select("role")
      .eq("id", req.user.id)
      .single();

    if (empError || !employee) {
      return res
        .status(404)
        .json({ success: false, error: "Employee not found" });
    }

    // Check geofence for office_only employees
    let status = "Present";
    const withinOffice = isWithinOffice(latitude, longitude);

    if (employee.role === "office_only" && !withinOffice) {
      status = "Outside Office";
      return res.status(400).json({
        success: false,
        error: "You must be within office premises to punch in/out",
        withinOffice: false,
      });
    }

    // Record attendance
    const { data: attendance, error: attError } = await supabase
      .from("attendance")
      .insert([
        {
          employee_id: req.user.id,
          timestamp: new Date().toISOString(),
          type: type,
          latitude: latitude,
          longitude: longitude,
          status: status,
        },
      ])
      .select()
      .single();

    if (attError) throw attError;

    res.json({
      success: true,
      message: `Successfully punched ${type}!`,
      attendance: {
        id: attendance.id,
        type: attendance.type,
        timestamp: attendance.timestamp,
        status: attendance.status,
        withinOffice: withinOffice,
      },
    });
  } catch (error) {
    console.error("Punch error:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Get attendance logs
app.get("/attendance/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    // Employees can only view their own records
    if (req.user.role !== "admin" && req.user.id !== parseInt(id)) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const { data: attendance, error } = await supabase
      .from("attendance")
      .select("*")
      .eq("employee_id", id)
      .order("timestamp", { ascending: false });

    if (error) throw error;

    res.json({ success: true, attendance });
  } catch (error) {
    console.error("Get attendance error:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// ========== ERROR HANDLING ==========
// 404 handler should be LAST
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: "Route not found",
    availableEndpoints: [
      "GET /",
      "GET /health",
      "POST /admin/login",
      "POST /auth/login",
      "GET /settings/office",
      "POST /attendance/punch",
      "GET /attendance/:id",
      "GET /employees-public",
      "POST /employees-public",
      "PUT /employees-public/:id",
      "DELETE /employees-public/:id",
      "GET /attendance-public",
    ],
  });
});

// Global error handler
app.use((error, req, res, next) => {
  console.error("Server error:", error);
  res.status(500).json({ success: false, error: "Internal server error" });
});

// ========== SERVER START ==========
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Attendance system running on port ${PORT}`);
  console.log(
    `📍 Office location: ${process.env.OFFICE_LATITUDE}, ${process.env.OFFICE_LONGITUDE}`
  );
  console.log(`📏 Office radius: ${process.env.OFFICE_RADIUS}m`);
  console.log(`🌐 Environment: ${process.env.NODE_ENV || "development"}`);
  console.log(`🔒 Admin panel: https://your-domain/admin-panel-${ADMIN_PANEL_ID}`);
});
