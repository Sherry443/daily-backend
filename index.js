require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

// --- ENVIRONMENT VARIABLES VALIDATION ---
const requiredEnvVars = ['JWT_SECRET', 'MONGODB_URI', 'PORT', 'FRONTEND_URL'];
const missingVars = requiredEnvVars.filter(v => !process.env[v]);

if (missingVars.length > 0) {
  console.warn(`⚠️ Warning: Missing environment variables: ${missingVars.join(', ')}`);
  if (process.env.NODE_ENV === 'production') {
    console.error('❌ Critical: Cannot start in production without all environment variables');
    process.exit(1);
  }
}

const JWT_SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 5000;
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";
const MONGODB_URI = process.env.MONGODB_URI;

// --- MIDDLEWARE SETUP ---
const corsOptions = {
  origin: [FRONTEND_URL, "https://daily-frontend-navy.vercel.app"],
  credentials: true,
  methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
};

app.use(cors(corsOptions));
app.use(bodyParser.json({ limit: "10mb" }));
app.use(bodyParser.urlencoded({ limit: "10mb", extended: true }));

// Trust proxy for Vercel
app.set("trust proxy", 1);

// --- SOCKET.IO SETUP ---
const http = require("http");
const server = http.createServer(app);

const io = require("socket.io")(server, {
  cors: corsOptions,
  transports: ["websocket", "polling"],
});

io.on("connection", (socket) => {
  console.log("✅ Client connected:", socket.id);
  
  socket.on("disconnect", () => {
    console.log("❌ Client disconnected:", socket.id);
  });

  socket.on("error", (error) => {
    console.error("Socket error:", error);
  });
});

// --- MONGODB CONNECTION WITH RETRY LOGIC ---
const connectDB = async () => {
  try {
    if (!MONGODB_URI) {
      throw new Error("MONGODB_URI is not defined");
    }
    
    await mongoose.connect(MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });
    console.log("✅ MongoDB Connected");
  } catch (err) {
    console.error("❌ MongoDB Connection Error:", err.message);
    // Retry connection after 5 seconds
    setTimeout(connectDB, 5000);
  }
};

// Handle MongoDB connection events
mongoose.connection.on('disconnected', () => {
  console.warn("⚠️ MongoDB disconnected, attempting to reconnect...");
});

connectDB();

// --- USER SCHEMA ---
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, unique: true, required: true, lowercase: true, trim: true },
  password: { type: String, required: true }
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

// --- ORDER SCHEMA ---
const orderSchema = new mongoose.Schema({
  shopify_order_id: { type: String, unique: true, required: true },
  order_number: String,
  customer_full_name: String,
  customer_phone: String,
  full_address: String,
  line_items: [{
    title: String,
    quantity: Number,
    price: String
  }],
  total: String,
  created_at: Date,
  status: { 
    type: String, 
    enum: ['delivered', 'in_progress', 'cancelled', 'rescheduled', 'pending'],
    default: 'pending'
  },
  handled_by: {
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    name: String,
    updated_at: Date
  }
}, { timestamps: true });

// Create compound index for better performance
orderSchema.index({ created_at: -1, status: 1 });
orderSchema.index({ shopify_order_id: 1 });

const Order = mongoose.model("Order", orderSchema);

// --- AUTHENTICATION MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: "Access denied. No token provided." });
    }

    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified;
    next();
  } catch (error) {
    console.error("Token verification error:", error.message);
    res.status(403).json({ error: "Invalid or expired token" });
  }
};

// --- ERROR HANDLING MIDDLEWARE ---
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

// --- AUTHENTICATION ROUTES ---

app.post("/auth/register", asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters" });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "Invalid email format" });
  }

  const existingUser = await User.findOne({ email: email.toLowerCase() });
  if (existingUser) {
    return res.status(400).json({ error: "Email already registered" });
  }

  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  const user = new User({
    name: name.trim(),
    email: email.toLowerCase(),
    password: hashedPassword
  });

  await user.save();

  const token = jwt.sign(
    { id: user._id, email: user.email, name: user.name },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.status(201).json({
    message: "User registered successfully",
    token,
    user: { id: user._id, name: user.name, email: user.email }
  });
}));

app.post("/auth/login", asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  const user = await User.findOne({ email: email.toLowerCase() });
  if (!user) {
    return res.status(400).json({ error: "Invalid email or password" });
  }

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    return res.status(400).json({ error: "Invalid email or password" });
  }

  const token = jwt.sign(
    { id: user._id, email: user.email, name: user.name },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.json({
    message: "Login successful",
    token,
    user: { id: user._id, name: user.name, email: user.email }
  });
}));

app.get("/auth/me", authenticateToken, asyncHandler(async (req, res) => {
  const user = await User.findById(req.user.id).select('-password');
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }
  res.json(user);
}));

// --- HELPER FUNCTION ---
const formatOrder = (order) => {
  const billing = order.billing_address || {};
  const shipping = order.shipping_address || {};
  const customer = order.customer || {};
  
  const firstName = billing.first_name || customer.first_name || shipping.first_name || "";
  const lastName = billing.last_name || customer.last_name || shipping.last_name || "";
  const fullName = `${firstName} ${lastName}`.trim() || billing.name || "Unknown";

  const phone = billing.phone || shipping.phone || customer.phone || "N/A";

  const fullAddress = [
    billing.address1,
    billing.address2,
    billing.city,
    billing.province,
    billing.zip,
    billing.country,
  ].filter(Boolean).join(", ") || "N/A";

  const items = order.line_items?.map(item => ({
    title: item.title,
    quantity: item.quantity,
    price: `Rs ${Number(item.price).toLocaleString("en-PK")}`
  })) || [];

  const total = `Rs ${Number(order.total_price).toLocaleString("en-PK")}`;

  return {
    shopify_order_id: order.id.toString(),
    order_number: `#${order.order_number}`,
    customer_full_name: fullName,
    customer_phone: phone,
    full_address: fullAddress,
    line_items: items,
    total: total,
    created_at: new Date(order.created_at)
  };
};

// --- ORDER ROUTES ---

app.get("/orders", authenticateToken, asyncHandler(async (req, res) => {
  const orders = await Order.find()
    .sort({ created_at: -1 })
    .limit(100)
    .populate('handled_by.user_id', 'name email')
    .lean();
  
  res.json(orders);
}));

app.patch("/orders/:orderId/status", authenticateToken, asyncHandler(async (req, res) => {
  const { orderId } = req.params;
  const { status } = req.body;

  const validStatuses = ['delivered', 'in_progress', 'cancelled', 'rescheduled', 'pending'];
  if (!validStatuses.includes(status)) {
    return res.status(400).json({ error: "Invalid status" });
  }

  if (!mongoose.Types.ObjectId.isValid(orderId)) {
    return res.status(400).json({ error: "Invalid order ID" });
  }

  const updatedOrder = await Order.findByIdAndUpdate(
    orderId,
    {
      status,
      handled_by: {
        user_id: req.user.id,
        name: req.user.name,
        updated_at: new Date()
      }
    },
    { new: true }
  ).populate('handled_by.user_id', 'name email');

  if (!updatedOrder) {
    return res.status(404).json({ error: "Order not found" });
  }

  io.emit("order_updated", updatedOrder);

  res.json(updatedOrder);
}));

// --- WEBHOOK ROUTE ---

app.post("/webhooks/orders/create", asyncHandler(async (req, res) => {
  try {
    const order = req.body;
    
    if (!order.id || !order.order_number) {
      return res.status(400).json({ error: "Invalid order data" });
    }
    
    console.log("🔔 NEW ORDER RECEIVED:", order.order_number);
    
    const formattedOrder = formatOrder(order);
    const newOrder = new Order(formattedOrder);
    
    await newOrder.save();
    
    console.log("✅ Order saved to database");
    
    io.emit("new_order", newOrder);
    
    console.log("✅ Order broadcasted to frontend\n");
    
    res.status(200).json({ success: true, message: "Order received" });
  } catch (error) {
    if (error.code === 11000) {
      console.log("⚠️ Duplicate order, skipping...");
      return res.status(200).json({ success: true, message: "Duplicate" });
    }
    throw error;
  }
}));

// --- HEALTH CHECK ---

app.get("/", (req, res) => {
  res.json({ 
    status: "Server is running! 🚀",
    timestamp: new Date().toISOString(),
    mongodb: mongoose.connection.readyState === 1 ? "Connected" : "Disconnected"
  });
});

app.get("/health", (req, res) => {
  const health = {
    status: "OK",
    timestamp: new Date().toISOString(),
    mongodb: mongoose.connection.readyState === 1 ? "Connected" : "Disconnected",
    uptime: process.uptime()
  };
  res.json(health);
});

// --- 404 HANDLER ---
app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

// --- GLOBAL ERROR HANDLER ---
app.use((err, req, res, next) => {
  console.error("❌ Error:", err);
  
  if (err.name === 'ValidationError') {
    return res.status(400).json({ error: err.message });
  }
  
  if (err.name === 'CastError') {
    return res.status(400).json({ error: "Invalid ID format" });
  }
  
  res.status(500).json({ error: "Internal server error" });
});

// --- GRACEFUL SHUTDOWN ---
process.on('SIGTERM', () => {
  console.log('SIGTERM signal received: closing HTTP server');
  server.close(() => {
    console.log('HTTP server closed');
    mongoose.connection.close();
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT signal received: closing HTTP server');
  server.close(() => {
    console.log('HTTP server closed');
    mongoose.connection.close();
    process.exit(0);
  });
});

// --- START SERVER ---
const PORT_NUM = parseInt(PORT, 10) || 5000;
server.listen(PORT_NUM, () => {
  console.log(`🚀 Server running on port ${PORT_NUM}`);
  console.log(`📡 WebSocket ready`);
  console.log(`🔗 Webhook: ${process.env.WEBHOOK_URL || `http://localhost:${PORT_NUM}/webhooks/orders/create`}`);
  console.log(`🌐 Frontend URL: ${FRONTEND_URL}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);