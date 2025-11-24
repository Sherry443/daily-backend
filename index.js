require("dotenv").config();
const express = require("express");
const cors = require("cors");
const http = require("http");
const { Server } = require("socket.io");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// ============================================
// CONFIGURATION & VALIDATION
// ============================================

const config = {
  JWT_SECRET: process.env.JWT_SECRET || "your-secret-key-change-in-production",
  PORT: process.env.PORT || 5000,
  FRONTEND_URL: process.env.FRONTEND_URL || "http://localhost:3000",
  MONGODB_URI: process.env.MONGODB_URI,
  NODE_ENV: process.env.NODE_ENV || "development"
};

// Validate critical environment variables
const requiredEnvVars = ['MONGODB_URI'];
const missingVars = requiredEnvVars.filter(v => !process.env[v]);

if (missingVars.length > 0) {
  console.error(`❌ Missing required environment variables: ${missingVars.join(', ')}`);
  if (config.NODE_ENV === 'production') {
    process.exit(1);
  }
}

// ============================================
// EXPRESS APP SETUP
// ============================================

const app = express();
const server = http.createServer(app);

// CORS Configuration
app.use(cors({
  origin: [config.FRONTEND_URL, "http://localhost:3000"],
  credentials: true,
  methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ limit: "10mb", extended: true }));
app.set("trust proxy", 1);

// ============================================
// SOCKET.IO SETUP - IMPROVED
// ============================================

const io = new Server(server, {
  cors: {
    origin: [config.FRONTEND_URL, "http://localhost:3000"],
    methods: ["GET", "POST"],
    credentials: true
  },
  transports: ['websocket', 'polling'],
  pingTimeout: 60000,
  pingInterval: 25000,
  connectTimeout: 45000,
  allowEIO3: true
});

let connectedClients = new Set();

io.on('connection', (socket) => {
  connectedClients.add(socket.id);
  console.log(`✅ Socket.IO client connected. ID: ${socket.id}. Total: ${connectedClients.size}`);

  // Send welcome message
  socket.emit('connected', { 
    message: 'Connected to order server',
    socketId: socket.id 
  });

  // Send initial orders when client connects
  socket.on('get_orders', async () => {
    try {
      const orders = await Order.find({})
        .sort({ created_at: -1 })
        .limit(100)
        .populate('handled_by.user_id', 'name email')
        .lean();
      socket.emit('orders_list', orders);
      console.log(`📦 Sent ${orders.length} orders to client ${socket.id}`);
    } catch (error) {
      console.error('Error fetching orders:', error);
      socket.emit('error', { message: 'Failed to fetch orders' });
    }
  });

  // Ping-pong to keep connection alive
  socket.on('ping', () => {
    socket.emit('pong');
  });

  socket.on('disconnect', (reason) => {
    connectedClients.delete(socket.id);
    console.log(`❌ Socket.IO client disconnected. ID: ${socket.id}. Reason: ${reason}. Total: ${connectedClients.size}`);
  });

  socket.on('error', (error) => {
    console.error('Socket.IO error:', error);
  });
});

// Broadcast function for Socket.IO
const broadcast = (event, data) => {
  io.emit(event, data);
  console.log(`📡 Broadcasted ${event} to ${connectedClients.size} clients`);
  return connectedClients.size;
};

// ============================================
// MONGODB CONNECTION
// ============================================

const connectDB = async () => {
  try {
    await mongoose.connect(config.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });
    console.log("✅ MongoDB Connected");
  } catch (err) {
    console.error("❌ MongoDB Connection Error:", err.message);
    setTimeout(connectDB, 5000);
  }
};

mongoose.connection.on('disconnected', () => {
  console.warn("⚠️ MongoDB disconnected");
});

mongoose.connection.on('error', (err) => {
  console.error("❌ MongoDB error:", err);
});

connectDB();

// ============================================
// MONGOOSE SCHEMAS
// ============================================

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { 
    type: String, 
    unique: true, 
    required: true, 
    lowercase: true, 
    trim: true,
    index: true 
  },
  password: { type: String, required: true }
}, { 
  timestamps: true 
});

const orderSchema = new mongoose.Schema({
  shopify_order_id: { 
    type: String, 
    unique: true, 
    required: true,
    index: true 
  },
  order_number: { type: String, required: true },
  customer_full_name: String,
  customer_phone: String,
  full_address: String,
  line_items: [{
    title: String,
    quantity: Number,
    price: String
  }],
  total: String,
  created_at: { type: Date, default: Date.now },
  status: { 
    type: String, 
    enum: ['delivered', 'in_progress', 'cancelled', 'rescheduled', 'pending'],
    default: 'pending',
    index: true
  },
  handled_by: {
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    name: String,
    updated_at: Date
  }
}, { 
  timestamps: true 
});

orderSchema.index({ created_at: -1, status: 1 });
orderSchema.index({ status: 1, created_at: -1 });

const User = mongoose.model("User", userSchema);
const Order = mongoose.model("Order", orderSchema);

// ============================================
// MIDDLEWARE
// ============================================

const authenticateToken = (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: "Access denied. No token provided." });
    }

    const verified = jwt.verify(token, config.JWT_SECRET);
    req.user = verified;
    next();
  } catch (error) {
    console.error("Token verification error:", error.message);
    res.status(403).json({ error: "Invalid or expired token" });
  }
};

const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

app.use((req, res, next) => {
  console.log(`${req.method} ${req.path}`);
  next();
});

// ============================================
// HELPER FUNCTIONS
// ============================================

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

// ============================================
// AUTHENTICATION ROUTES
// ============================================

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
    config.JWT_SECRET,
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
    config.JWT_SECRET,
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

// ============================================
// ORDER ROUTES
// ============================================

app.get("/orders", authenticateToken, asyncHandler(async (req, res) => {
  const { status, limit = 100, skip = 0 } = req.query;
  
  const query = status && status !== 'all' ? { status } : {};
  
  const orders = await Order.find(query)
    .sort({ created_at: -1 })
    .limit(parseInt(limit))
    .skip(parseInt(skip))
    .populate('handled_by.user_id', 'name email')
    .lean();
  
  res.json(orders);
}));

app.get("/orders/:orderId", authenticateToken, asyncHandler(async (req, res) => {
  const { orderId } = req.params;

  if (!mongoose.Types.ObjectId.isValid(orderId)) {
    return res.status(400).json({ error: "Invalid order ID" });
  }

  const order = await Order.findById(orderId)
    .populate('handled_by.user_id', 'name email');

  if (!order) {
    return res.status(404).json({ error: "Order not found" });
  }

  res.json(order);
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

  // Broadcast via Socket.IO
  broadcast('order_updated', updatedOrder);

  res.json(updatedOrder);
}));

// ============================================
// WEBHOOK ROUTE - FIXED DUPLICATE ISSUE
// ============================================

app.post("/webhooks/orders/create", asyncHandler(async (req, res) => {
  const order = req.body;
  
  if (!order.id || !order.order_number) {
    return res.status(400).json({ error: "Invalid order data" });
  }
  
  console.log("🔔 NEW ORDER WEBHOOK:", order.order_number);
  
  try {
    const shopifyOrderId = order.id.toString();
    
    // Check if order already exists
    const existingOrder = await Order.findOne({ shopify_order_id: shopifyOrderId });
    
    if (existingOrder) {
      console.log("⚠️ Order already exists in database, skipping:", order.order_number);
      return res.status(200).json({ 
        success: true, 
        message: "Order already exists",
        duplicate: true
      });
    }
    
    // Format and save new order
    const formattedOrder = formatOrder(order);
    const newOrder = new Order(formattedOrder);
    
    await newOrder.save();
    console.log("✅ New order saved to database:", newOrder.order_number);
    
    // Broadcast to all connected Socket.IO clients
    const clientCount = broadcast('new_order', newOrder);
    console.log(`📡 Broadcasted new order to ${clientCount} clients`);
    
    res.status(200).json({ 
      success: true, 
      message: "Order received and broadcasted",
      clients: clientCount,
      order_id: newOrder._id
    });
    
  } catch (error) {
    console.error("❌ Error processing webhook:", error);
    
    // Handle duplicate key error (in case of race condition)
    if (error.code === 11000) {
      console.log("⚠️ Duplicate order detected (race condition)");
      return res.status(200).json({ 
        success: true, 
        message: "Duplicate order",
        duplicate: true
      });
    }
    
    throw error;
  }
}));

// ============================================
// DEBUG ROUTE - Test webhook manually
// ============================================

app.post("/test/webhook", asyncHandler(async (req, res) => {
  // Sample test order
  const testOrder = {
    id: Date.now(),
    order_number: Math.floor(Math.random() * 10000),
    billing_address: {
      first_name: "Test",
      last_name: "Customer",
      phone: "03001234567",
      address1: "123 Test Street",
      city: "Lahore",
      province: "Punjab",
      country: "Pakistan"
    },
    line_items: [
      {
        title: "Test Product",
        quantity: 2,
        price: "1000"
      }
    ],
    total_price: "2000",
    created_at: new Date().toISOString()
  };

  const formattedOrder = formatOrder(testOrder);
  const newOrder = new Order(formattedOrder);
  
  await newOrder.save();
  
  // Broadcast
  broadcast('new_order', newOrder);
  
  res.json({ 
    success: true, 
    message: "Test order created and broadcasted",
    order: newOrder 
  });
}));

// ============================================
// HEALTH CHECK ROUTES
// ============================================

app.get("/", (req, res) => {
  res.json({ 
    status: "Server is running! 🚀",
    timestamp: new Date().toISOString(),
    mongodb: mongoose.connection.readyState === 1 ? "Connected" : "Disconnected",
    socketio_clients: connectedClients.size,
    environment: config.NODE_ENV
  });
});

app.get("/health", (req, res) => {
  const health = {
    status: "OK",
    timestamp: new Date().toISOString(),
    mongodb: mongoose.connection.readyState === 1 ? "Connected" : "Disconnected",
    socketio_clients: connectedClients.size,
    uptime: process.uptime(),
    memory: process.memoryUsage()
  };
  res.json(health);
});

// ============================================
// ERROR HANDLING
// ============================================

app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

app.use((err, req, res, next) => {
  console.error("❌ Error:", err);
  
  if (err.name === 'ValidationError') {
    return res.status(400).json({ error: err.message });
  }
  
  if (err.name === 'CastError') {
    return res.status(400).json({ error: "Invalid ID format" });
  }

  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({ error: "Invalid token" });
  }
  
  res.status(500).json({ 
    error: config.NODE_ENV === 'production' 
      ? "Internal server error" 
      : err.message 
  });
});

// ============================================
// GRACEFUL SHUTDOWN
// ============================================

const gracefulShutdown = async (signal) => {
  console.log(`\n${signal} signal received: closing server gracefully`);
  
  io.close(() => {
    console.log('Socket.IO server closed');
  });
  
  server.close(() => {
    console.log('HTTP server closed');
    
    mongoose.connection.close(false, () => {
      console.log('MongoDB connection closed');
      process.exit(0);
    });
  });
  
  setTimeout(() => {
    console.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// ============================================
// START SERVER
// ============================================

const PORT_NUM = parseInt(config.PORT, 10);

server.listen(PORT_NUM, () => {
  console.log('\n' + '='.repeat(60));
  console.log(`🚀 Server running on port ${PORT_NUM}`);
  console.log(`📡 Socket.IO server ready`);
  console.log(`🔗 Webhook endpoint: http://localhost:${PORT_NUM}/webhooks/orders/create`);
  console.log(`🧪 Test endpoint: http://localhost:${PORT_NUM}/test/webhook`);
  console.log(`🌐 Frontend URL: ${config.FRONTEND_URL}`);
  console.log(`📊 Environment: ${config.NODE_ENV}`);
  console.log(`🔌 Connected Socket.IO clients: ${connectedClients.size}`);
  console.log('='.repeat(60) + '\n');
});