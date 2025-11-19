require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(bodyParser.json());

// JWT Secret Key (add this to your .env file: JWT_SECRET=your-secret-key-here)
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key-change-this";

// SOCKET.IO SETUP
const http = require("http").Server(app);
const io = require("socket.io")(http, {
  cors: { 
    origin: "*",
    methods: ["GET", "POST"]
  },
});

io.on("connection", (socket) => {
  console.log("✅ Client connected:", socket.id);
  socket.on("disconnect", () => {
    console.log("❌ Client disconnected:", socket.id);
  });
});

// MONGODB CONNECTION
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log("✅ MongoDB Connected"))
.catch((err) => console.error("❌ MongoDB Error:", err));

// USER SCHEMA
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true }
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

// ORDER SCHEMA (Updated with status fields)
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

const Order = mongoose.model("Order", orderSchema);

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified;
    next();
  } catch (error) {
    res.status(403).json({ error: "Invalid token" });
  }
};

// --- AUTHENTICATION ROUTES ---

// Register new user
app.post("/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Validation
    if (!name || !email || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "Email already registered" });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user
    const user = new User({
      name,
      email,
      password: hashedPassword
    });

    await user.save();

    // Create JWT token
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
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Login user
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: "Invalid email or password" });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: "Invalid email or password" });
    }

    // Create JWT token
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
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Get current user (verify token)
app.get("/auth/me", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

// Helper function - Format Order
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

// --- Fetch Orders from Database (Protected Route) ---
app.get("/orders", authenticateToken, async (req, res) => {
  try {
    const orders = await Order.find()
      .sort({ created_at: -1 })
      .limit(100)
      .populate('handled_by.user_id', 'name email');
    
    res.json(orders);
  } catch (err) {
    console.error("Error fetching orders:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// --- Update Order Status (Protected Route) ---
app.patch("/orders/:orderId/status", authenticateToken, async (req, res) => {
  try {
    const { orderId } = req.params;
    const { status } = req.body;

    // Validate status
    const validStatuses = ['delivered', 'in_progress', 'cancelled', 'rescheduled', 'pending'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: "Invalid status" });
    }

    // Update order
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

    // Broadcast update to all connected clients
    io.emit("order_updated", updatedOrder);

    res.json(updatedOrder);
  } catch (error) {
    console.error("Error updating order status:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// --- WEBHOOK for Real-time Orders ---
app.post("/webhooks/orders/create", async (req, res) => {
  try {
    const order = req.body;
    
    console.log("🔔 NEW ORDER RECEIVED:", order.order_number);
    
    // Format order
    const formattedOrder = formatOrder(order);
    
    // Save to database
    const newOrder = new Order(formattedOrder);
    await newOrder.save();
    
    console.log("✅ Order saved to database");
    
    // Broadcast to frontend
    io.emit("new_order", newOrder);
    
    console.log("✅ Order broadcasted to frontend\n");
    
    res.status(200).send("OK");
  } catch (error) {
    if (error.code === 11000) {
      console.log("⚠️ Duplicate order, skipping...");
      res.status(200).send("Duplicate");
    } else {
      console.error("❌ Webhook error:", error);
      res.status(500).send("Error");
    }
  }
});

// Health check
app.get("/", (req, res) => {
  res.send("Server is running! 🚀");
});

// Start server
const PORT = process.env.PORT || 5000;
http.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📡 WebSocket ready`);
  console.log(`🔗 Webhook: http://localhost:${PORT}/webhooks/orders/create`);
});