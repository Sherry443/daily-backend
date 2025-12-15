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
  JWT_SECRET: process.env.JWT_SECRET,
  PORT: process.env.PORT || 5000,
  FRONTEND_URL: process.env.FRONTEND_URL,
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
  origin: [config.FRONTEND_URL],
  credentials: true,
  methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ limit: "10mb", extended: true }));
app.set("trust proxy", 1);

const requireAdmin = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    
    if (!user || !user.isAdmin) {
      return res.status(403).json({ 
        error: "Access denied. Admin privileges required." 
      });
    }
    
    next();
  } catch (error) {
    console.error("Admin check error:", error);
    res.status(500).json({ error: "Authorization error" });
  }
};


// ============================================
// SOCKET.IO SETUP - IMPROVED
// ============================================

const io = new Server(server, {
  cors: {
    origin: [config.FRONTEND_URL],
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
const createAdminUser = async () => {
  try {
    const adminEmail = 'contact.ranazaki@gmail.com';
    const existingAdmin = await User.findOne({ email: adminEmail });
    
    if (!existingAdmin) {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash('123@rana', salt);
      
      const admin = new User({
        name: 'rana zaki',
        email: adminEmail,
        password: hashedPassword,
        isAdmin: true
      });
      
      await admin.save();
      console.log('✅ Admin user created successfully');
    } else {
      console.log('✅ Admin user already exists');
    }
  } catch (error) {
    console.error('❌ Error creating admin user:', error);
  }
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
// createAdminUser();

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
  password: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },  // NEW
  createdAt: { type: Date, default: Date.now }
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
  },
  // NEW FIELDS FOR ADMIN APPROVAL
  admin_approval: {
    status: { 
      type: String, 
      enum: ['pending', 'confirmed', 'denied'],
      default: 'pending'
    },
    approved_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    approved_at: Date,
    denial_reason: String
  }
}, { 
  timestamps: true 
});

orderSchema.index({ created_at: -1, status: 1 });
orderSchema.index({ status: 1, created_at: -1 });

const User = mongoose.model("User", userSchema);
const Order = mongoose.model("Order", orderSchema);
createAdminUser();
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
// ADD THESE ROUTES TO YOUR EXISTING server.js
// ============================================

// ============================================
// PRODUCT SCHEMA (Add this after Order schema)
// ============================================

const productSchema = new mongoose.Schema({
  shopify_product_id: { 
    type: String, 
    unique: true, 
    required: true,
    index: true 
  },
  title: { type: String, required: true },
  variants: [{
    variant_id: String,
    title: String,
    sku: String,
    inventory_quantity: { type: Number, default: 0 },
    price: String
  }],
  total_inventory: { type: Number, default: 0 },
  image_url: String,
  product_type: String,
  vendor: String,
  tags: [String],
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now }
}, { 
  timestamps: true 
});

productSchema.index({ title: 'text', product_type: 'text', vendor: 'text' });

const Product = mongoose.model("Product", productSchema);

// ============================================
// PRODUCT ROUTES
// ============================================

// Get all products with search and filters
app.get("/products", authenticateToken, asyncHandler(async (req, res) => {
  const { search, sort = 'title', order = 'asc', limit = 50, skip = 0 } = req.query;
  
  let query = {};
  
  // Search functionality
  if (search) {
    query.$or = [
      { title: { $regex: search, $options: 'i' } },
      { product_type: { $regex: search, $options: 'i' } },
      { vendor: { $regex: search, $options: 'i' } },
      { 'variants.sku': { $regex: search, $options: 'i' } }
    ];
  }
  
  // Sorting
  const sortOrder = order === 'desc' ? -1 : 1;
  const sortOptions = { [sort]: sortOrder };
  
  const products = await Product.find(query)
    .sort(sortOptions)
    .limit(parseInt(limit))
    .skip(parseInt(skip))
    .lean();
  
  const total = await Product.countDocuments(query);
  
  res.json({
    products,
    total,
    page: Math.floor(parseInt(skip) / parseInt(limit)) + 1,
    totalPages: Math.ceil(total / parseInt(limit))
  });
}));

// Get single product
app.get("/products/:productId", authenticateToken, asyncHandler(async (req, res) => {
  const { productId } = req.params;

  if (!mongoose.Types.ObjectId.isValid(productId)) {
    return res.status(400).json({ error: "Invalid product ID" });
  }

  const product = await Product.findById(productId);

  if (!product) {
    return res.status(404).json({ error: "Product not found" });
  }

  res.json(product);
}));

// Update product inventory manually
app.patch("/products/:productId/inventory", authenticateToken, asyncHandler(async (req, res) => {
  const { productId } = req.params;
  const { variant_id, inventory_quantity } = req.body;

  if (!mongoose.Types.ObjectId.isValid(productId)) {
    return res.status(400).json({ error: "Invalid product ID" });
  }

  const product = await Product.findById(productId);
  
  if (!product) {
    return res.status(404).json({ error: "Product not found" });
  }

  // Update specific variant inventory
  if (variant_id) {
    const variant = product.variants.find(v => v.variant_id === variant_id);
    if (variant) {
      variant.inventory_quantity = inventory_quantity;
    }
  }

  // Recalculate total inventory
  product.total_inventory = product.variants.reduce((sum, v) => sum + (v.inventory_quantity || 0), 0);
  product.updated_at = new Date();

  await product.save();

  // Broadcast update
  broadcast('product_updated', product);

  res.json(product);
}));

// Shopify Products Webhook - Sync inventory
// Shopify Products Webhook - Sync inventory
app.post("/webhooks/products/update", asyncHandler(async (req, res) => {
  const shopifyProduct = req.body;
  
  if (!shopifyProduct.id) {
    return res.status(400).json({ error: "Invalid product data" });
  }
  
  console.log("🔔 PRODUCT UPDATE WEBHOOK:", shopifyProduct.title);
  
  try {
    const productId = shopifyProduct.id.toString();
    
    const variants = shopifyProduct.variants?.map(v => ({
      variant_id: v.id.toString(),
      title: v.title,
      sku: v.sku,
      inventory_quantity: v.inventory_quantity || 0,
      price: `Rs ${Number(v.price).toLocaleString("en-PK")}`
    })) || [];
    
    const totalInventory = variants.reduce((sum, v) => sum + (v.inventory_quantity || 0), 0);
    
    // Get the price from the first variant or calculate average/min price
    const firstVariantPrice = shopifyProduct.variants?.[0]?.price || 0;
    
    const productData = {
      shopify_product_id: productId,
      title: shopifyProduct.title,
      variants: variants,
      total_inventory: totalInventory,
      price: firstVariantPrice, // Add this line - store numeric price
      formatted_price: `Rs ${Number(firstVariantPrice).toLocaleString("en-PK")}`, // Add formatted version
      image_url: shopifyProduct.image?.src || shopifyProduct.images?.[0]?.src,
      product_type: shopifyProduct.product_type,
      vendor: shopifyProduct.vendor,
      tags: shopifyProduct.tags?.split(',').map(t => t.trim()) || [],
      updated_at: new Date()
    };
    
    const product = await Product.findOneAndUpdate(
      { shopify_product_id: productId },
      productData,
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );
    
    console.log("✅ Product synced:", product.title);
    
    // Broadcast to connected clients
    broadcast('product_updated', product);
    
    res.status(200).json({ success: true, product_id: product._id });
    
  } catch (error) {
    console.error("❌ Error syncing product:", error);
    throw error;
  }
}));

// ============================================
// DASHBOARD STATS ROUTES
// ============================================

// Get dashboard statistics for admin
app.get("/dashboard/stats", authenticateToken, asyncHandler(async (req, res) => {
  const { startDate, endDate } = req.query;
  
  let dateFilter = {};
  if (startDate || endDate) {
    dateFilter.created_at = {};
    if (startDate) dateFilter.created_at.$gte = new Date(startDate);
    if (endDate) dateFilter.created_at.$lte = new Date(endDate);
  }
  
  // Count orders by status
  const [pending, inProgress, delivered, cancelled, rescheduled] = await Promise.all([
    Order.countDocuments({ ...dateFilter, status: 'pending' }),
    Order.countDocuments({ ...dateFilter, status: 'in_progress' }),
    Order.countDocuments({ ...dateFilter, status: 'delivered' }),
    Order.countDocuments({ ...dateFilter, status: 'cancelled' }),
    Order.countDocuments({ ...dateFilter, status: 'rescheduled' })
  ]);
  
  // Calculate revenue (only delivered orders)
  const deliveredOrders = await Order.find({ ...dateFilter, status: 'delivered' }).lean();
  const totalRevenue = deliveredOrders.reduce((sum, order) => {
    const amount = parseFloat(order.total.replace(/[^0-9.]/g, ''));
    return sum + (isNaN(amount) ? 0 : amount);
  }, 0);
  
  // Recent orders
  const recentOrders = await Order.find(dateFilter)
    .sort({ created_at: -1 })
    .limit(10)
    .populate('handled_by.user_id', 'name email')
    .lean();
  
  // Top handlers
  const topHandlers = await Order.aggregate([
    { $match: { ...dateFilter, 'handled_by.user_id': { $exists: true } } },
    { $group: { 
      _id: '$handled_by.user_id', 
      name: { $first: '$handled_by.name' },
      count: { $sum: 1 } 
    }},
    { $sort: { count: -1 } },
    { $limit: 5 }
  ]);
  
  res.json({
    stats: {
      pending,
      in_progress: inProgress,
      delivered,
      cancelled,
      rescheduled,
      total: pending + inProgress + delivered + cancelled + rescheduled
    },
    revenue: {
      total: totalRevenue,
      formatted: `Rs ${totalRevenue.toLocaleString("en-PK")}`
    },
    recentOrders,
    topHandlers
  });
}));

// Get user-specific dashboard statistics
// Get user-specific dashboard statistics
app.get("/dashboard/user-stats", authenticateToken, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const { startDate, endDate } = req.query;
  
  let dateFilter = { 'handled_by.user_id': new mongoose.Types.ObjectId(userId) };
  if (startDate || endDate) {
    dateFilter['handled_by.updated_at'] = {};
    if (startDate) dateFilter['handled_by.updated_at'].$gte = new Date(startDate);
    if (endDate) dateFilter['handled_by.updated_at'].$lte = new Date(endDate);
  }
  
  // Count user's handled orders by status
  const [pending, inProgress, delivered, cancelled, rescheduled] = await Promise.all([
    Order.countDocuments({ ...dateFilter, status: 'pending' }),
    Order.countDocuments({ ...dateFilter, status: 'in_progress' }),
    Order.countDocuments({ ...dateFilter, status: 'delivered' }),
    Order.countDocuments({ ...dateFilter, status: 'cancelled' }),
    Order.countDocuments({ ...dateFilter, status: 'rescheduled' })
  ]);
  
  // Get orders grouped by date
  const ordersByDate = await Order.aggregate([
    { $match: dateFilter },
    { $group: {
      _id: { $dateToString: { format: "%Y-%m-%d", date: "$handled_by.updated_at" } },
      pending: { $sum: { $cond: [{ $eq: ["$status", "pending"] }, 1, 0] } },
      in_progress: { $sum: { $cond: [{ $eq: ["$status", "in_progress"] }, 1, 0] } },
      delivered: { $sum: { $cond: [{ $eq: ["$status", "delivered"] }, 1, 0] } },
      cancelled: { $sum: { $cond: [{ $eq: ["$status", "cancelled"] }, 1, 0] } },
      rescheduled: { $sum: { $cond: [{ $eq: ["$status", "rescheduled"] }, 1, 0] } }
    }},
    { $sort: { _id: -1 } },
    { $limit: 30 }
  ]);
  
  // Recent handled orders
  const recentOrders = await Order.find(dateFilter)
    .sort({ 'handled_by.updated_at': -1 })
    .limit(20)
    .lean();
  
  res.json({
    stats: {
      pending,
      in_progress: inProgress,
      delivered,
      cancelled,
      rescheduled,
      total: pending + inProgress + delivered + cancelled + rescheduled
    },
    ordersByDate,
    recentOrders
  });
}));
// GET /dashboard/user-detailed-stats/:userId
// GET /dashboard/user-detailed-stats/:userId
app.get('/dashboard/user-detailed-stats/:userId', authenticateToken, asyncHandler(async (req, res) => {
  try {
    const { userId } = req.params;
    const { startDate, endDate, timeframe } = req.query;
    
    // Validate userId
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ error: "Invalid user ID" });
    }
    
    // Build date filter
    let dateFilter = { 'handled_by.user_id': new mongoose.Types.ObjectId(userId) };
    
    if (startDate || endDate) {
      dateFilter['handled_by.updated_at'] = {};
      if (startDate) {
        const start = new Date(startDate);
        start.setHours(0, 0, 0, 0);
        dateFilter['handled_by.updated_at'].$gte = start;
      }
      if (endDate) {
        const end = new Date(endDate);
        end.setHours(23, 59, 59, 999);
        dateFilter['handled_by.updated_at'].$lte = end;
      }
    }
    
    // Get user name
    const user = await User.findById(userId);
    
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    
    // Summary stats
    const summary = {
      total: await Order.countDocuments(dateFilter),
      pending: await Order.countDocuments({ ...dateFilter, status: 'pending' }),
      in_progress: await Order.countDocuments({ ...dateFilter, status: 'in_progress' }),
      delivered: await Order.countDocuments({ ...dateFilter, status: 'delivered' }),
      cancelled: await Order.countDocuments({ ...dateFilter, status: 'cancelled' }),
      rescheduled: await Order.countDocuments({ ...dateFilter, status: 'rescheduled' })
    };
    
    // Daily breakdown
    const dailyBreakdown = await Order.aggregate([
      { $match: dateFilter },
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m-%d", date: "$handled_by.updated_at" } },
          total: { $sum: 1 },
          pending: { $sum: { $cond: [{ $eq: ["$status", "pending"] }, 1, 0] } },
          in_progress: { $sum: { $cond: [{ $eq: ["$status", "in_progress"] }, 1, 0] } },
          delivered: { $sum: { $cond: [{ $eq: ["$status", "delivered"] }, 1, 0] } },
          cancelled: { $sum: { $cond: [{ $eq: ["$status", "cancelled"] }, 1, 0] } },
          rescheduled: { $sum: { $cond: [{ $eq: ["$status", "rescheduled"] }, 1, 0] } }
        }
      },
      { $sort: { _id: 1 } }
    ]);
    
    // Recent orders
    const recentOrders = await Order.find(dateFilter)
      .sort({ 'handled_by.updated_at': -1 })
      .limit(20)
      .select('order_number customer_full_name total status created_at')
      .lean();
    
    res.json({
      userName: user.name,
      summary,
      dailyBreakdown,
      recentOrders
    });
    
  } catch (error) {
    console.error('Error fetching user detailed stats:', error);
    res.status(500).json({ error: 'Server error' });
  }
}));
// Get user's handled orders with advanced filtering
app.get("/user/my-orders", authenticateToken, asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const { 
    date, 
    startDate, 
    endDate, 
    status, 
    limit = 50, 
    skip = 0,
    sort = 'desc' // desc or asc
  } = req.query;
  
  // Build query filter
  let query = { 'handled_by.user_id': new mongoose.Types.ObjectId(userId) };
  
  // Status filter
  if (status && status !== 'all') {
    query.status = status;
  }
  
  // Date filters
  if (date) {
    // Single date filter (for specific day)
    const startOfDay = new Date(date);
    startOfDay.setHours(0, 0, 0, 0);
    const endOfDay = new Date(date);
    endOfDay.setHours(23, 59, 59, 999);
    
    query['handled_by.updated_at'] = {
      $gte: startOfDay,
      $lte: endOfDay
    };
  } else if (startDate || endDate) {
    // Date range filter
    query['handled_by.updated_at'] = {};
    
    if (startDate) {
      const start = new Date(startDate);
      start.setHours(0, 0, 0, 0);
      query['handled_by.updated_at'].$gte = start;
    }
    
    if (endDate) {
      const end = new Date(endDate);
      end.setHours(23, 59, 59, 999);
      query['handled_by.updated_at'].$lte = end;
    }
  }
  
  // Sorting
  const sortOrder = sort === 'asc' ? 1 : -1;
  
  // Fetch orders with pagination
  const [orders, totalCount] = await Promise.all([
    Order.find(query)
      .sort({ 'handled_by.updated_at': sortOrder })
      .limit(parseInt(limit))
      .skip(parseInt(skip))
      .populate('handled_by.user_id', 'name email')
      .populate('admin_approval.approved_by', 'name email')
      .lean(),
    Order.countDocuments(query)
  ]);
  
  // Get stats for filtered orders
  const stats = await Order.aggregate([
    { $match: query },
    {
      $group: {
        _id: null,
        total: { $sum: 1 },
        pending: { $sum: { $cond: [{ $eq: ["$status", "pending"] }, 1, 0] } },
        in_progress: { $sum: { $cond: [{ $eq: ["$status", "in_progress"] }, 1, 0] } },
        delivered: { $sum: { $cond: [{ $eq: ["$status", "delivered"] }, 1, 0] } },
        cancelled: { $sum: { $cond: [{ $eq: ["$status", "cancelled"] }, 1, 0] } },
        rescheduled: { $sum: { $cond: [{ $eq: ["$status", "rescheduled"] }, 1, 0] } },
        confirmed: { $sum: { $cond: [{ $eq: ["$admin_approval.status", "confirmed"] }, 1, 0] } },
        denied: { $sum: { $cond: [{ $eq: ["$admin_approval.status", "denied"] }, 1, 0] } },
        pending_approval: { $sum: { $cond: [{ $eq: ["$admin_approval.status", "pending"] }, 1, 0] } }
      }
    }
  ]);
  
  res.json({
    orders,
    pagination: {
      total: totalCount,
      limit: parseInt(limit),
      skip: parseInt(skip),
      page: Math.floor(parseInt(skip) / parseInt(limit)) + 1,
      totalPages: Math.ceil(totalCount / parseInt(limit))
    },
    stats: stats[0] || {
      total: 0,
      pending: 0,
      in_progress: 0,
      delivered: 0,
      cancelled: 0,
      rescheduled: 0,
      confirmed: 0,
      denied: 0,
      pending_approval: 0
    }
  });
}));

// ============================================
// TEST ROUTE - Sync sample products
// ============================================

app.post("/test/products", asyncHandler(async (req, res) => {
  const sampleProducts = [
    {
      id: Date.now(),
      title: "Cotton T-Shirt",
      product_type: "Clothing",
      vendor: "Fashion Brand",
      tags: "clothing,tshirt,cotton",
      variants: [
        { id: Date.now() + 1, title: "Small", sku: "TS-S", inventory_quantity: 50, price: "999" },
        { id: Date.now() + 2, title: "Medium", sku: "TS-M", inventory_quantity: 75, price: "999" },
        { id: Date.now() + 3, title: "Large", sku: "TS-L", inventory_quantity: 100, price: "999" }
      ]
    },
    {
      id: Date.now() + 100,
      title: "Denim Jeans",
      product_type: "Clothing",
      vendor: "Fashion Brand",
      tags: "clothing,jeans,denim",
      variants: [
        { id: Date.now() + 101, title: "30", sku: "DJ-30", inventory_quantity: 25, price: "2499" },
        { id: Date.now() + 102, title: "32", sku: "DJ-32", inventory_quantity: 40, price: "2499" },
        { id: Date.now() + 103, title: "34", sku: "DJ-34", inventory_quantity: 35, price: "2499" }
      ]
    }
  ];

  const results = [];
  
  for (const product of sampleProducts) {
    const productId = product.id.toString();
    
    const variants = product.variants.map(v => ({
      variant_id: v.id.toString(),
      title: v.title,
      sku: v.sku,
      inventory_quantity: v.inventory_quantity || 0,
      price: `Rs ${Number(v.price).toLocaleString("en-PK")}`
    }));
    
    const totalInventory = variants.reduce((sum, v) => sum + v.inventory_quantity, 0);
    
    const savedProduct = await Product.findOneAndUpdate(
      { shopify_product_id: productId },
      {
        shopify_product_id: productId,
        title: product.title,
        variants: variants,
        total_inventory: totalInventory,
        product_type: product.product_type,
        vendor: product.vendor,
        tags: product.tags.split(',').map(t => t.trim()),
        updated_at: new Date()
      },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );
    
    results.push(savedProduct);
  }
  
  // Broadcast
  results.forEach(product => broadcast('product_updated', product));
  
  res.json({ 
    success: true, 
    message: "Test products created",
    products: results 
  });
}));
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
    { id: user._id, email: user.email, name: user.name, isAdmin: user.isAdmin },  // ✅ Add isAdmin
    config.JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.status(201).json({
    message: "User registered successfully",
    token,
    user: { 
      id: user._id, 
      name: user.name, 
      email: user.email,
      isAdmin: user.isAdmin  // ✅ Add isAdmin here
    }
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
    { id: user._id, email: user.email, name: user.name, isAdmin: user.isAdmin },  // ✅ Add isAdmin
    config.JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.json({
    message: "Login successful",
    token,
    user: { 
      id: user._id, 
      name: user.name, 
      email: user.email,
      isAdmin: user.isAdmin  // ✅ Add isAdmin here
    }
  });
}));

app.get("/auth/me", authenticateToken, asyncHandler(async (req, res) => {
  const user = await User.findById(req.user.id).select('-password');
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }
  res.json(user);  // ✅ Ye automatically isAdmin return karega
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

const updateOrderStatus = async (orderId, status) => {
  try {
    setUpdatingOrder(orderId);
    const token = localStorage.getItem('token');
    
    console.log('🔄 Updating order:', orderId, 'to status:', status);
    console.log('🔑 Token exists:', !!token);
    
    const response = await fetch(`${BACKEND_URL}/orders/${orderId}/status`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({ status })
    });

    console.log('📡 Response status:', response.status);

    if (response.ok) {
      const updatedOrder = await response.json();
      console.log('✅ Order updated successfully:', updatedOrder);
      setOrders(prevOrders => 
        prevOrders.map(order => 
          order._id === updatedOrder._id ? updatedOrder : order
        )
      );
      // Show success message
      alert(`Order ${updatedOrder.order_number} updated to ${getStatusLabel(status)}`);
    } else if (response.status === 401) {
      console.error('❌ Unauthorized - logging out');
      alert('Session expired. Please login again.');
      onLogout();
    } else {
      const errorData = await response.json();
      console.error('❌ Error response:', errorData);
      alert(`Failed to update order: ${errorData.error || 'Unknown error'}`);
    }
  } catch (error) {
    console.error('❌ Error updating order:', error);
    alert(`Failed to update order status: ${error.message}`);
  } finally {
    setUpdatingOrder(null);
  }
};
app.patch("/orders/:orderId/status", authenticateToken, asyncHandler(async (req, res) => {
  const { orderId } = req.params;
  const { status } = req.body;

  console.log(`🔄 Updating order ${orderId} to status: ${status}`);

  // Validate orderId
  if (!mongoose.Types.ObjectId.isValid(orderId)) {
    return res.status(400).json({ error: "Invalid order ID format" });
  }

  // Validate status
  const validStatuses = ['delivered', 'in_progress', 'cancelled', 'rescheduled', 'pending'];
  if (!status || !validStatuses.includes(status)) {
    return res.status(400).json({ 
      error: "Invalid status. Must be one of: " + validStatuses.join(', ') 
    });
  }

  // Find and update order
  const order = await Order.findById(orderId);
  
  if (!order) {
    return res.status(404).json({ error: "Order not found" });
  }

  // Update order status and handler info
  order.status = status;
  order.handled_by = {
    user_id: req.user.id,
    name: req.user.name,
    updated_at: new Date()
  };

  await order.save();

  // Populate the user reference
  await order.populate('handled_by.user_id', 'name email');

  console.log(`✅ Order ${order.order_number} updated to ${status} by ${req.user.name}`);

  // Broadcast update to all connected clients
  broadcast('order_updated', order.toObject());

  res.json(order);
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

app.get("/admin/users", authenticateToken, requireAdmin, asyncHandler(async (req, res) => {
  const users = await User.find({ isAdmin: false })
    .select('-password')
    .sort({ createdAt: -1 })
    .lean();
  
  // Get order counts for each user
  const usersWithStats = await Promise.all(
    users.map(async (user) => {
      const orderStats = await Order.aggregate([
        { $match: { 'handled_by.user_id': user._id } },
        {
          $group: {
            _id: '$status',
            count: { $sum: 1 }
          }
        }
      ]);
      
      const stats = {
        total: 0,
        delivered: 0,
        in_progress: 0,
        cancelled: 0,
        rescheduled: 0,
        pending: 0
      };
      
      orderStats.forEach(stat => {
        stats[stat._id] = stat.count;
        stats.total += stat.count;
      });
      
      return {
        ...user,
        orderStats: stats
      };
    })
  );
  
  res.json(usersWithStats);
}));


// Get user's handled orders (Admin only)
app.get("/admin/users/:userId/orders", authenticateToken, requireAdmin, asyncHandler(async (req, res) => {
  const { userId } = req.params;
  const { date, status } = req.query;
  
  if (!mongoose.Types.ObjectId.isValid(userId)) {
    return res.status(400).json({ error: "Invalid user ID" });
  }
  
  let query = { 'handled_by.user_id': userId };
  
  // Filter by status
  if (status && status !== 'all') {
    query.status = status;
  }
  
  // Filter by date
  if (date) {
    const startOfDay = new Date(date);
    startOfDay.setHours(0, 0, 0, 0);
    const endOfDay = new Date(date);
    endOfDay.setHours(23, 59, 59, 999);
    
    query['handled_by.updated_at'] = {
      $gte: startOfDay,
      $lte: endOfDay
    };
  }
  
  const orders = await Order.find(query)
    .sort({ 'handled_by.updated_at': -1 })
    .populate('handled_by.user_id', 'name email')
    .lean();
  
  res.json(orders);
}));

// Confirm order (Admin only)
app.patch("/admin/orders/:orderId/confirm", authenticateToken, requireAdmin, asyncHandler(async (req, res) => {
  const { orderId } = req.params;
  
  if (!mongoose.Types.ObjectId.isValid(orderId)) {
    return res.status(400).json({ error: "Invalid order ID" });
  }
  
  const order = await Order.findById(orderId);
  
  if (!order) {
    return res.status(404).json({ error: "Order not found" });
  }
  
  order.admin_approval = {
    status: 'confirmed',
    approved_by: req.user.id,
    approved_at: new Date()
  };
  
  await order.save();
  await order.populate('handled_by.user_id', 'name email');
  await order.populate('admin_approval.approved_by', 'name email');
  
  console.log(`✅ Order ${order.order_number} confirmed by admin`);
  
  // Broadcast update
  broadcast('order_updated', order.toObject());
  
  res.json(order);
}));

// Deny order (Admin only)
app.patch("/admin/orders/:orderId/deny", authenticateToken, requireAdmin, asyncHandler(async (req, res) => {
  const { orderId } = req.params;
  const { reason } = req.body;
  
  if (!mongoose.Types.ObjectId.isValid(orderId)) {
    return res.status(400).json({ error: "Invalid order ID" });
  }
  
  const order = await Order.findById(orderId);
  
  if (!order) {
    return res.status(404).json({ error: "Order not found" });
  }
  
  order.admin_approval = {
    status: 'denied',
    approved_by: req.user.id,
    approved_at: new Date(),
    denial_reason: reason || 'Not specified'
  };
  
  await order.save();
  await order.populate('handled_by.user_id', 'name email');
  await order.populate('admin_approval.approved_by', 'name email');
  
  console.log(`❌ Order ${order.order_number} denied by admin`);
  
  // Broadcast update
  broadcast('order_updated', order.toObject());
  
  res.json(order);
}));

// Get admin dashboard stats
app.get("/admin/dashboard/stats", authenticateToken, requireAdmin, asyncHandler(async (req, res) => {
  const { date, startDate, endDate } = req.query;
  
  let dateFilter = {};
  
  // Single date filter
  if (date) {
    const startOfDay = new Date(date);
    startOfDay.setHours(0, 0, 0, 0);
    const endOfDay = new Date(date);
    endOfDay.setHours(23, 59, 59, 999);
    
    dateFilter['handled_by.updated_at'] = {
      $gte: startOfDay,
      $lte: endOfDay
    };
  }
  // Date range filter
  else if (startDate || endDate) {
    dateFilter['handled_by.updated_at'] = {};
    if (startDate) {
      const start = new Date(startDate);
      start.setHours(0, 0, 0, 0);
      dateFilter['handled_by.updated_at'].$gte = start;
    }
    if (endDate) {
      const end = new Date(endDate);
      end.setHours(23, 59, 59, 999);
      dateFilter['handled_by.updated_at'].$lte = end;
    }
  }
  
  // Get all non-admin users
  const users = await User.find({ isAdmin: false }).select('_id name email').lean();
  
  // Get orders handled by each user
  const userOrderStats = await Promise.all(
    users.map(async (user) => {
      const userFilter = {
        'handled_by.user_id': user._id,
        ...dateFilter
      };
      
      const [statusCounts, approvalCounts, totalOrders] = await Promise.all([
        Order.aggregate([
          { $match: userFilter },
          {
            $group: {
              _id: '$status',
              count: { $sum: 1 }
            }
          }
        ]),
        Order.aggregate([
          { $match: userFilter },
          {
            $group: {
              _id: '$admin_approval.status',
              count: { $sum: 1 }
            }
          }
        ]),
        Order.countDocuments(userFilter)
      ]);
      
      const stats = {
        total: totalOrders,
        delivered: 0,
        in_progress: 0,
        cancelled: 0,
        rescheduled: 0,
        pending: 0,
        confirmed: 0,
        denied: 0,
        pending_approval: 0
      };
      
      statusCounts.forEach(item => {
        stats[item._id] = item.count;
      });
      
      approvalCounts.forEach(item => {
        if (item._id === 'confirmed') stats.confirmed = item.count;
        if (item._id === 'denied') stats.denied = item.count;
        if (item._id === 'pending') stats.pending_approval = item.count;
      });
      
      return {
        user,
        stats
      };
    })
  );
  
  // Sort by total orders (most active first)
  userOrderStats.sort((a, b) => b.stats.total - a.stats.total);
  
  res.json(userOrderStats);
}));

// Get today's activity summary
app.get("/admin/today-summary", authenticateToken, requireAdmin, asyncHandler(async (req, res) => {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const tomorrow = new Date(today);
  tomorrow.setDate(tomorrow.getDate() + 1);
  
  const dateFilter = {
    'handled_by.updated_at': {
      $gte: today,
      $lt: tomorrow
    }
  };
  
  const [totalOrders, pendingApproval, confirmed, denied, users] = await Promise.all([
    Order.countDocuments(dateFilter),
    Order.countDocuments({ ...dateFilter, 'admin_approval.status': 'pending' }),
    Order.countDocuments({ ...dateFilter, 'admin_approval.status': 'confirmed' }),
    Order.countDocuments({ ...dateFilter, 'admin_approval.status': 'denied' }),
    User.countDocuments({ isAdmin: false })
  ]);
  
  res.json({
    date: today.toISOString().split('T')[0],
    totalOrders,
    pendingApproval,
    confirmed,
    denied,
    activeUsers: users
  });
}));

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


