import express from 'express';
import multer from 'multer';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'hamzzcloud_secret_key_change_this';
const API_KEY_PREFIX = 'hk_';

// Middleware
app.use(express.static(path.join(__dirname, '..')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ============ MONGODB SCHEMAS ============

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  role: { type: String, default: 'user' },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

const apiKeySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  apiKey: { type: String, unique: true, required: true },
  name: { type: String, required: true },
  plan: { type: String, default: 'free' },
  rateLimit: { type: Number, default: 100 },
  requestsUsed: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  lastUsed: { type: Date },
  isActive: { type: Boolean, default: true }
});

const fileSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  apiKeyId: { type: mongoose.Schema.Types.ObjectId, ref: 'ApiKey' },
  filename: String,
  originalName: String,
  size: Number,
  type: String,
  data: Buffer,
  expiryOption: { type: String, default: 'never' },
  expiredAt: { type: Date, default: null },
  uploadedAt: { type: Date, default: Date.now }
});

fileSchema.index({ expiredAt: 1 }, { expireAfterSeconds: 0 });

const User = mongoose.model('User', userSchema);
const ApiKey = mongoose.model('ApiKey', apiKeySchema);
const File = mongoose.model('File', fileSchema);

// ============ DATABASE CONNECTION ============

const MONGODB_URI = process.env.MONGODB_URI;

console.log('MONGODB_URI exists:', !!MONGODB_URI);
if (MONGODB_URI) {
  console.log('MONGODB_URI prefix:', MONGODB_URI.substring(0, 20));
}

const connectionOptions = {
  serverSelectionTimeoutMS: 30000,
  connectTimeoutMS: 30000,
  socketTimeoutMS: 45000,
  family: 4,
  maxPoolSize: 10,
  minPoolSize: 2
};

let cached = global.mongoose;
if (!cached) {
  cached = global.mongoose = { conn: null, promise: null };
}

async function connectDB() {
  if (cached.conn) {
    console.log('Using cached connection');
    return cached.conn;
  }

  if (!cached.promise) {
    console.log('Creating new connection to MongoDB...');
    console.log('Connection string:', MONGODB_URI ? MONGODB_URI.replace(/:.+?@/, ':****@') : 'undefined');
    
    cached.promise = mongoose.connect(MONGODB_URI, connectionOptions).then((mongoose) => {
      console.log('✅ MongoDB connected successfully');
      return mongoose;
    }).catch(err => {
      console.error('❌ MongoDB connection error:', err.message);
      console.error('Full error:', err);
      cached.promise = null;
      throw err;
    });
  }
  
  cached.conn = await cached.promise;
  return cached.conn;
}

// Health check endpoint dengan debug
app.get('/api/health', async (req, res) => {
  const dbState = mongoose.connection.readyState;
  const states = {
    0: 'disconnected',
    1: 'connected',
    2: 'connecting',
    3: 'disconnecting'
  };
  
  let errorMsg = null;
  try {
    await connectDB();
  } catch (err) {
    errorMsg = err.message;
  }
  
  res.json({
    status: 'ok',
    database: states[dbState] || 'unknown',
    mongodb_uri_configured: !!MONGODB_URI,
    mongodb_uri_prefix: MONGODB_URI ? MONGODB_URI.substring(0, 30) : null,
    error: errorMsg,
    timestamp: new Date().toISOString()
  });
});

// Test connection endpoint
app.get('/api/test-db', async (req, res) => {
  try {
    await connectDB();
    const result = await mongoose.connection.db.admin().ping();
    res.json({ success: true, ping: result });
  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});

// ============ AUTH ENDPOINTS ============

app.post('/api/auth/register', async (req, res) => {
  try {
    await connectDB();
    const { username, email, password } = req.body;
    
    const existing = await User.findOne({ $or: [{ username }, { email }] });
    if (existing) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({
      username,
      email,
      password: hashedPassword
    });
    
    const apiKey = API_KEY_PREFIX + crypto.randomBytes(32).toString('hex');
    await ApiKey.create({
      userId: user._id,
      apiKey: apiKey,
      name: 'Default API Key',
      plan: 'free',
      rateLimit: 100
    });
    
    const token = jwt.sign({ userId: user._id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({ success: true, token, user: { id: user._id, username: user.username, email: user.email } });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    await connectDB();
    const { username, password } = req.body;
    
    const user = await User.findOne({ $or: [{ username }, { email: username }] });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ userId: user._id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({ success: true, token, user: { id: user._id, username: user.username, email: user.email, role: user.role } });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/auth/me', async (req, res) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    await connectDB();
    const user = await User.findById(decoded.userId).select('-password');
    const apiKeys = await ApiKey.find({ userId: decoded.userId });
    res.json({ user, apiKeys });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.post('/api/keys', async (req, res) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    await connectDB();
    const { name, plan } = req.body;
    const planLimits = { free: 100, basic: 1000, pro: 10000, enterprise: 100000 };
    const apiKey = API_KEY_PREFIX + crypto.randomBytes(32).toString('hex');
    const keyDoc = await ApiKey.create({
      userId: decoded.userId,
      apiKey: apiKey,
      name: name || 'New API Key',
      plan: plan || 'free',
      rateLimit: planLimits[plan] || 100
    });
    res.json({ success: true, apiKey: keyDoc.apiKey, name: keyDoc.name, plan: keyDoc.plan });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/keys', async (req, res) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    await connectDB();
    const keys = await ApiKey.find({ userId: decoded.userId });
    res.json(keys);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/keys/:id', async (req, res) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    await connectDB();
    await ApiKey.findOneAndDelete({ _id: req.params.id, userId: decoded.userId });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

function getExpiryDate(expiryOption) {
  const now = new Date();
  switch (expiryOption) {
    case '5m': return new Date(now.getTime() + 5 * 60 * 1000);
    case '1d': return new Date(now.getTime() + 24 * 60 * 60 * 1000);
    case '7d': return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    case '30d': return new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
    default: return null;
  }
}

async function authenticateAPIKey(apiKey) {
  await connectDB();
  return await ApiKey.findOne({ apiKey: apiKey, isActive: true });
}

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

app.post('/api/upload', upload.single('file'), async (req, res) => {
  const apiKey = req.headers['x-api-key'] || req.query.api_key;
  if (!apiKey) return res.status(401).json({ error: 'API key required' });
  
  try {
    const keyDoc = await authenticateAPIKey(apiKey);
    if (!keyDoc) return res.status(401).json({ error: 'Invalid API key' });
    
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    
    keyDoc.lastUsed = new Date();
    keyDoc.requestsUsed += 1;
    await keyDoc.save();
    
    const expiryOption = req.body.expiry || 'never';
    const expiredAt = getExpiryDate(expiryOption);
    
    const fileDoc = new File({
      apiKeyId: keyDoc._id,
      userId: keyDoc.userId,
      filename: req.file.originalname,
      originalName: req.file.originalname,
      size: req.file.size,
      type: req.file.mimetype,
      data: req.file.buffer,
      expiryOption: expiryOption,
      expiredAt: expiredAt
    });
    
    const result = await fileDoc.save();
    res.json({ success: true, fileId: result._id, url: `/api/file/${result._id}` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/file/:id', async (req, res) => {
  try {
    await connectDB();
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).json({ error: 'File not found' });
    if (file.expiredAt && new Date() > file.expiredAt) return res.status(410).json({ error: 'File expired' });
    res.setHeader('Content-Type', file.type);
    res.send(file.data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/files', async (req, res) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    await connectDB();
    const files = await File.find({ userId: decoded.userId, $or: [{ expiredAt: null }, { expiredAt: { $gt: new Date() } }] }, { data: 0 }).sort({ uploadedAt: -1 }).limit(50);
    res.json(files);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Static pages
app.get('/docs', (req, res) => res.sendFile(path.join(__dirname, '..', 'docs.html')));
app.get('/pricing', (req, res) => res.sendFile(path.join(__dirname, '..', 'pricing.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, '..', 'login.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, '..', 'dashboard.html')));
app.get('/upload', (req, res) => res.sendFile(path.join(__dirname, '..', 'upload.html')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, '..', 'index.html')));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
