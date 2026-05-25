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
  rateLimit: { type: Number, default: 20 },
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

mongoose.connect(MONGODB_URI, {
  serverSelectionTimeoutMS: 5000
}).then(async () => {
  console.log('MongoDB connected');
  await File.collection.createIndex({ expiredAt: 1 }, { expireAfterSeconds: 0 });
  
  const adminExists = await User.findOne({ username: 'admin' });
  if (!adminExists) {
    const hashedPassword = await bcrypt.hash('admin123', 10);
    await User.create({
      username: 'admin',
      email: 'admin@hamzz.cloud',
      password: hashedPassword,
      role: 'admin'
    });
    console.log('Default admin created: admin / admin123');
  }
}).catch(err => {
  console.error('MongoDB connection error:', err);
});

// ============ HELPER FUNCTIONS ============

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

function generateApiKey() {
  return API_KEY_PREFIX + crypto.randomBytes(32).toString('hex');
}

async function authenticateAPIKey(apiKey) {
  const keyDoc = await ApiKey.findOne({ apiKey: apiKey, isActive: true });
  if (!keyDoc) return null;
  
  keyDoc.lastUsed = new Date();
  keyDoc.requestsUsed += 1;
  await keyDoc.save();
  
  return keyDoc;
}

async function apiKeyAuth(req, res, next) {
  const apiKey = req.headers['x-api-key'] || req.query.api_key;
  
  if (!apiKey) {
    return res.status(401).json({ error: 'API key required', docs: '/docs' });
  }
  
  const keyDoc = await authenticateAPIKey(apiKey);
  if (!keyDoc) {
    return res.status(401).json({ error: 'Invalid or inactive API key' });
  }
  
  if (keyDoc.requestsUsed >= keyDoc.rateLimit) {
    return res.status(429).json({ error: 'Rate limit exceeded. Upgrade your plan.' });
  }
  
  req.apiKey = keyDoc;
  next();
}

async function jwtAuth(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }
});

// ============ AUTH ENDPOINTS ============

app.post('/api/auth/register', async (req, res) => {
  try {
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
    
    const apiKey = generateApiKey();
    await ApiKey.create({
      userId: user._id,
      apiKey: apiKey,
      name: 'Default API Key',
      plan: 'free',
      rateLimit: 20
    });
    
    const token = jwt.sign({ userId: user._id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({ success: true, token, user: { id: user._id, username: user.username, email: user.email } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
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
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/auth/me', jwtAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    const apiKeys = await ApiKey.find({ userId: req.user.userId });
    
    res.json({ user, apiKeys });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ API KEY MANAGEMENT ============

app.post('/api/keys', jwtAuth, async (req, res) => {
  try {
    const { name, plan } = req.body;
    
    const planLimits = {
      free: 20,
      basic: 100,
      pro: 1000,
      enterprise: 10000
    };
    
    const apiKey = generateApiKey();
    const keyDoc = await ApiKey.create({
      userId: req.user.userId,
      apiKey: apiKey,
      name: name || 'New API Key',
      plan: plan || 'free',
      rateLimit: planLimits[plan] || 20
    });
    
    res.json({ success: true, apiKey: keyDoc.apiKey, name: keyDoc.name, plan: keyDoc.plan, rateLimit: keyDoc.rateLimit });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/keys', jwtAuth, async (req, res) => {
  try {
    const keys = await ApiKey.find({ userId: req.user.userId });
    res.json(keys);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/keys/:id', jwtAuth, async (req, res) => {
  try {
    await ApiKey.findOneAndDelete({ _id: req.params.id, userId: req.user.userId });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ UPLOAD ENDPOINT ============

app.post('/api/upload', apiKeyAuth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const expiryOption = req.body.expiry || 'never';
    const expiredAt = getExpiryDate(expiryOption);

    const fileDoc = new File({
      apiKeyId: req.apiKey._id,
      userId: req.apiKey.userId,
      filename: req.file.originalname,
      originalName: req.file.originalname,
      size: req.file.size,
      type: req.file.mimetype,
      data: req.file.buffer,
      expiryOption: expiryOption,
      expiredAt: expiredAt
    });

    const result = await fileDoc.save();
    
    let expiryMessage = '';
    if (expiryOption === '5m') expiryMessage = 'File akan expired dalam 5 menit';
    else if (expiryOption === '1d') expiryMessage = 'File akan expired dalam 1 hari';
    else if (expiryOption === '7d') expiryMessage = 'File akan expired dalam 7 hari';
    else if (expiryOption === '30d') expiryMessage = 'File akan expired dalam 30 hari';
    else expiryMessage = 'File tidak akan expired';
    
    res.json({
      success: true,
      fileId: result._id,
      url: `/api/file/${result._id}`,
      fullUrl: `${req.protocol}://${req.get('host')}/api/file/${result._id}`,
      expiry: expiryOption,
      expiryMessage: expiryMessage,
      expiredAt: expiredAt,
      remainingQuota: req.apiKey.rateLimit - req.apiKey.requestsUsed
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ GET FILE ============

app.get('/api/file/:id', async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    
    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }
    
    if (file.expiredAt && new Date() > file.expiredAt) {
      return res.status(410).json({ error: 'File has expired' });
    }
    
    res.setHeader('Content-Type', file.type);
    res.setHeader('Content-Disposition', `inline; filename="${file.originalName}"`);
    res.send(file.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ GET FILES LIST ============

app.get('/api/files', jwtAuth, async (req, res) => {
  try {
    const files = await File.find(
      { 
        userId: req.user.userId,
        $or: [
          { expiredAt: null },
          { expiredAt: { $gt: new Date() } }
        ]
      },
      { data: 0 }
    )
      .sort({ uploadedAt: -1 })
      .limit(50);
    
    res.json(files);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ STATIC PAGES ============

app.get('/docs', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'docs.html'));
});

app.get('/pricing', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'pricing.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'login.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'dashboard.html'));
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});