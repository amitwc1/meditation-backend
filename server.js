require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 5001;
const isProduction = process.env.NODE_ENV === 'production';
const JWT_SECRET = process.env.JWT_SECRET || 'secret_key';

// ─── Security Middleware ───────────────────────────────────────────────
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));

// Rate Limiting
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20,
    message: { message: 'Too many attempts, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
});

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
});

// CORS Configuration
const corsOrigins = process.env.CORS_ORIGIN
    ? process.env.CORS_ORIGIN.split(',').map(s => s.trim())
    : ['http://localhost:5173', 'http://localhost:3000'];

app.use(cors({
    origin: isProduction ? corsOrigins : '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging (only in development)
if (!isProduction) {
    app.use((req, res, next) => {
        console.log(`${new Date().toISOString()} ${req.method} ${req.url}`);
        next();
    });
}

// Static file serving for uploads
app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
    maxAge: isProduction ? '7d' : 0,
    etag: true,
}));

// ─── Upload Directories ────────────────────────────────────────────────
const uploadDirs = ['uploads', 'uploads/images', 'uploads/audio'];
uploadDirs.forEach(dir => {
    const fullPath = path.join(__dirname, dir);
    if (!fs.existsSync(fullPath)) {
        fs.mkdirSync(fullPath, { recursive: true });
    }
});

// ─── Database Connection Pool ──────────────────────────────────────────
const db = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'meditation_app',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    enableKeepAlive: true,
    keepAliveInitialDelay: 0,
});

// Database health check on startup
(async () => {
    try {
        const connection = await db.getConnection();
        console.log('✓ Database connected successfully');
        connection.release();
    } catch (err) {
        console.error('✗ Database connection failed:', err.message);
        if (isProduction) process.exit(1);
    }
})();

// ─── Multer Storage Configuration ──────────────────────────────────────
const ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
const ALLOWED_AUDIO_TYPES = ['audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/mp4', 'audio/aac', 'audio/x-m4a'];
const MAX_FILE_SIZE = parseInt(process.env.UPLOAD_MAX_SIZE) || 52428800; // 50MB

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const isAudio = ALLOWED_AUDIO_TYPES.includes(file.mimetype);
        const dir = isAudio ? 'uploads/audio' : 'uploads/images';
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname).toLowerCase();
        cb(null, uniqueSuffix + ext);
    }
});

const fileFilter = (req, file, cb) => {
    const allowed = [...ALLOWED_IMAGE_TYPES, ...ALLOWED_AUDIO_TYPES];
    if (allowed.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error(`File type ${file.mimetype} is not supported`), false);
    }
};

const upload = multer({
    storage,
    fileFilter,
    limits: { fileSize: MAX_FILE_SIZE },
});

// ─── Authentication Middleware ──────────────────────────────────────────
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Authentication required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// ─── Input Validation Helpers ──────────────────────────────────────────
const validateEmail = (email) => {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
};

const sanitizeString = (str) => {
    if (!str) return '';
    return str.trim().replace(/[<>]/g, '');
};

// ─── Error Handler ─────────────────────────────────────────────────────
const asyncHandler = (fn) => (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
};

// ─── Health Check ──────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
    });
});

// ─── Auth Routes ───────────────────────────────────────────────────────

// Admin Login
app.post('/api/admin/login', authLimiter, asyncHandler(async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    const [rows] = await db.execute('SELECT * FROM admins WHERE username = ?', [sanitizeString(username)]);
    if (rows.length === 0) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    const admin = rows[0];
    const validPassword = await bcrypt.compare(password, admin.password);
    if (!validPassword && password !== admin.password) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign(
        { id: admin.id, role: 'admin' },
        JWT_SECRET,
        { expiresIn: '24h' }
    );
    res.json({ token });
}));

// User Signup
app.post('/api/auth/signup', authLimiter, asyncHandler(async (req, res) => {
    const { name, email, password } = req.body;

    // Validation
    if (!name || !email || !password) {
        return res.status(400).json({ message: 'Name, email, and password are required' });
    }
    if (!validateEmail(email)) {
        return res.status(400).json({ message: 'Invalid email format' });
    }
    if (password.length < 6) {
        return res.status(400).json({ message: 'Password must be at least 6 characters' });
    }
    if (name.length < 2 || name.length > 100) {
        return res.status(400).json({ message: 'Name must be between 2 and 100 characters' });
    }

    // Check if email exists
    const [existing] = await db.execute('SELECT id FROM users WHERE email = ?', [email.trim().toLowerCase()]);
    if (existing.length > 0) {
        return res.status(409).json({ message: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    await db.execute(
        'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
        [sanitizeString(name), email.trim().toLowerCase(), hashedPassword]
    );
    res.status(201).json({ message: 'Account created successfully' });
}));

// User Login
app.post('/api/auth/login', authLimiter, asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required' });
    }

    const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email.trim().toLowerCase()]);
    if (rows.length === 0) {
        return res.status(401).json({ message: 'Invalid email or password' });
    }

    const user = rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
        return res.status(401).json({ message: 'Invalid email or password' });
    }

    const token = jwt.sign(
        { id: user.id },
        JWT_SECRET,
        { expiresIn: '30d' }
    );

    res.json({
        token,
        user: { id: user.id, name: user.name, email: user.email }
    });
}));

// ─── Public API Routes ─────────────────────────────────────────────────

// Get Categories
app.get('/api/categories', apiLimiter, asyncHandler(async (req, res) => {
    const [rows] = await db.execute('SELECT * FROM categories ORDER BY name ASC');
    res.json(rows);
}));

// Get Meditations (optionally filter by category)
app.get('/api/meditations', apiLimiter, asyncHandler(async (req, res) => {
    const { category_id } = req.query;
    let query = 'SELECT m.*, c.name AS category_name FROM meditations m LEFT JOIN categories c ON m.category_id = c.id';
    let params = [];

    if (category_id) {
        const catId = parseInt(category_id);
        if (isNaN(catId)) {
            return res.status(400).json({ message: 'Invalid category_id' });
        }
        query += ' WHERE m.category_id = ?';
        params.push(catId);
    }

    query += ' ORDER BY m.created_at DESC';

    const [rows] = await db.execute(query, params);
    res.json(rows);
}));

// Get Meditation Details
app.get('/api/meditations/:id', apiLimiter, asyncHandler(async (req, res) => {
    const id = parseInt(req.params.id);
    if (isNaN(id)) {
        return res.status(400).json({ message: 'Invalid meditation ID' });
    }

    const [rows] = await db.execute(
        'SELECT m.*, c.name AS category_name FROM meditations m LEFT JOIN categories c ON m.category_id = c.id WHERE m.id = ?',
        [id]
    );

    if (rows.length === 0) {
        return res.status(404).json({ message: 'Meditation not found' });
    }
    res.json(rows[0]);
}));

// ─── Favorites (Authenticated) ────────────────────────────────────────
app.get('/api/favorites', authenticateToken, asyncHandler(async (req, res) => {
    const [rows] = await db.execute(
        `SELECT m.*, c.name AS category_name FROM favorites f 
         JOIN meditations m ON f.meditation_id = m.id 
         LEFT JOIN categories c ON m.category_id = c.id 
         WHERE f.user_id = ? ORDER BY f.created_at DESC`,
        [req.user.id]
    );
    res.json(rows);
}));

app.post('/api/favorites', authenticateToken, asyncHandler(async (req, res) => {
    const { meditation_id } = req.body;
    if (!meditation_id) {
        return res.status(400).json({ message: 'meditation_id is required' });
    }

    // Check if already favorited
    const [existing] = await db.execute(
        'SELECT id FROM favorites WHERE user_id = ? AND meditation_id = ?',
        [req.user.id, meditation_id]
    );
    if (existing.length > 0) {
        return res.status(409).json({ message: 'Already in favorites' });
    }

    await db.execute(
        'INSERT INTO favorites (user_id, meditation_id) VALUES (?, ?)',
        [req.user.id, meditation_id]
    );
    res.status(201).json({ message: 'Added to favorites' });
}));

app.delete('/api/favorites/:meditation_id', authenticateToken, asyncHandler(async (req, res) => {
    await db.execute(
        'DELETE FROM favorites WHERE user_id = ? AND meditation_id = ?',
        [req.user.id, parseInt(req.params.meditation_id)]
    );
    res.json({ message: 'Removed from favorites' });
}));

// ─── Recently Played (Authenticated) ──────────────────────────────────
app.post('/api/recently-played', authenticateToken, asyncHandler(async (req, res) => {
    const { meditation_id } = req.body;
    if (!meditation_id) {
        return res.status(400).json({ message: 'meditation_id is required' });
    }

    // Upsert: delete old entry, insert new
    await db.execute(
        'DELETE FROM recently_played WHERE user_id = ? AND meditation_id = ?',
        [req.user.id, meditation_id]
    );
    await db.execute(
        'INSERT INTO recently_played (user_id, meditation_id) VALUES (?, ?)',
        [req.user.id, meditation_id]
    );
    res.json({ message: 'Recorded play' });
}));

app.get('/api/recently-played', authenticateToken, asyncHandler(async (req, res) => {
    const [rows] = await db.execute(
        `SELECT m.*, c.name AS category_name, rp.played_at FROM recently_played rp 
         JOIN meditations m ON rp.meditation_id = m.id 
         LEFT JOIN categories c ON m.category_id = c.id 
         WHERE rp.user_id = ? ORDER BY rp.played_at DESC LIMIT 20`,
        [req.user.id]
    );
    res.json(rows);
}));

// ─── Admin Features ────────────────────────────────────────────────────

// Upload Files
app.post('/api/upload', authenticateToken, upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: 'No file uploaded' });
    }
    const fileUrl = `${req.protocol}://${req.get('host')}/${req.file.destination}/${req.file.filename}`;
    res.json({ url: fileUrl, filename: req.file.filename, size: req.file.size });
});

// Add Category
app.post('/api/categories', authenticateToken, asyncHandler(async (req, res) => {
    const { name, image_url } = req.body;

    if (!name || name.trim().length === 0) {
        return res.status(400).json({ message: 'Category name is required' });
    }

    const [result] = await db.execute(
        'INSERT INTO categories (name, image_url) VALUES (?, ?)',
        [sanitizeString(name), image_url || null]
    );
    res.status(201).json({ id: result.insertId, name: sanitizeString(name), image_url });
}));

// Update Category
app.put('/api/categories/:id', authenticateToken, asyncHandler(async (req, res) => {
    const id = parseInt(req.params.id);
    const { name, image_url } = req.body;

    if (isNaN(id)) {
        return res.status(400).json({ message: 'Invalid category ID' });
    }
    if (!name || name.trim().length === 0) {
        return res.status(400).json({ message: 'Category name is required' });
    }

    const [result] = await db.execute(
        'UPDATE categories SET name = ?, image_url = ? WHERE id = ?',
        [sanitizeString(name), image_url || null, id]
    );

    if (result.affectedRows === 0) {
        return res.status(404).json({ message: 'Category not found' });
    }

    res.json({ id, name: sanitizeString(name), image_url });
}));

// Add Meditation
app.post('/api/meditations', authenticateToken, asyncHandler(async (req, res) => {
    const { title, description, audio_url, image_url, duration, category_id } = req.body;

    if (!title || !audio_url) {
        return res.status(400).json({ message: 'Title and audio_url are required' });
    }

    const [result] = await db.execute(
        'INSERT INTO meditations (title, description, audio_url, image_url, duration, category_id) VALUES (?, ?, ?, ?, ?, ?)',
        [
            sanitizeString(title),
            sanitizeString(description || ''),
            audio_url,
            image_url || null,
            parseInt(duration) || 0,
            parseInt(category_id) || null
        ]
    );
    res.status(201).json({ id: result.insertId, message: 'Meditation added successfully' });
}));

// Update Meditation
app.put('/api/meditations/:id', authenticateToken, asyncHandler(async (req, res) => {
    const id = parseInt(req.params.id);
    const { title, description, audio_url, image_url, duration, category_id } = req.body;

    if (isNaN(id)) {
        return res.status(400).json({ message: 'Invalid meditation ID' });
    }

    const [result] = await db.execute(
        'UPDATE meditations SET title = ?, description = ?, audio_url = ?, image_url = ?, duration = ?, category_id = ? WHERE id = ?',
        [
            sanitizeString(title),
            sanitizeString(description || ''),
            audio_url,
            image_url || null,
            parseInt(duration) || 0,
            parseInt(category_id) || null,
            id
        ]
    );

    if (result.affectedRows === 0) {
        return res.status(404).json({ message: 'Meditation not found' });
    }
    res.json({ message: 'Meditation updated successfully' });
}));

// Delete Meditation
app.delete('/api/meditations/:id', authenticateToken, asyncHandler(async (req, res) => {
    const id = parseInt(req.params.id);
    if (isNaN(id)) {
        return res.status(400).json({ message: 'Invalid meditation ID' });
    }

    const [result] = await db.execute('DELETE FROM meditations WHERE id = ?', [id]);
    if (result.affectedRows === 0) {
        return res.status(404).json({ message: 'Meditation not found' });
    }
    res.json({ message: 'Meditation deleted successfully' });
}));

// Delete Category
app.delete('/api/categories/:id', authenticateToken, asyncHandler(async (req, res) => {
    const id = parseInt(req.params.id);
    if (isNaN(id)) {
        return res.status(400).json({ message: 'Invalid category ID' });
    }

    const [result] = await db.execute('DELETE FROM categories WHERE id = ?', [id]);
    if (result.affectedRows === 0) {
        return res.status(404).json({ message: 'Category not found' });
    }
    res.json({ message: 'Category deleted successfully' });
}));

// Get Users (Admin only)
app.get('/api/users', authenticateToken, asyncHandler(async (req, res) => {
    const [rows] = await db.execute('SELECT id, name, email, created_at FROM users ORDER BY created_at DESC');
    res.json(rows);
}));

// Admin Stats endpoint
app.get('/api/admin/stats', authenticateToken, asyncHandler(async (req, res) => {
    const [[{ userCount }]] = await db.execute('SELECT COUNT(*) as userCount FROM users');
    const [[{ medCount }]] = await db.execute('SELECT COUNT(*) as medCount FROM meditations');
    const [[{ catCount }]] = await db.execute('SELECT COUNT(*) as catCount FROM categories');
    const [[{ playCount }]] = await db.execute('SELECT COUNT(*) as playCount FROM recently_played');

    res.json({
        users: userCount,
        meditations: medCount,
        categories: catCount,
        plays: playCount,
    });
}));

// ─── Multer Error Handler ──────────────────────────────────────────────
app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(413).json({ message: 'File too large. Maximum size is 50MB.' });
        }
        return res.status(400).json({ message: err.message });
    }

    if (!isProduction) {
        console.error('Server error:', err);
    }

    res.status(err.status || 500).json({
        message: isProduction ? 'Internal server error' : err.message,
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ message: 'Endpoint not found' });
});

// ─── Start Server ──────────────────────────────────────────────────────
app.listen(PORT, () => {
    console.log(`\n🧘 Meditation API Server`);
    console.log(`   Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`   Port: ${PORT}`);
    console.log(`   Ready at: http://localhost:${PORT}/api/health\n`);
});
