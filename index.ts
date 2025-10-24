import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import mongoose from 'mongoose';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import mongoSanitize from 'express-mongo-sanitize';
import compression from 'compression';
import { body, validationResult } from 'express-validator';
import nodemailer from 'nodemailer';
import crypto from 'crypto';
import NodeCache from 'node-cache';

const app = express();
// Optimized cache settings for better performance

// Trust proxy for Render/Vercel (Fixes express-rate-limit issue)
app.set('trust proxy', 1);

// Enable security and performance middlewares
app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                scriptSrc: ["'self'"],
                imgSrc: ["'self'", 'data:', 'https:'],
            },
        },
    })
);
app.use(compression());
app.use(
    cors({
        origin: process.env.FRONTEND_URL || 'http://localhost:3000',
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization', 'Cache-Control', 'Accept'],
    })
);
app.use(
    express.json({
        limit: '10kb',
        verify: (req, res, buf) => {
            (req as any).rawBody = buf;
        },
    })
);
app.use(express.urlencoded({ extended: true }));

// 3. Safe sanitize (Fixes “Skipping sanitize on non-plain object”)
app.use((req, res, next) => {
    try {
        if (req.is('multipart/form-data')) return next(); // Skip on file uploads
        mongoSanitize({ replaceWith: '_' })(req, res, next);
    } catch (err) {
        console.warn('Skipping sanitize on non-plain object:', err instanceof Error ? err.message : 'Unknown error');
        next();
    }
});


const cache = new NodeCache({
    stdTTL: 600, // 10 minutes default TTL
    checkperiod: 120, // Check for expired keys every 2 minutes
    useClones: false, // Don't clone objects for better performance
    deleteOnExpire: true, // Automatically delete expired keys
    maxKeys: 1000 // Limit cache size to prevent memory issues
});

// Security and Performance Middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
}));
app.use(compression()); // Enable gzip compression
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Cache-Control', 'Accept']
}));
app.use(express.json({
    limit: '10kb',
    verify: (req, res, buf) => {
        // Store raw body for potential signature verification
        (req as any).rawBody = buf;
    }
}));
// app.use(mongoSanitize({
//     replaceWith: '_',
// }));


app.use((req, res, next) => {
    try {
        mongoSanitize()(req, res, next);
    } catch (err) {
        console.warn('Skipping sanitize on non-plain object:', err instanceof Error ? err.message : 'Unknown error');
        next();
    }
});

// Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Too many requests from this IP'
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: 'Too many OTP attempts'
});

app.use('/api/', limiter);
app.use('/api/auth/', authLimiter);

// MongoDB Connection with optimized settings
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/usermanagement', {
    maxPoolSize: 20, // Increased pool size for better concurrency
    minPoolSize: 5, // Maintain minimum connections
    maxIdleTimeMS: 30000, // Close connections after 30s of inactivity
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
    retryWrites: true, // Enable retryable writes
    retryReads: true, // Enable retryable reads
});

// User Schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true, maxlength: 100 },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
        match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    },
    phone: {
        type: String,
        required: true,
        unique: true,
        match: /^[0-9]{10}$/
    },
    addr: { type: String, required: true, maxlength: 500 },
    otp: { type: String, select: false },
    otpExpiry: { type: Date, select: false },
    verified: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
}, {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
});

// Optimized indexes for better query performance
// Note: email and phone already have unique indexes from schema definition
userSchema.index({ createdAt: -1 }); // For sorting by creation date (most recent first)
userSchema.index({ verified: 1, createdAt: -1 }); // Compound index for verified users with date sorting
// Note: email + verified compound index not needed since email is already unique

const User = mongoose.model('User', userSchema);

// Nodemailer Configuration
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST || 'smtp.gmail.com',
    port: Number(process.env.EMAIL_PORT) || 465,
    secure: true, // true for port 465
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
    connectionTimeout: 10000,
    greetingTimeout: 5000,
    socketTimeout: 10000,
    pool: true,
    maxConnections: 3,
    maxMessages: 50,
    tls: {
        rejectUnauthorized: false,
    },
});

// Utility Functions
const generateOTP = (): string => {
    return crypto.randomInt(100000, 999999).toString();
};

const sendOTPEmail = async (email: string, otp: string): Promise<void> => {
    try {
        // Verify transporter configuration first
        await transporter.verify();

        const mailOptions = {
            from: process.env.EMAIL_FROM || 'noreply@usermgmt.com',
            to: email,
            subject: 'Your OTP for Verification',
            html: `<p>Your OTP is: <strong>${otp}</strong></p><p>Valid for 10 minutes.</p>`
        };

        const info = await transporter.sendMail(mailOptions);
        console.log('Email sent successfully:', info.messageId);
    } catch (error: any) {
        console.error('Email sending failed:', {
            error: error.message,
            code: error.code,
            command: error.command,
            response: error.response
        });
        throw new Error(`Failed to send email: ${error.message}`);
    }
};

// Validation Middleware
const validateUser = [
    body('name').trim().notEmpty().isLength({ max: 100 }).withMessage('Name is required (max 100 chars)'),
    body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
    body('phone').matches(/^[0-9]{10}$/).withMessage('Phone must be 10 digits'),
    body('addr').trim().notEmpty().isLength({ max: 500 }).withMessage('Address required (max 500 chars)')
];

const validateOTP = [
    body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
    body('otp').isLength({ min: 6, max: 6 }).withMessage('OTP must be 6 digits')
];

// Error Handler
const asyncHandler = (fn: Function) => (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
};

// Routes

// Health check with database status
app.get('/api/health', async (req, res) => {
    try {
        const dbStatus = mongoose.connection.readyState;
        const dbStates = ['disconnected', 'connected', 'connecting', 'disconnecting'];

        res.json({
            success: true,
            message: 'Server is running',
            timestamp: new Date().toISOString(),
            database: {
                status: dbStates[dbStatus],
                connected: dbStatus === 1
            },
            cache: {
                keys: cache.keys().length,
                stats: cache.getStats()
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Health check failed',
            error: error instanceof Error ? error.message : 'Unknown error'
        });
    }
});

// Generate OTP
app.post('/api/auth/generate-otp', validateOTP.slice(0, 1), asyncHandler(async (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
        return res.status(404).json({ success: false, message: 'User not found' });
    }

    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

    user.otp = otp;
    user.otpExpiry = otpExpiry;
    await user.save();

    try {
        await sendOTPEmail(email, otp);
    } catch (error: any) {
        console.error('Email send error:', error);
        return res.status(500).json({
            success: false,
            message: 'Failed to send OTP email. Please try again later.',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }

    res.json({
        success: true,
        message: 'OTP generated',
        otp, // For demo purposes only - remove in production
        expiresIn: '10 minutes'
    });
}));

// Verify OTP
app.post('/api/auth/verify-otp', validateOTP, asyncHandler(async (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    const { email, otp } = req.body;
    const user = await User.findOne({ email }).select('+otp +otpExpiry');

    if (!user) {
        return res.status(404).json({ success: false, message: 'User not found' });
    }

    if (!user.otp || user.otp !== otp) {
        return res.status(400).json({ success: false, message: 'Invalid OTP' });
    }

    if (!user.otpExpiry || user.otpExpiry < new Date()) {
        return res.status(400).json({ success: false, message: 'OTP expired' });
    }

    user.verified = true;
    user.otp = undefined;
    user.otpExpiry = undefined;
    await user.save();

    // Clear all user list cache entries
    const keys = cache.keys();
    keys.forEach(key => {
        if (key.startsWith('users_list_')) {
            cache.del(key);
        }
    });

    res.json({ success: true, message: 'User verified successfully' });
}));

// Create User
app.post('/api/users', validateUser, asyncHandler(async (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    const { name, email, phone, addr } = req.body;

    // Optimized query using indexes
    const existingUser = await User.findOne({
        $or: [{ email }, { phone }]
    }).lean();
    if (existingUser) {
        return res.status(409).json({
            success: false,
            message: existingUser.email === email ? 'Email already exists' : 'Phone already exists'
        });
    }

    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

    const user = await User.create({
        name,
        email,
        phone,
        addr,
        otp,
        otpExpiry
    });

    try {
        await sendOTPEmail(email, otp);
    } catch (error: any) {
        console.error('Email send error:', error);
        return res.status(500).json({
            success: false,
            message: 'User created but failed to send OTP email. Please try generating OTP again.',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }

    // Clear all user list cache entries
    const keys = cache.keys();
    keys.forEach(key => {
        if (key.startsWith('users_list_')) {
            cache.del(key);
        }
    });

    res.status(201).json({
        success: true,
        data: user,
        otp, // For demo purposes only
        message: 'User created. OTP sent to email.'
    });
}));

// Get All Users
app.get('/api/users', asyncHandler(async (req: Request, res: Response) => {
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 10;
    const skip = (page - 1) * limit;

    const cacheKey = `users_list_${page}_${limit}`;
    const cached = cache.get(cacheKey);

    if (cached) {
        return res.json(cached);
    }

    // Optimized query with projection to reduce data transfer
    const [users, total] = await Promise.all([
        User.find({}, {
            name: 1,
            email: 1,
            phone: 1,
            addr: 1,
            verified: 1,
            createdAt: 1,
            updatedAt: 1
        })
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .lean(),
        User.countDocuments()
    ]);

    const response = {
        success: true,
        data: users,
        pagination: {
            page,
            limit,
            total,
            pages: Math.ceil(total / limit)
        }
    };

    cache.set(cacheKey, response);
    res.json(response);
}));

// Get User by ID
app.get('/api/users/:id', asyncHandler(async (req: Request, res: Response) => {
    const { id } = req.params;

    if (!id || !mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ success: false, message: 'Invalid user ID' });
    }

    const cacheKey = `user_${id}`;
    const cached = cache.get(cacheKey);

    if (cached) {
        return res.json(cached);
    }

    const user = await User.findById(id as string).lean();

    if (!user) {
        return res.status(404).json({ success: false, message: 'User not found' });
    }

    const response = { success: true, data: user };
    cache.set(cacheKey, response);
    res.json(response);
}));

// Update User
app.put('/api/users/:id', validateUser, asyncHandler(async (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
    }

    const { id } = req.params;
    const { name, email, phone, addr } = req.body;

    if (!id || !mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ success: false, message: 'Invalid user ID' });
    }

    // Check if user exists first
    const existingUser = await User.findById(id as string);
    if (!existingUser) {
        return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Check for duplicates (excluding current user) - optimized query
    const duplicate = await User.findOne({
        $or: [{ email }, { phone }],
        _id: { $ne: id }
    }).lean();

    if (duplicate) {
        return res.status(409).json({
            success: false,
            message: duplicate.email === email ? 'Email already exists' : 'Phone already exists'
        });
    }

    const user = await User.findByIdAndUpdate(
        id,
        { name, email, phone, addr, updatedAt: Date.now() },
        { new: true, runValidators: true }
    );

    if (!user) {
        return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Clear relevant cache entries
    cache.del('users_list');
    cache.del(`user_${id}`);
    // Clear all user list cache entries
    const keys = cache.keys();
    keys.forEach(key => {
        if (key.startsWith('users_list_')) {
            cache.del(key);
        }
    });

    res.json({ success: true, data: user, message: 'User updated successfully' });
}));

// Delete User
app.delete('/api/users/:id', asyncHandler(async (req: Request, res: Response) => {
    const { id } = req.params;

    if (!id || !mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ success: false, message: 'Invalid user ID' });
    }

    // Check if user exists first
    const existingUser = await User.findById(id as string);
    if (!existingUser) {
        return res.status(404).json({ success: false, message: 'User not found' });
    }

    const user = await User.findByIdAndDelete(id as string);

    if (!user) {
        return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Clear relevant cache entries
    cache.del('users_list');
    cache.del(`user_${id}`);
    // Clear all user list cache entries
    const keys = cache.keys();
    keys.forEach(key => {
        if (key.startsWith('users_list_')) {
            cache.del(key);
        }
    });

    res.json({ success: true, message: 'User deleted successfully' });
}));

// Performance monitoring middleware
app.use((req: Request, res: Response, next: NextFunction) => {
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
    });
    next();
});

// Global Error Handler
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    console.error(err.stack);
    res.status(err.status || 500).json({
        success: false,
        message: err.message || 'Internal server error'
    });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});