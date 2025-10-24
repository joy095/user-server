import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import mongoose from 'mongoose';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import mongoSanitize from 'express-mongo-sanitize';
import compression from 'compression';
import { body, validationResult } from 'express-validator';
import crypto from 'crypto';
import NodeCache from 'node-cache';

const app = express();

// Trust proxy for Render/Vercel
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

// Safe sanitize
app.use((req, res, next) => {
    try {
        if (req.is('multipart/form-data')) return next();
        mongoSanitize({ replaceWith: '_' })(req, res, next);
    } catch (err) {
        next(); // Silently skip sanitization errors
    }
});

const cache = new NodeCache({
    stdTTL: 600,
    checkperiod: 120,
    useClones: false,
    deleteOnExpire: true,
    maxKeys: 1000
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

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/usermanagement', {
    maxPoolSize: 20,
    minPoolSize: 5,
    maxIdleTimeMS: 30000,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
    retryWrites: true,
    retryReads: true,
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

userSchema.index({ createdAt: -1 });
userSchema.index({ verified: 1, createdAt: -1 });

const User = mongoose.model('User', userSchema);

// Email Service Configuration
// Using Resend API (works reliably on Render)
const sendOTPEmail = async (email: string, otp: string): Promise<void> => {
    const apiKey = process.env.RESEND_API_KEY;

    // Development mode - just log OTP
    if (!apiKey || process.env.NODE_ENV === 'development') {
        console.log(`📧 [DEV MODE] OTP for ${email}: ${otp}`);
        console.log(`⚠️  Set RESEND_API_KEY env variable for production`);
        return;
    }

    try {
        const response = await fetch('https://api.resend.com/emails', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${apiKey}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                from: process.env.EMAIL_FROM || 'onboarding@resend.dev',
                to: email,
                subject: 'Your OTP for Verification',
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <h2 style="color: #333;">Verification Code</h2>
                        <p>Your OTP verification code is:</p>
                        <div style="background: #f4f4f4; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0;">
                            <h1 style="color: #2563eb; margin: 0; font-size: 32px; letter-spacing: 5px;">${otp}</h1>
                        </div>
                        <p style="color: #666;">This code will expire in 10 minutes.</p>
                        <p style="color: #999; font-size: 12px; margin-top: 30px;">If you didn't request this code, please ignore this email.</p>
                    </div>
                `,
            }),
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(`Resend API error: ${response.status} - ${JSON.stringify(errorData)}`);
        }

        const data = await response.json();
        console.log('✅ Email sent successfully:', data.id);
    } catch (error: any) {
        console.error('❌ Email sending failed:', error.message);
        throw new Error(`Failed to send email: ${error.message}`);
    }
};

// Alternative: SendGrid Implementation (uncomment if you prefer SendGrid)
/*
const sendOTPEmailSendGrid = async (email: string, otp: string): Promise<void> => {
    const apiKey = process.env.SENDGRID_API_KEY;
    
    if (!apiKey) {
        console.log(`📧 [DEV MODE] OTP for ${email}: ${otp}`);
        return;
    }

    try {
        const response = await fetch('https://api.sendgrid.com/v3/mail/send', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${apiKey}`,
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                personalizations: [{
                    to: [{ email }],
                    subject: 'Your OTP for Verification',
                }],
                from: {
                    email: process.env.EMAIL_FROM || 'noreply@yourdomain.com',
                    name: 'User Management'
                },
                content: [{
                    type: 'text/html',
                    value: `<p>Your OTP is: <strong>${otp}</strong></p><p>Valid for 10 minutes.</p>`
                }]
            }),
        });

        if (!response.ok) {
            throw new Error(`SendGrid API error: ${response.status}`);
        }

        console.log('✅ Email sent via SendGrid');
    } catch (error: any) {
        console.error('❌ Email sending failed:', error.message);
        throw new Error(`Failed to send email: ${error.message}`);
    }
};
*/

// Utility Functions
const generateOTP = (): string => {
    return crypto.randomInt(100000, 999999).toString();
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

// Health check
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
            email: {
                service: process.env.RESEND_API_KEY ? 'Resend' : 'Development (Console)',
                configured: !!process.env.RESEND_API_KEY
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

        res.json({
            success: true,
            message: 'OTP sent to email',
            ...(process.env.NODE_ENV === 'development' && { otp }), // Show OTP only in dev
            expiresIn: '10 minutes'
        });
    } catch (error: any) {
        console.error('Email send error:', error);
        return res.status(500).json({
            success: false,
            message: 'Failed to send OTP email. Please try again later.',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
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

    // Clear cache
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

        // Clear cache
        const keys = cache.keys();
        keys.forEach(key => {
            if (key.startsWith('users_list_')) {
                cache.del(key);
            }
        });

        res.status(201).json({
            success: true,
            data: user,
            ...(process.env.NODE_ENV === 'development' && { otp }), // Show OTP only in dev
            message: 'User created. OTP sent to email.'
        });
    } catch (error: any) {
        console.error('Email send error:', error);
        return res.status(500).json({
            success: false,
            message: 'User created but failed to send OTP email. Please generate OTP again.',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
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

    const existingUser = await User.findById(id as string);
    if (!existingUser) {
        return res.status(404).json({ success: false, message: 'User not found' });
    }

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

    // Clear cache
    cache.del(`user_${id}`);
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

    const existingUser = await User.findById(id as string);
    if (!existingUser) {
        return res.status(404).json({ success: false, message: 'User not found' });
    }

    const user = await User.findByIdAndDelete(id as string);

    if (!user) {
        return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Clear cache
    cache.del(`user_${id}`);
    const keys = cache.keys();
    keys.forEach(key => {
        if (key.startsWith('users_list_')) {
            cache.del(key);
        }
    });

    res.json({ success: true, message: 'User deleted successfully' });
}));

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
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📧 Email service: ${process.env.RESEND_API_KEY ? 'Resend (Production)' : 'Console (Development)'}`);
    console.log(`🗄️  Database: ${process.env.MONGODB_URI ? 'MongoDB Atlas' : 'Local MongoDB'}`);
});