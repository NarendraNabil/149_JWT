const db = require('../models');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const User = db.User;
const SALT_ROUNDS = 10;

function isNonEmptyString(value) {
    return typeof value === 'string' && value.trim().length > 0;
}

function sendInternalServerError(res, error, action) {
    console.error(`Error ${action}:`, error);
    return res.status(500).json({ message: 'Internal Server Error' });
}

async function register(req, res) {
    const { email, password } = req.body || {};

    if (!isNonEmptyString(email) || typeof password !== 'string' || password.length === 0) {
        return res.status(400).json({ message: 'Email dan password wajib diisi' });
    }

    const normalizedEmail = email.trim();

    try {
        const existingUser = await User.findOne({ where: { email: normalizedEmail } });
        if (existingUser) {
            return res.status(400).json({ message: 'Email sudah terdaftar' });
        }

        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        const user = await User.create({
            email: normalizedEmail,
            password: hashedPassword
        });

        return res.status(201).json({
            message: 'Registrasi berhasil',
            data: {
                id: user.id,
                email: user.email
            }
        });
    } catch (error) {
        if (error.name === 'SequelizeUniqueConstraintError') {
            return res.status(400).json({ message: 'Email sudah terdaftar' });
        }

        return sendInternalServerError(res, error, 'registering user');
    }
}

async function login(req, res) {
    const { email, password } = req.body || {};

    if (!isNonEmptyString(email) || typeof password !== 'string' || password.length === 0) {
        return res.status(400).json({ message: 'Email dan password wajib diisi' });
    }

    try {
        const user = await User.findOne({
            where: { email: email.trim() }
        });

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ message: 'Email atau password salah.' });
        }

        const jwtSecret = process.env.JWT_SECRET;
        const jwtExpires = process.env.JWT_EXPIRES;
        if (!jwtSecret || !jwtExpires) {
            console.error('JWT_SECRET and JWT_EXPIRES must be configured.');
            return res.status(500).json({ message: 'Internal Server Error' });
        }

        const token = jwt.sign(
            {
                id: user.id,
                email: user.email
            },
            jwtSecret,
            { expiresIn: jwtExpires }
        );

        return res.status(200).json({
            message: 'Login berhasil',
            token
        });
    } catch (error) {
        return sendInternalServerError(res, error, 'logging in user');
    }
}

module.exports = {
    register,
    login
};
