const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const prisma = require('../prisma');

const accessTokenTTL = 600; // 10 минут
const refreshTokenTTL = 60 * 60 * 24 * 7; // 7 дней

const secretKey = process.env.JWT_SECRET;

function generateTokens(userId) {
    const accessToken = jwt.sign({userId}, secretKey, {expiresIn: accessTokenTTL});
    const refreshToken = jwt.sign({userId}, secretKey, {expiresIn: refreshTokenTTL});
    return {accessToken, refreshToken};
}

async function verifyAccessToken(token) {
    try {
        const decodedToken = jwt.verify(token, secretKey);
        const userId = decodedToken.userId;

        const user = await prisma.user.findUnique({
            where: {
                id: userId,
            },
        });

        if (!user || user.accessToken !== token) {
            return false;
        }

        return user;
    } catch (error) {
        return false;
    }
}

async function verifyRefreshToken(token) {
    try {
        const decodedToken = jwt.verify(token, secretKey);
        console.log(decodedToken);
        const userId = decodedToken.userId;

        const user = await prisma.user.findUnique({
            where: {
                id: userId,
            },
        });

        if (!user || user.refreshToken !== token) {
            return false;
        }

        return user;
    } catch (error) {
        return false;
    }
}

function setAuthorizationHeader(res, token) {
    res.header('Authorization', 'Bearer ' + token)
}

function setRefreshTokenCookie(res, token) {
    res.cookie('refreshToken', token, {httpOnly: true, sameSite: 'strict'})
}

async function authenticateJWT(req, res, next) {
    const authHeader = req.headers.authorization;

    let user = null;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const accessToken = authHeader.split(' ')[1];
        if (accessToken)
            user = await verifyAccessToken(accessToken);
    }

    if (!user) {
        const refreshToken = req.cookies.refreshToken;

        if (refreshToken) {
            user = await verifyRefreshToken(refreshToken);
            if (user) {
                const {accessToken: newAccessToken} = generateTokens(user.id);

                await prisma.user.update({
                    where: {
                        id: user.id,
                    },
                    data: {
                        accessToken: newAccessToken,
                    }
                });

                setAuthorizationHeader(res, newAccessToken);
            }
        }
    }

    if (!user) {
        return res.status(401).json({error: `Unauthorized`});
    }

    req.userId = user.id;
    next();
}

router.post('/signup', async (req, res) => {
    const id = req.body.id;
    const password = req.body.password;

    if (!id || !/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/g.test(id)) {
        return res.status(400).json({error: `Parameter 'id' should be valid email`});
    }
    if (!password || password.length < 6 || password.length > 64) {
        return res.status(400).json({error: `Parameter 'password' should be string with length from 6 to 64`});
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        const {accessToken, refreshToken} = generateTokens(id);

        await prisma.user.create({
            data: {
                id,
                password: hashedPassword,
                accessToken,
                refreshToken
            }
        });

        setAuthorizationHeader(res, accessToken);
        setRefreshTokenCookie(res, refreshToken);
        res.status(201).json({id});
    } catch (error) {
        console.error(error);
        res.status(500).json({error: 'Error creating user'});
    }
});

router.post('/signin', async (req, res) => {
    const id = req.body.id;
    const password = req.body.password;

    if (!id) {
        return res.status(400).json({error: `Parameter 'id' is required`});
    }
    if (!password) {
        return res.status(400).json({error: `Parameter 'password' is required`});
    }

    const user = await prisma.user.findUnique({
        where: {
            id,
        },
    });

    if (!user) {
        return res.status(401).json({error: 'Incorrect username'});
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
        return res.status(401).json({error: 'Incorrect username or password'});
    }

    const {accessToken, refreshToken} = generateTokens(id);
    await prisma.user.update({
        where: {
            id,
        },
        data: {
            accessToken,
            refreshToken
        }
    });

    setAuthorizationHeader(res, accessToken);
    setRefreshTokenCookie(res, refreshToken);
    res.status(200).json({id});
});

router.post('/signin/new_token', async (req, res) => {
    const refreshToken = req.cookies.refreshToken;


    const user = await verifyRefreshToken(refreshToken);

    if (!user) {
        return res.status(500).json({error: 'Error refreshing token'});
    }

    const {accessToken: newAccessToken} = generateTokens(user.id);

    console.log(newAccessToken);

    await prisma.user.update({
        where: {
            id: user.id,
        },
        data: {
            accessToken: newAccessToken,
        }
    });
    setAuthorizationHeader(res, newAccessToken);
    return res.status(200).json({message: 'success'});
});

router.get('/logout', authenticateJWT, async (req, res) => {
    const userId = req.userId;

    await prisma.user.update({
        where: {
            id: userId,
        },
        data: {
            accessToken: null,
            refreshToken: null,
        },
    });

    setAuthorizationHeader(res, null);
    setRefreshTokenCookie(res, null);
    res.status(200).json({message: 'success'});
});

router.get('/info', authenticateJWT, async (req, res) => {
    const userId = req.userId;

    res.status(200).json({
        data: {
            id: userId
        }
    });
});

module.exports = {
    router,
    authenticateJWT
};
