import type { Request, Response, NextFunction } from "express";
import { type JwtPayload, verify } from "jsonwebtoken";
import config from "../config";

declare global {
    namespace Express {
        interface Request {
            signedToken: string | JwtPayload
        }
    }
}

export default function authMiddleware(req: Request, res: Response, next: NextFunction) {
    const token = req.headers.authorization;
    if (!token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    try {
        const secretOrPrivateKey = Buffer.from(config.get('publicKey'), 'base64')
        const signedToken = verify(token.split(' ')[1], secretOrPrivateKey)
        req.signedToken = signedToken;
        next();
    } catch (error) {
        return res.status(401).json({ error: error });
    }
}