import jwt from 'jsonwebtoken';

import dotenv from "dotenv";
dotenv.config();

const secretKey = process.env.JWT_SECRET;

export function verifyToken(req, res, next) {

    // Authorization: Bearer <token>

    const bearerHeader = req.headers['authorization'];

    if(typeof bearerHeader !== "undefined"){
        const bearer = bearerHeader.split(" ")

        const bearerToken = bearer[1];

        // req.token = bearerToken;

        jwt.verify(bearerToken, secretKey, (err, authData) =>{
            if (err){
                return res.status(403).json({
                    status: "error",
                    timestamp: Date.now(),
                    data: {
                        message: "FORBIDDEN! - Invalid or expired token.",
                        status: 403
                    }
                });
            } else {
                req.user = authData;
                next()
            }
        })

        // next();
    } else {
        // FORBIDDEN
        return res.status(401).json({
            status : "error",
            timestamp : Date.now(),
            data : {
                message: "UNAUTHORIZED! - Token not provided.",
                status: 401
            }
        })
    }
}