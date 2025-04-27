import { ApiError } from "../utils/ApiErros.js";
import jwt from "jsonwebtoken"
import {asyncHandler} from "../utils/AsyncHandler.js"
import db from "../db/index.js"

const verifyJwt = asyncHandler(async(req, _, next)=>{
    const {access_token_cookie} = req.cookies;
    if(!access_token_cookie) throw new ApiError(401, 'unauthorized access');

    try {
        //verify access token
        const verify_access_token = jwt.verify(access_token_cookie, process.env.ACCESS_TOKEN_SECRET);
   
        //make sure user exist in db
        const userExistDb = await db.query(
            `SELECT 
            id FROM users 
            WHERE id = $1`,[verify_access_token.id]
        );
        if(userExistDb.rowCount === 0) throw new ApiError(500, 'something went wrong');

        req.user = verify_access_token;
        next()
    } catch (error) {
        throw new ApiError(401, 'unauthorized access')
    }
});

const verifyAuth = asyncHandler(async(req, _, next)=>{
    const {access_token_cookie} = req.cookies;
    
    if(access_token_cookie){
        try {
            //verify access token
            const verify_access_token = jwt.verify(access_token_cookie, process.env.ACCESS_TOKEN_SECRET);
       
            //make sure user exist in db
            const userExistDb = await db.query(
                `SELECT 
                id FROM users 
                WHERE id = $1`,[verify_access_token.id]
            );
            if(userExistDb.rowCount === 0) throw new ApiError(500, 'something went wrong');
    
            req.user = verify_access_token;
            next()
        } catch (error) {
            throw new ApiError(401, 'unauthorized access')
        }
    }else{
        req.user = null;
        next();
    }
});

export {
    verifyJwt,
    verifyAuth
};
