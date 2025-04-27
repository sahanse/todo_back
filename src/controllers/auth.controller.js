import { ApiError } from "../utils/ApiErros.js";
import {ApiResponse} from "../utils/ApiResponse.js"
import { asyncHandler } from "../utils/AsyncHandler.js";
import db from "../db/index.js"
import crypto from "crypto"
import {bcryptCompare, bcryptHash} from "../utils/Bcrypt.js"
import {mailSender} from "../utils/EmailManager.js"
import {createLoginToken, create_reg_verify_token , create_access_reg_token, create_login_verify_Token, create_access_login_token} from "../utils/JwtManager.js"
import {option} from "../utils/constant.js"
import jwt from "jsonwebtoken"

const generateRegisterOtp = asyncHandler(async(req, res)=>{
    console.log("generating otp")
    const {access_token_cookie, refresh_token_cookie, register_token_cookie} = req.cookies;
    if(access_token_cookie || refresh_token_cookie) throw new ApiError(401, 'Unauthorized access');
    if(!register_token_cookie) throw new ApiError(401, 'Unauthorized access');

    //get data from cookie
    let register_token_data = null
    try {
        const decoded_token = await jwt.verify(register_token_cookie, process.env.REGISTER_TOKEN_SECRET);
        register_token_data = decoded_token;
    } catch (error) {
        console.log(error)
        throw new ApiError(500, 'something went wrong')
    };
    if(!register_token_data) throw new ApiError(500, 'something went wrong');
    const {email, token_pass} = register_token_data;
    
    //verify token pass
    const verify_token_pass = bcryptCompare(process.env.REGISTER_TOKEN_PASS, token_pass);
    if(!verify_token_pass) throw new ApiError(401, 'Unauthorized access');

    //generate otp
    const otp = crypto.randomInt(10000, 100000);
    const hashed_otp = await bcryptHash(String(otp));

    try {
        const response = await db.query(
            `INSERT INTO otp (email, otp, created_at, method)
             VALUES ($1, $2, NOW(), $3)
             ON CONFLICT (email) DO UPDATE
             SET 
             otp = EXCLUDED.otp,
             created_at = NOW(),
             method = EXCLUDED.method,
             user_id = EXCLUDED.user_id
             WHERE otp.created_at + interval '3 minutes' < NOW();`,[email, hashed_otp, 'register']
        );
        if(response.rowCount === 0) throw new ApiError(400, 'Please wait untill previous otp expires')
    } catch (error) {
        if(error instanceof ApiError){
            throw error
        }
        throw new ApiError(500, 'something went wrong');
    };

    const email_subject = 'Otp for email verification';
    const email_content =`Otp to complete your registration is ${otp}`
   
    // send otp email to user
    // try {
    //     const send_user_email = await mailSender(email,email_subject, email_content);
    // } catch (error) {
    //     throw new ApiError(500, 'something went wrong')
    // };

    const register_verify_pass = await bcryptHash(process.env.REGISTER_VERIFY_PASS);
    const register_ver_token = await create_reg_verify_token ({email, pass:register_verify_pass})

    console.log(otp)
    return res
    .status(200)
    .cookie('register_verify_cookie', register_ver_token, {...option, maxAge: 1000 * 60 * 3})
    .json(new ApiResponse(200, {otp}, 'Otp sent successfully'));
});

const verifyRegisterOtp = asyncHandler(async(req, res)=>{
   const {access_token_cookie, refresh_token_cookie, register_token_cookie, register_verify_cookie} = req.cookies;
   if(access_token_cookie || refresh_token_cookie) throw new ApiError(401, 'Unauthorized access');
   if(!register_verify_cookie) throw new ApiError(401, 'Unauthorized access');

    const {otp} = req.body;
    if(!otp) throw new ApiError(400, 'please provide otp');
    if(String(otp).trim() === '') throw new ApiError(400, 'Null value received at otp');

    //verify token 
    let token_data = null;
    try {
        const decoded_token = await jwt.verify(register_verify_cookie, process.env.REGISTER_VERIFY_SECRET);
        token_data = decoded_token;
    } catch (error) {
        throw new ApiError(401, 'Unauthorized access');
    };
    if(!token_data) throw new ApiError(500, 'something went wrong');

    const {email, pass} = token_data;
    if(!email || !pass) throw new ApiError(401, 'Unauthorized access');

    //verify cookie pass
    const verify_token_pass = await bcryptCompare(String(process.env.REGISTER_VERIFY_PASS),pass);
    if(!verify_token_pass) throw new ApiError(401, 'Unauthorized access');

    //get data from otp
    let stored_otp_data = null;
    try {
        const response = await db.query(
            `SELECT otp, method
            from otp
            WHERE email = $1
            AND created_at + interval '3 minutes' >= NOW()`,[email]
        );
       if(response.rowCount === 0) throw new ApiError(400, 'Otp expired')
       stored_otp_data = response.rows[0]
    } catch (error) {
        if(error instanceof ApiError){
            throw error
        }
        throw new ApiError(500, 'something went wrong')
    };
    if(!stored_otp_data) throw new ApiError(500, 'something went wrong');

    const stored_otp = stored_otp_data.otp;
    const stored_method = stored_otp_data.method;

    if(stored_method !== 'register') throw new ApiError(500, 'Unauthorized access');
    
    //comapre both otp
    const compare_otp = await bcryptCompare(String(otp), stored_otp);
    if(!compare_otp) throw new ApiError(400, 'Wrong otp');

    res.clearCookie('register_verify_cookie');
    res.clearCookie('register_token_cookie');
    //delete the otp
    try {
        const response = await db.query(
            `DELETE FROM otp
            WHERE email = $1`,[email]
        );
        if(response.rowCount === 0) throw new ApiError(500, 'something went wrong');
    } catch (error) {
        if(error instanceof ApiError){
            throw error
        };
        throw new ApiError(500, 'something went wrong');
    };

    const reg_access_pass = await bcryptHash(String(process.env.ACCESS_REG_PASS));

    const reg_access_token = await create_access_reg_token({email, pass:reg_access_pass});

    return res
    .status(200)
    .cookie('access_reg_token', reg_access_token, option)
    .json(new ApiResponse(200, {}, 'otp verifed successfully'))
});

const generateLoginOtp = asyncHandler(async(req, res)=>{
    const {access_token_cookie, refresh_token_cookie, login_token_cookie} = req.cookies;
    if(access_token_cookie || refresh_token_cookie) throw new ApiError(401, 'Unauthorized access');
    if(!login_token_cookie) throw new ApiError(401, 'Unauthorized access');

    //verify token 
    let login_token_data = null;
    try {
        const verify_login_token = await jwt.verify(login_token_cookie, process.env.LOGIN_TOKEN_SECRET);
        login_token_data = verify_login_token;
    } catch (error) {
        
        throw new ApiError(401, 'Unauthorized access')
    };
    
    if(!login_token_data) throw new ApiError(500, 'something went wrong');

    const {id, name, email, pass} = login_token_data;

    //compare both token pass
    const compare_token_pass = await bcryptCompare(String(process.env.LOGIN_VERIFY_PASS), pass);
    if(compare_token_pass) throw new ApiError(401, 'Unauthorized access pass');

    //generate otp
    const otp = crypto.randomInt(10000, 100000);
    const hashed_otp = await bcryptHash(String(otp));

    //save otp in to db
    try {
        const response = await db.query(
            `INSERT INTO otp (email, otp, created_at, method)
             VALUES ($1, $2, NOW(), $3)
             ON CONFLICT (email) DO UPDATE
             SET 
             otp = EXCLUDED.otp,
             created_at = NOW(),
             method = EXCLUDED.method,
             user_id = EXCLUDED.user_id
             WHERE otp.created_at + interval '3 minutes' < NOW();`,[email, hashed_otp, 'login']
        );
        if(response.rowCount === 0) throw new ApiError(400, 'Please wait untill previous otp expires')
    } catch (error) {
        if(error instanceof ApiError){
            throw error
        }
        throw new ApiError(500, 'something went wrong');
    };

    const email_subject = 'Otp for email verification';
    const email_content =`Otp to complete your login is ${otp}`
   
    //send otp email to user
    // try {
    //     const send_user_email = await mailSender(email,email_subject, email_content);
    // } catch (error) {
    //     throw new ApiError(500, 'something went wrong')
    // };

    const login_verify_pass = await bcryptHash(process.env.LOGIN_VERIFY_PASS);
    const login_ver_token = await create_login_verify_Token ({id, name, email, pass:login_verify_pass});

    console.log(otp);

    return res
    .status(200)
    .cookie('login_verify_cookie', login_ver_token, {...option, maxAge: 1000 * 60 * 3})
    .json(new ApiResponse(200, {otp}, 'Otp sent successfully'));
});

const verifyLoginOtp = asyncHandler(async(req, res)=>{
    const {access_token_cookie, refresh_token_cookie, login_verify_cookie} = req.cookies;
    if(access_token_cookie || refresh_token_cookie) throw new ApiError(401, 'Unauthorized access');
    if(!login_verify_cookie) throw new ApiError(401, 'Unauthorized access');

    const {otp} = req.body;
    if(!otp) throw new ApiError(400, 'please provide otp');
    if(String(otp).trim() === '') throw new ApiError(400, 'Null value received in otp');

    //verify cookie
    let verify_login_data = null;
    try {
        const verify_login_token = await jwt.verify(login_verify_cookie, process.env.LOGIN_VERIFY_SECRET)
        verify_login_data = verify_login_token;
    } catch (error) {
        throw new ApiError(401, 'Unauthorized access');
    };
    if(!verify_login_data) throw new ApiError(500, 'Something went wrong');

    const {id, name, email, pass} = verify_login_data;
    
    
    //verify token pass
    const verify_token_pass = await bcryptCompare(String(process.env.LOGIN_VERIFY_PASS), pass);
    if(!verify_token_pass) throw new ApiError(401, 'Unauthorized access pas');

    //get data from otp
    let stored_otp_data = null;
    try {
        const response = await db.query(
            `SELECT otp, method
            from otp
            WHERE email = $1
            AND created_at + interval '3 minutes' >= NOW()`,[email]
        );
       if(response.rowCount === 0) throw new ApiError(400, 'Otp expired')
       stored_otp_data = response.rows[0]
    } catch (error) {
        if(error instanceof ApiError){
            throw error
        }
        throw new ApiError(500, 'something went wrong')
    };
    if(!stored_otp_data) throw new ApiError(500, 'something went wrong');

    const stored_otp = stored_otp_data.otp;
    const stored_method = stored_otp_data.method;

    if(stored_method !== 'login') throw new ApiError(500, 'Unauthorized access');
    
    //comapre both otp
    const compare_otp = await bcryptCompare(String(otp), stored_otp);
    if(!compare_otp) throw new ApiError(400, 'Wrong otp');

    res.clearCookie('login_verify_cookie');
    res.clearCookie('login_token_cookie');


    //delete the otp
    try {
        const response = await db.query(
            `DELETE FROM otp
            WHERE email = $1`,[email]
        );
        if(response.rowCount === 0) throw new ApiError(500, 'something went wrong');
    } catch (error) {
        if(error instanceof ApiError){
            throw error
        };
        throw new ApiError(500, 'something went wrong');
    };

    const login_access_pass = await bcryptHash(String(process.env.ACCESS_LOGIN_PASS));
    const login_access_token = await create_access_login_token({id, name, email, pass:login_access_pass});

    return res
    .status(200)
    .cookie('access_login_token', login_access_token, option)
    .json(new ApiResponse(200, {}, 'otp verifed successfully'))
});


export { 
    generateRegisterOtp,
    generateLoginOtp,
    verifyRegisterOtp,
    verifyLoginOtp
}
