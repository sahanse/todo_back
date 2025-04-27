import { ApiError } from "../utils/ApiErros.js";
import {ApiResponse} from "../utils/ApiResponse.js"
import {asyncHandler} from "../utils/AsyncHandler.js"
import db from "../db/index.js"
import {bcryptHash, bcryptCompare} from "../utils/Bcrypt.js";
import {createAccessToken, createRefreshToken, createToken, createLoginToken, createRegisterToken} from "../utils/JwtManager.js"
import {option} from "../utils/constant.js"
import jwt from "jsonwebtoken"

const userRegister = asyncHandler(async(req, res)=>{
    const {access_token_cookie, refresh_token_cookie, register_token_cookie, access_reg_token} = req.cookies;
    if(access_token_cookie || refresh_token_cookie) throw new ApiError(400, 'logout to continue');
    
    const {name, email, password} = req.body;
    const bodyKeys = Object.keys(req.body);
    const requiredFields = ['name', 'email', 'password'];

    //make sure all fields are provided
    for(let val of requiredFields){
        if(!bodyKeys.includes(val)) throw new ApiError(400, `Please provide ${val}`);
        if(String(req.body.val).trim() === '') throw new ApiError(400, `Null value received at ${val}`);
    }

    if(!access_reg_token){
        try {
            const registerUserDb = await db.query(
                `SELECT id
                FROM users WHERE email = $1`,[email]
            );
            if(registerUserDb.rowCount > 0) throw new ApiError(400, 'user with email alreday exist');
          } catch (error) {
           if (error instanceof ApiError) {
               throw error; // Already a custom error, rethrow as is
           }
           throw new ApiError(500, 'something went wrong');
          }
          const register_token_pass = await bcryptHash(String(process.env.REGISTER_TOKEN_PASS));
          const register_token = await createRegisterToken({email, token_pass:register_token_pass});
          Object.keys(req.cookies).forEach((cookie)=> res.clearCookie(cookie, {path:'/'}));

          return res
          .status(200)
          .cookie('register_token_cookie', register_token, option)
          .json(new ApiResponse(200, {}, 'please proceed for otp verification'))
    };

    if(access_reg_token){
        let register_token_data = null;
        try {
            const verify_reg_token = await jwt.verify(access_reg_token, process.env.ACCESS_REG_SECRET);
            register_token_data = verify_reg_token;
        } catch (error) {
            throw new ApiError(401, 'Uanuthorized access');
        };

        if(email !== register_token_data.email) throw new ApiError(401, 'Unauthorized access');

        //hash the user password
        const hashed_pass = await bcryptHash(password);

        //save the user into db
        let user_id = null;
        try {
            const response = await db.query(
                `INSERT INTO users
                (name, email, password)
                VALUES ($1, $2, $3) RETURNING id`,[name, email, hashed_pass]
            );
            if(response.rowCount === 0) throw new ApiError(500, 'something went wrong');
            user_id = response.rows[0].id;
        } catch (error) {
            if(error instanceof ApiError){
                throw error
            };
            throw new ApiError(500, 'something went wrong');
        }
        if(!user_id) throw new ApiError(500, 'something went wrong');

        const {accessToken, refreshToken} = createToken({name, email, id:user_id}, {id:user_id});

        //save refreshToken in db
        try {
            const response = await db.query(
                `UPDATE users
                SET refreshtoken = $1
                WHERE id = $2`,[refreshToken, user_id]
            );
            if(response.rowCount === 0) throw new ApiError(500, 'something went wrong');
        } catch (error) {
            if(error instanceof ApiError){
                throw error
            };
            throw new ApiError(500, 'something went wrong');
        }

        Object.keys(req.cookies).forEach((cookie)=> res.clearCookie(cookie));

        return res
        .status(200)
        .cookie('access_token_cookie', accessToken, {...option, maxAge:1000 * 60 * 60 * 24})
        .cookie('refresh_token_cookie', refreshToken, {...option, maxAge: 1000 * 60 * 60 * 24 * 10})
        .json(new ApiResponse(200, {id:user_id, name, email}, 'user registered successfully'))
    }
});

const authCheck = asyncHandler(async(req, res)=>{
    const {access_token_cookie, refresh_token_cookie} = req.cookies;
    if(!access_token_cookie && !refresh_token_cookie) throw new ApiError(401, 'Unauthorized access login to continue');
    if(access_token_cookie && !refresh_token_cookie){
        Object.keys(req.cookies).forEach((cookie)=> res.clearCookie(cookie));
        throw new ApiError(401, 'Unauthorized access login to continue');
    } 
    
    if(refresh_token_cookie && !access_token_cookie){
        let id = null;
        try {
            const decoded_refresh_token = jwt.verify(refresh_token_cookie, process.env.REFRESH_TOKEN_SECRET);
            id = decoded_refresh_token.id;
        } catch (error) {
            Object.keys(req.cookies).forEach((cookie)=> res.clearCookie(cookie));
            throw new ApiError(400, 'Unauthorized access login to continue');
        }

        if(!id) throw new ApiError(401, `Unauthorized access`);

        //make sure user exist in db
        let storedData = null;
        try {
            const userExistDb = await db.query(
                `SELECT 
                *FROM users
                 WHERE id = $1`,[id]
            );
            if(userExistDb.rowCount === 0){
                Object.keys(req.cookies).forEach((cookie)=> res.clearCookie(cookie));
                throw new ApiError(401, 'Unauthorized access');
            };
            storedData = userExistDb.rows[0];
        } catch (error) {
            if (error instanceof ApiError) {
                throw error; // Already a custom error, rethrow as is
            }
            Object.keys(req.cookies).forEach((cookie)=> res.clearCookie(cookie));
            throw new ApiError(500, 'something went wrong');
        };

        try {
            const verifyStoredToken  = jwt.verify(storedData.refreshtoken, process.env.REFRESH_TOKEN_SECRET);
        } catch (error) {
           throw new ApiError(401,`Unauthorized access`) 
        };
        delete storedData.refreshtoken;
        delete storedData.password;

        const accessToken = createAccessToken(storedData);
        if(!accessToken) throw new ApiError(500, 'something went wrong');

        delete storedData.id;

        return res
        .status(200)
        .cookie('access_token_cookie', accessToken, {...option, maxAge:1000 * 60 * 60 * 24})
        .json(new ApiResponse(200, {data:storedData}, 'Access token refreshed successfully'))
    };

    if(access_token_cookie && refresh_token_cookie){
        let access_token_data = null;
        let refresh_token_data = null;
        try {
            const decoded_access_token = jwt.verify(access_token_cookie, process.env.ACCESS_TOKEN_SECRET);
            access_token_data = decoded_access_token;
            const decoded_refresh_token = jwt.verify(refresh_token_cookie, process.env.REFRESH_TOKEN_SECRET);
            refresh_token_data = decoded_refresh_token;

            const checkUserExist = await db.query(
                `SELECT id
                FROM users 
                WHERE id = $1`,[access_token_data.id]
            );
            if(checkUserExist.rowCount === 0){
                Object.keys(req.cookies).forEach((cookie)=> res.clearCookie(cookie));
                
                throw new ApiError(401, 'Unauthorized access')  
            }
        } catch (error) {

            if(error instanceof ApiError){
                throw error
            };

            Object.keys(req.cookies).forEach((cookie)=> res.clearCookie(cookie))
            throw new ApiError(400, 'Unauthorized access');
        };

        if(!access_token_data) throw new ApiError(401, 'Unauthorized access');
        if(!refresh_token_data) throw new ApiError(401, 'Unauthorized access');
        if(access_token_data.id !== refresh_token_data.id) throw new ApiError(401, 'Unauthorized access');

        delete access_token_data.id;
        delete access_token_data.iat;
        delete access_token_data.exp

        return res
        .status(200)
        .json(new ApiResponse(200, {data:access_token_data}, 'user authenticated successfully'));
    }

});

const userLogin = asyncHandler(async(req, res)=>{
    const {access_token_cookie, refresh_token_cookie, access_login_token} = req.cookies;
    if(access_token_cookie || refresh_token_cookie) throw new ApiError(401, 'logout to continue');

    const {email, password} = req.body;
    if(!email || !password) throw new ApiError(400, 'please provide email and password');

    let required_fields = ['email', 'password'];
    for(let val in req.body){
        if(!required_fields.includes(val)) throw new ApiError(400, `unidentified filed ${val}`);
        if(String(req.body[val]).trim() === '') throw new ApiError(400, `Null value received at ${val}`);
    }
    
    if(!access_login_token){
        //make sure user exist 
        let user_exist_data = null;
        try {
            const response = await db.query(
                `SELECT id, name, email, password
                FROM users
                WHERE email = $1`,[email]
            );
            if(response.rowCount === 0) throw new ApiError(400, 'Account not found');
            user_exist_data = response.rows[0];
        } catch (error) {
            if(error instanceof ApiError){
                throw error
            }
            throw new ApiError(500, 'something went wrong')
        }

        //compare both password 
        const compare_pass = await bcryptCompare(String(password), user_exist_data.password);
        if(!compare_pass) throw new ApiError(400, 'Wrong password')

        const login_token_pass = await bcryptHash(String(process.env.LOGIN_TOKEN_PASS));

        const login_token_data = {
            id:user_exist_data.id,
            name:user_exist_data.name,
            email:user_exist_data.email,
            pass:login_token_pass
        }

        //create accessLogin token
        const login_token = await createLoginToken(login_token_data);

        if(!login_token) throw new ApiError(500, 'something went wrong');

        Object.keys(req.cookies).forEach((cookie)=> res.clearCookie(cookie));

        return res
        .status(200)
        .cookie('login_token_cookie', login_token, option)
        .json(new ApiResponse(200, {}, 'continue for otp verification'))
    };

    if(access_login_token){
        //verify access_login token
        let login_token_data = null;
        try {
            const verify_login_token = await jwt.verify(access_login_token, process.env.ACCESS_LOGIN_SECRET);
            login_token_data = verify_login_token;
        } catch (error) {
            Object.keys(req.cookies).forEach((cookie)=> res.clearCookie(cookie));
            throw new ApiError(401, 'Unauthroized access 1')
        }
        if(!login_token_data) throw new ApiError(500, 'Something went wrong 1');
        
        const {id, name, pass} = login_token_data;
        const token_mail = login_token_data.email;

        if(token_mail !== email) throw new ApiError(401, 'Unauthorized access 2');
        const verify_token_pass = await bcryptCompare(String(process.env.ACCESS_LOGIN_PASS), pass);
        if(!verify_token_pass) throw new ApiError(401, 'unauthorized access 3');

        //create refreshToken
        const {accessToken, refreshToken} = createToken({id,name, email}, {id});
        
        //store the refreshtoke in db
        try {
            const response = await db.query(
                `UPDATE users
                SET refreshtoken = $1
                WHERE email = $2`,[refreshToken, email]
            );
            if(response.rowCount === 0) throw new ApiError(500, 'something went wrong 4');
        } catch (error) {
            if(error instanceof ApiError){
                throw error
            };
            console.log(error)
            throw new ApiError(500, 'something went wrong 5');
        }

        Object.keys(req.cookies).forEach((cookie)=> res.clearCookie(cookie));

        return res
        .status(200)
        .cookie('access_token_cookie', accessToken,{...option, maxAge:1000 * 60 * 60 *24})
        .cookie('refresh_token_cookie', refreshToken, {...option, maxAge: 1000 * 60 * 60 * 24 * 10})
        .json(new ApiResponse(200, {}, 'login successfull'))
    }
});

const userLogout = asyncHandler(async(req, res)=>{
    const user = req.user;
    if(!user) throw new ApiError(401, 'Unauthorized access');

    //remove refreshtoken from db
    try {
        const removeTokenDb = await db.query(
            `UPDATE users
            SET refreshtoken = $1
            WHERE id = $2`,[null, user.id]
        );
        if(removeTokenDb.rowCount === 0) throw new ApiError(500, 'something went wrong');
    } catch (error) {
        throw new ApiError(500, 'something went wrong');
    };

    Object.keys(req.cookies).forEach((cookie)=> res.clearCookie(cookie));

    return res
    .status(200)
    .json(new ApiResponse(200, {}, 'logout successfully'))
});

const deleteAccount = asyncHandler(async(req, res)=>{
    
});
 
export {
    userRegister,
    authCheck,
    userLogin,
    userLogout,
    deleteAccount
}
