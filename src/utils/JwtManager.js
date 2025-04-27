import jwt from "jsonwebtoken"

export const createAccessToken = (data)=>{
    const accessToken = jwt.sign(data, process.env.ACCESS_TOKEN_SECRET, {expiresIn:process.env.ACCESS_TOKEN_EXPIRY});
    return accessToken;
};

export const createRefreshToken = (data)=>{
    const refreshToken = jwt.sign(data, process.env.REFRESH_TOKEN_SECRET, {expiresIn:process.env.REFRESH_TOKEN_EXPIRY});
    return refreshToken;
};

export const createLoginToken= (data)=>{
    const loginToken = jwt.sign(data, process.env.LOGIN_TOKEN_SECRET, {expiresIn:process.env.LOGIN_TOKEN_EXPIRY});
    return loginToken;
};

export const createRegisterToken= (data)=>{
    const registerToken = jwt.sign(data, process.env.REGISTER_TOKEN_SECRET, {expiresIn:process.env.REGISTER_TOKEN_EXPIRY});
    return registerToken;
};

export const create_reg_verify_token = (data)=>{
    const registerVerifyToken = jwt.sign(data, process.env.REGISTER_VERIFY_SECRET, {expiresIn:process.env.REGISTER_VERIFY_EXPIRY});
    return registerVerifyToken;
};

export const create_login_verify_Token = (data)=>{
    const login_verify_token = jwt.sign(data, process.env.LOGIN_VERIFY_SECRET, {expiresIn:process.env.LOGIN_VERIFY_EXPIRY});
    return login_verify_token;
};


export const create_access_reg_token = (data)=>{
    const access_reg_token = jwt.sign(data, process.env.ACCESS_REG_SECRET, {expiresIn:process.env.ACCESS_REG_EXPIRY});
    return access_reg_token;
};

export const create_access_login_token = (data)=>{
    const access_login_token = jwt.sign(data, process.env.ACCESS_LOGIN_SECRET, {expiresIn:process.env.ACCESS_LOGIN_EXPIRY});
    return access_login_token;
};

export const createToken = (accessTokenData, refreshTokenData)=>{
    const accessToken = createAccessToken(accessTokenData);
    const refreshToken = createRefreshToken(refreshTokenData);

    return {
        accessToken,
        refreshToken
    }
};

