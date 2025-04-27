// error.middleware.js

import { ApiError } from "../utils/ApiErros.js";

const errorHandlerMiddleware = (err, req, res, next) => {
    console.log("Custom Error Handler Hit => ", err)

    if (err instanceof ApiError) {
        return res.status(err.statusCode).json({
            statusCode: err.statusCode,
            data: err.data,
            message: err.message,
            success: err.success,
            errors: err.errors
        });
    }

    return res.status(500).json({
        statusCode: 500,
        data: null,
        message: err.message || "Internal Server Error",
        success: false,
        errors: []
    });
};

export { errorHandlerMiddleware };