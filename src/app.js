import express from "express"
import cookieParser from "cookie-parser"
import cors from "cors"
import {errorHandlerMiddleware} from "./middlewares/error.middleware.js"
const app = express();

app.use(cors({
    origin:process.env.CORS_ORIGIN,
    credentials:true
}));

app.use(cookieParser());
app.use(express.static("public"));
app.use(express.json({}));
app.use(express.urlencoded({extended:true}));

//importing routes
import userRoutes from "./routes/user.routes.js"
import todoRoutes from "./routes/todo.routes.js"
import authRoutes from "./routes/auth.routes.js"

//routes declaration
app.use("/api/v1/user",userRoutes);
app.use('/api/v1/todo', todoRoutes);
app.use('/api/v1/auth', authRoutes)
app.use(errorHandlerMiddleware)

export default app;

