import { Router } from "express";
import {
    generateRegisterOtp,
    generateLoginOtp,
    verifyRegisterOtp,
    verifyLoginOtp
} from "../controllers/auth.controller.js" 
import {verifyAuth} from "../middlewares/auth.middleware.js"
 
const router = Router();
       
router.route('/login/get').get(generateLoginOtp);
router.route('/register/get').get(generateRegisterOtp);
router.route('/login/verify').post(verifyLoginOtp);
router.route('/register/verify').post(verifyRegisterOtp);

export default router;
