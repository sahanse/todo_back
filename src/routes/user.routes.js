import { Router } from "express";
import {
    userRegister,
    authCheck,
    userLogin,
    userLogout,
    deleteAccount
} from "../controllers/user.controller.js";
import {verifyJwt} from "../middlewares/auth.middleware.js";

const router = Router();

router.route('/register').post(userRegister);
router.route('/auth/check').get(authCheck);
router.route('/login').post(userLogin);
router.route('/logout').post(verifyJwt, userLogout);
router.route('/deleteAcc').delete(verifyJwt, deleteAccount);

export default router;
