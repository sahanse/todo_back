import { Router } from "express";
import {
    addTodo,
    getTodos,
    deleteTodo,
    updateTodo,
    completeTodo,
    deleteAllTodo
} from "../controllers/todo.controller.js";
import {verifyJwt} from "../middlewares/auth.middleware.js";
const router = Router();

router.route('/add').post(verifyJwt, addTodo);
router.route('/delete').delete(verifyJwt, deleteTodo);
router.route('/edit').patch(verifyJwt, updateTodo);
router.route('/complete').patch(verifyJwt, completeTodo);
router.route("/getAll").get(verifyJwt,getTodos);
router.route('/deleteAll').delete(verifyJwt, deleteAllTodo);

export default router;
