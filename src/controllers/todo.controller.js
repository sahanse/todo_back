import { ApiError } from "../utils/ApiErros.js";
import {ApiResponse} from "../utils/ApiResponse.js"
import {asyncHandler} from "../utils/AsyncHandler.js"
import db from "../db/index.js"

const addTodo = asyncHandler(async(req, res)=>{
    if(!req.user) throw new ApiError(401, 'Unauthorized access');
    const {id} = req.user;

    const {todo} = req.body;
    if(!todo) throw new ApiError(400, 'Todo is required');
    if(String(todo).trim() === '') throw new ApiError(400, 'Please provide todo');

    const date = new Date().toISOString();
    //save todo in db
    let todo_id = null;
    try {
        const saveTodoDb = await db.query(
            `INSERT INTO
            todos (todo, user_id, created_at)
            VALUES ($1, $2, $3)
            RETURNING id`,[todo, id, date]
        );
        if(saveTodoDb.rowCount === 0) throw new ApiError(500, 'Something went wrong');
        todo_id = saveTodoDb.rows[0].id
    } catch (error) {
        if(error instanceof ApiError){
            throw error
        };
        throw new ApiError(500, 'something went wrong')
    };
    if(!todo_id) throw new ApiError(400, 'something went wrong');

    const todo_data = {
        id:todo_id,
        todo,
        completed:false,
        date
    };

    return res
    .status(200)
    .json(new ApiResponse(200, todo_data, 'todo created successfully'));
});

const getTodos = asyncHandler(async(req, res)=>{
    if(!req.user) throw new ApiError(400, 'Unauthorized access');

    const {id} = req.user;

    //get all todos of user 
   let todos=[];
   try {
     const getTodoDb = await db.query(
         `SELECT *
         FROM todos
         WHERE user_id =$1`,[id]
     );
    todos = getTodoDb.rows;
   } catch (error) {
    throw new ApiError(500, 'Something went wrong');
   };

   return res
   .status(200)
   .json(new ApiResponse(200, todos, 'todos fetched succesfully'));
});

const deleteTodo = asyncHandler(async(req, res)=>{
    if(!req.user) throw new ApiError(400, 'Unauthorized access');

    const {id} = req.user;
    const todo_id = req.body.id;

    if(!todo_id) throw new ApiError(400, 'Please provide id');

    //delete todo from db 
    try {
        const deleetTodoDb = await db.query(
            `DELETE FROM todos
            WHERE id = $1 AND user_id = $2`,[todo_id, id]
        );
        if(deleetTodoDb.rowCount === 0) throw new ApiError(500, 'something went wrong');
    } catch (error) {
        if(error instanceof ApiError){
            throw error
        };
        throw new ApiError(500, 'something went wrong');
    };

    return res
    .status(200)
    .json(new ApiResponse(200, {}, 'todo deleted successfully'));

});

const updateTodo = asyncHandler(async(req, res)=>{
    if(!req.user) throw new ApiError(400, 'unauthorized access');

    const user_id = req.user.id;

    const {id, todo}= req.body;
    if(!id || !todo) throw new ApiError(400, 'please provide id and todo');

    for(let val in req.body){
        if(String(req.body[val]).trim() === '') throw new ApiError(400, `Null value received at ${val}`)
    }

    //update the data
    try {
        const updateTodoDb = await db.query(
            `UPDATE todos
            SET todo = $1
            WHERE id = $2 AND user_id = $3`,[todo, id, user_id]
        );
        if(updateTodo.rowCount ===0) throw new ApiError(500, 'something went wrong');
    } catch (error) {
        if(error instanceof ApiError){
            throw error
        }
        throw new ApiError(500, 'something went wrong')
    };

    return res
    .status(200)
    .json(new ApiResponse(200, {}, 'todo updated successfully'));
});

const completeTodo = asyncHandler(async(req, res)=>{
    if(!req.user) throw new ApiError(400, 'unauthorized access');

    const user_id = req.user.id;
    const {id} = req.body;

    if(!id) throw new ApiError(400, 'please provide id');

    //update the staus in db
    try {
        const response = await db.query(
            `UPDATE todos
             SET completed = CASE 
             WHEN completed = true THEN false
             ELSE true
             END
             WHERE id = $1 AND user_id = $2`,[id, user_id]
        );
        if(response.rowCount === 0) throw new ApiError(500, 'something went wrong');
    } catch (error) {
        if(error instanceof ApiError){
            throw error
        };
        throw new ApiError(500, 'something went wrong')
    };

    return res
    .status(200)
    .json(new ApiResponse(200, {}, 'status updated successfully'))
});

const deleteAllTodo = asyncHandler(async(req, res)=>{
    if(!req.user) throw new ApiError(400, 'unauthorized access');

    const {id} = req.user;
    if(!id) throw new ApiError(400,'Unauthorozed access');

    //delete all todos from db
    try {
        const response = await db.query(
            `DELETE FROM todos
            WHERE user_id = $1`,[id]
        );
        if(response.rowCount === 0) throw new ApiError(500, 'something went wrong');
    } catch (error) {
        if(error instanceof ApiError){
            throw error
        };
        throw new ApiError(500, 'something went wrong')
    };

    return res
    .status(200)
    .json(new ApiResponse(200, {}, 'deleted all todos successfully'));
});

export {
    addTodo,
    getTodos,
    deleteTodo,
    updateTodo,
    completeTodo,
    deleteAllTodo
}

