import app from "./app.js"
import env from "dotenv"
import db from "./db/index.js"

env.config({
   path:"./.env" 
});

db.connect()
.then(()=>{
    app.listen(process.env.EXPRESS_PORT || 8000, ()=>{
        console.log(`listening to port: ${process.env.EXPRESS_PORT || 8000}`)
    })
})
.catch((error)=>{
    console.log(`index :: dbconnect :: error :: ${error}`)
});

