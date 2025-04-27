import pg from "pg";

const db = new pg.Client({
    user:process.env.PG_USER,
    password:process.env.PG_PASS,
    port:process.env.PG_PORT,
    host:process.env.PG_HOST,
    database:process.env.PG_DB
});

export default db;

