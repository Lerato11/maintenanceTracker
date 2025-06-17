import mysql from "mysql2";

import dotenv from "dotenv";
dotenv.config();

const dbPool = mysql.createPool({
    host: process.env.MYSQL_HOST,
    // host: "127.0.0.1",

    user: process.env.MYSQL_USER,
    // user: "root",

    password:process.env.MYSQL_PASSWORD,
    // password: "PiedPiper5.2",

    database: process.env.MYSQL_DATABASE
    // database: "maintananceDB"
}).promise()


// const [rows] = await dbPool.query("SELECT * FROM maintenance_users");
// // const rows = testConnection[0];
// console.log(rows)



// ------ USERS TABLE QUERIES --------- //

// get all users
export async function getUsers() {
    const [users] = await dbPool.query("SELECT * FROM maintenance_users");

    return users;
}

// const users = await getUsers();
// console.log(users);



// get specific user
export async function getUser(id) {
    const [user] = await dbPool.query(
        `SELECT * 
        FROM maintenance_users
        WHERE id = ?`, [id]
    );

    return user;
}


// const user = await getUser(2);
// console.log(user);

// create user (registration)
export async function registerUser(email, username, hashed_password, user_type, salt, api_key) {
    const [user] = await dbPool.query(
        `INSERT INTO maintenance_users (email, username, password_hash, user_type, salt, api_key)
        VALUES (?, ?, ?, ?, ?, ?)`, [email, username, hashed_password, user_type, salt, api_key]
    );

    const newUserId = user.insertId;
    return getUser(newUserId)
}


// delete a user
export async function removeUser(id) {
    const [deletedUser] = await dbPool.query(
        `DELETE FROM maintenance_users
        WHERE id = ?`, [id]
    )

    const newUsers = getUsers();
    return newUsers;
}


// check email (registration)
export async function checkEmail(email) {
    const [user] = await dbPool.query(
        `SELECT * 
        FROM maintenance_users
        WHERE email = ?`, [email]
    );

    return user;
}


// check api_key
export async function checkApiKey(api_key) {
    const [user] = await dbPool.query(
        `SELECT * 
        FROM maintenance_users
        WHERE api_key = ?`, [api_key]
    );

    return user;
}

// ------ LOGS TABLE QUERIES --------- //

// get all logs (R)
export async function getLogs(){
    const [logs] = await dbPool.query(
        `SELECT * 
        FROM maintenance_logs`
    );

    return logs;
}

// get specific log (R)
export async function getLog(id) {
    const [log] = await dbPool.query(
        `SELECT * 
        FROM maintenance_logs
        WHERE id = ?`, [id]
    );

    return log;
}

// add a log (C)
export async function createLog(title, description, priority, status, machine_id, location_id) {
    const [newLog] = await dbPool.query(
        `INSERT INTO maintenance_logs (title, description, priority, status, machine_id, location_id)
        VALUES (?, ?, ?, ?, ?, ?)`, [title, description, priority, status, machine_id, location_id]
    );

    const newLogId = newLog.result.insertId;
    return getLog(newLogId)
}

// // resolve a log (-> machineHistory) (D)
// export async function resolveLog(id, status) {
//     const [updatedLog] = dbPool.query(
//         `UPDATE maintenance_logs
//         SET status = ?
//         WHERE id = ?`, [id, status]
//     );
// }

// Update a log (status) (U)
export async function updateLogStatus(id, status) {
    const [updatedLog] = dbPool.query(
        `UPDATE maintenance_logs
        SET status = ?
        WHERE id = ?`, [id, status]
    );

    const returnedUpdatedLog = getLog(id);

    if (status === "Resolved"){
        const [newLog] = await dbPool.query(
            `INSERT INTO maintenance_machine_history (machine_id, location_id, title, description, created_at)
            VALUES (?, ?, ?, ?, ?)`, [returnedUpdatedLog.machine_id, returnedUpdatedLog.location_id, returnedUpdatedLog.title, returnedUpdatedLog.description, returnedUpdatedLog.created_at]
        );
    }

    return returnedUpdatedLog;
    
}

// admin assign a log
export async function assignLog(techId, id) {
    const [assignedLog] = await dbPool.query(
        `UPDATE maintenance_logs
        SET assigned_to = ?
        WHERE id = ?`, [techId, id]
    )
}


// ------ MACHINES TABLE QUERIES --------- //

// get all machines (R)
export async function getMachines() {
    const [machines] = await dbPool.query(
        `SELECT *
        FROM maintenance_machines`
    )

    return machines;
}

// get specific machine (R)
export async function getMachine(id) {
    const [machine] = await dbPool.query(
        `SELECT * 
        FROM maintenance_machines
        WHERE id = ?`, [id]
    );

    return machine;
}

// add a machine (C)
export async function addMachine(name, location_id) {
    const [newMachine] = await dbPool.query(
        `INSERT INTO maintenance_machines (name, location_id)
        VALUES (?, ?)`, [name, location_id]
    );

    const newMachineId = newMachine.result.insertId;
    return getMachine(newMachineId)
}


// get all specific machineHistory (R)
export async function getMachineHistory(id) {
    const [machineHistory] = await dbPool.query(
        `SELECT * 
        FROM maintenance_machine_history
        WHERE machine_id = ?`, [id]
    );

    return machineHistory;
}


// ------ LOCATIONS TABLE QUERIES --------- //

// get all locations (R) 
export async function getLocations() {
    const [locations] = await dbPool.query(
        `SELECT *
        FROM maintenance_locations`
    )

    return locations;
}

// get specific location (R)
export async function getLocation(id) {
    const [location] = await dbPool.query(
        `SELECT * 
        FROM maintenance_locations
        WHERE id = ?`, [id]
    );

    return location;
}

// add a location (C)
export async function addLocation(name) {
    const [newLocation] = await dbPool.query(
        `INSERT INTO maintenance_locations (name)
        VALUES (?, ?)`, [name]
    );

    const newLocationId = newLocation.result.insertId;
    return getLocation(newLocationId)
}