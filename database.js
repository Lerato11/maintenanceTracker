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


// ------ LOGIN / LOGOUT QUERIES --------- //
// export async function loginCheck(email) {
//     const [validUser] = await dbPool.query(
//         `SELECT * FROM maintenance_users
//         WHERE email= ? AND password = ?`, [email]
//     );

//     if (validUser.length > 0) {
//         return validUser;
//     } else {
//         return null;
//     }
// }

// ------ USERS TABLE QUERIES --------- //

// get all users
export async function getUsers() {
    const [returnedUser] = await dbPool.query("SELECT * FROM maintenance_users");

    if (returnedUser.length > 0) {
        const safeUsers = returnedUser.map(user => ({
            id: user.id,
            email: user.email,
            username: user.username,
            user_type: user.user_type,
        }));

        return safeUsers;
    } else {
        return null;
    }
}

// const users = await getUsers();
// console.log(users);



// get specific user
export async function getUser(id) {
    const [returnedUser] = await dbPool.query(
        `SELECT * 
        FROM maintenance_users
        WHERE id = ?`, [id]
    );

    if (returnedUser.length > 0) {
        const user = returnedUser[0];
        const safeUser = {
            id: user.id,
            email: user.email,
            username: user.username,
            user_type: user.user_type,
        };
        return safeUser;
    } else {
        return null;
    }
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

    return deletedUser.affectedRows > 0;
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


    if (log.length > 0) {
        return log[0];
    } else {
        return null; 
    }

    // return log;
}



// get specific techician logs
export async function getTechLogs(id) {
    const [logs] = await dbPool.query(
        `SELECT * 
        FROM maintenance_logs
        WHERE assigned_to = ?`, [id]
    );

    if (logs.length > 0) {
        return logs;
    } else {
        return null; 
    }
}


// add a log (C)
export async function createLog(title, description, priority, machine_id, location_id) {
    const [newLog] = await dbPool.query(
        `INSERT INTO maintenance_logs (title, description, priority, machine_id, location_id)
        VALUES (?, ?, ?, ?, ?)`, [title, description, priority, machine_id, location_id]
    );

    const newLogId = newLog.insertId;
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

// check api_key
export async function checkMachineAndLocationID(machine_id, location_id) {
    const [machine] = await dbPool.query(
        `SELECT * 
        FROM maintenance_machines
        WHERE id = ? AND location_id = ?`, [machine_id, location_id]
    );

    if (machine.length > 0) {
        return machine[0];
    } else {
        return null; 
    }
}


//check location_id
export async function checkLocationID(location_id) {
    const [location] = await dbPool.query(
        `SELECT * 
        FROM maintenance_locations
        WHERE id = ?`, [location_id]
    );

    if (location.length > 0) {
        return location[0];
    } else {
        return null; 
    }
}

// Update a log (status) (U)
export async function updateLogStatus(status, id) {
    const updatedLog = dbPool.query(
        `UPDATE maintenance_logs
        SET status = ?
        WHERE id = ?`, [status, id]
    );

    const returnedUpdatedLog = await getLog(id);

    if (status === "Resolved"){
        // const createdAtDate = new Date(originalLog.created_at);
        const resolvedAtDate = new Date();

        const [newLog] = await dbPool.query(
            `INSERT INTO maintenance_machine_history (machine_id, location_id, title, description, created_at, resolved_at)
            VALUES (?, ?, ?, ?, ?, ?)`, [returnedUpdatedLog.machine_id, returnedUpdatedLog.location_id, returnedUpdatedLog.title, returnedUpdatedLog.description, returnedUpdatedLog.created_at, resolvedAtDate]
        );
    }

    if (updatedLog.affectedRows > 0) {
        return true;
    } else {
        return false; 
    }
    
}

// admin assign a log
export async function assignLog(techId, id) {
    const [result] = await dbPool.query(
        `UPDATE maintenance_logs
        SET assigned_to = ?
        WHERE id = ?`, [techId, id]
    )

    if (result.affectedRows > 0) {
        return true;
    } else {
        return false; 
    }
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

    if (machine.length > 0) {
        return machine[0];
    } else {
        return null; 
    }
}

// add a machine (C)
export async function addMachine(name, location_id) {
    const createdAtDate = new Date();

    const [newMachine] = await dbPool.query(
        `INSERT INTO maintenance_machines (name, location_id, installed_at)
        VALUES (?, ?, ?)`, [name, location_id, createdAtDate]
    );

    const newMachineId = newMachine.insertId;
    return await getMachine(newMachineId)
}


// get all specific machineHistory (R)
export async function getMachineHistory(id) {
    const [machineHistory] = await dbPool.query(
        `SELECT * 
        FROM maintenance_machine_history
        WHERE machine_id = ?`, [id]
    );

    if (machineHistory.length > 0) {
        return machineHistory;
    } else {
        return null; 
    }
}

// delete a machine
export async function removeMachine(id) {
    const [result] = await dbPool.query(
        `DELETE FROM maintenance_machines
        WHERE id = ?`, [id]
    )

    if (result.affectedRows > 0) {
        return true;
    } else {
        return false; 
    }
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

    if (location.length > 0) {
        return location[0];
    } else {
        return null; 
    }
}

// add a location (C)
export async function addLocation(name) {
    const [newLocation] = await dbPool.query(
        `INSERT INTO maintenance_locations (name)
        VALUES (?)`, [name]
    );

    const newLocationId = newLocation.insertId;
    return getLocation(newLocationId)
}

// delete a location
export async function removeLocation(id) {
    const [result] = await dbPool.query(
        `DELETE FROM maintenance_locations
        WHERE id = ?`, [id]
    )

    if (result.affectedRows > 0) {
        return true;
    } else {
        return false; 
    }
}