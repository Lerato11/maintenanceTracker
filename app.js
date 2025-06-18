// ------ express code for the server ------- //

import express from "express"

import {getUsers, getUser, registerUser, checkEmail, getLogs, getLog, createLog, updateLogStatus,
    assignLog, getMachines, getMachine, addMachine, getMachineHistory, getLocations, getLocation, getTechLogs,
    checkApiKey,removeUser, checkMachineAndLocationID, checkLocationID, addLocation, removeLocation, removeMachine} from "./database.js";


// const { createHash } = require('crypto');
import {createHash} from "crypto";
import { stat } from "fs";

const app = express()

app.use(express.json());

// email validation function
function validEmail(email) {
    const pattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return pattern.test(email);
}


// alphanumeric generator (salt + api_key)
function randomString(length) {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

// hashing (sha-256)
function hash(string) {
  return createHash('sha256').update(string).digest('hex');
}

// ------ USERS TABLE Requests --------- //

// -------------------- get all users --------------------
app.get("/users", async (req, res) => {
    const {user_type} = req.body; // for testing purposes. later use localStorage
    const {api_key} = req.body; // localStorage.getItem("api_key")

    // check api_key

    const apiKeyCheck = await checkApiKey(api_key);

    if (apiKeyCheck.length <= 0){ // api_key exists

        return res.status(401).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "UNAUTHORISED! - Invalid or missing api_key",
               staus: 401
            }
        })
    }


    // check if user_type == "Admin"
    if (user_type != "Admin"){
        
        return res.status(403).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "FORBIDDEN! - Only 'Admin' users can access user records",
                status: 403
            }
        })
    }

    let users;

    try{
       users = await getUsers();

            if (users.length > 0){
            return res.status(200).json({
                status : "success",
                timestamp : Date.now(),
                data : {
                    message: "GET user - Successfull",
                    status: 200,
                    users: users,
                }  
            })
        } else {
            return res.status(404).json({
                status : "error",
                timestamp : Date.now(),
                data: {
                    message: `No users in database`,
                    status: 404
                }
            })
        }
    }
    catch (error){
        return res.status(500).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: `Database GET users error: ` + error, 
               status: 500
            }
        })
    }

    // return res.status(200).json({
    //     status : "success",
    //     timestamp : Date.now(),
    //     data : {
    //        message: "GET users - Successfull",
    //        status: 400,
    //        users: users
    //     }
    // })
})


// -------------------- get specific user --------------------
app.get("/users/:id", async (req, res) => {
    const {id} = req.params;

    const {user_type} = req.body; // for testing purposes. later use localStorage
    const {api_key} = req.body; // localStorage.getItem("api_key")

    // check api_key

    const apiKeyCheck = await checkApiKey(api_key);

    if (apiKeyCheck.length <= 0){ // api_key exists

        return res.status(401).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "UNAUTHORISED! - Invalid or missing api_key",
               staus: 401
            }
        })
    }


    // check if user_type == "Admin"
    if (user_type != "Admin"){
        
        return res.status(403).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "FORBIDDEN! - Only 'Admin' users can access user records",
                status: 403
            }
        })
    }

     let user;

    try{
        user = await getUser(id)

        if (user){
            return res.status(200).json({
                status : "success",
                timestamp : Date.now(),
                data : {
                    message: "GET user - Successfull",
                    status: 200,
                    user: user,
                    assigned_logs : await getTechLogs(id)
                }  
            })
        } else {
            return res.status(404).json({
                status : "error",
                timestamp : Date.now(),
                data: {
                    message: `User (id: ${id}) not in database`,
                    status: 404
                }
            })
        }
    } 

    catch (error){
        return res.status(500).json({
            status: "error",
            timestamp: Date.now(),
            data: {
                message: `Database GET user error: ` + error, 
                status: 500
            }
        })
    }
})


// -------------------- create user (registration) --------------------
app.post("/register", async (req, res) => {
    // registration input from user : email, username, password, user_type
    const {email} = req.body;
    const {username} = req.body;
    const {password} = req.body;
    const {user_type} = req.body;


    // check if params are present

    // check if email in body exists
    if (!email){
        return res.status(400).json({
            status : "error [400]",
            timestamp : Date.now(),
            data : {
                message : "Missing email parameter",
                status : 400
            }
        })
    }

    // check if password in body exists
    else if (!password){
        return res.status(400).json({
            status : "error [400]",
            timestamp : Date.now(),
            data : {
                message : "Missing password parameter",
                status : 400
            }
        })
    }

    // check if username in body exists
    else if (!username){
        return res.status(400).json({
            status : "error [400]",
            timestamp : Date.now(),
            data : {
                message : "Missing username parameter",
                status : 400
            }
        })
    }

    // check if username in body exists
    else if (!user_type){
        return res.status(400).json({
            status : "error [400]",
            timestamp : Date.now(),
            data : {
                message : "Missing user type parameter",
                status : 400
            }
        })
    }


    //  validate the password 

    let hasNumber = /\d/.test(password); 
    let hasUppercase = /[A-Z]/.test(password); 
    let hasLowercase = /[a-z]/.test(password); 
    let hasSymbol = /[^A-Za-z0-9]/.test(password); 
    let isLongEnough = password.length >= 8; // longer than 7 characters

    if (!hasNumber || !hasUppercase || !hasLowercase || !hasSymbol || !isLongEnough){
        // status

        return res.status(400).json({
            status : "error [400]",
            timestamp : Date.now(),
            data : {
                message : "Invalid form credentials",
                status : 400
            }
        })
    }


    // check if email already exists
        // if so : can't add
        // else : can add 

    const emailCheck = await checkEmail(email)

    if (emailCheck.length > 0){ // email exists
        // res.status(409).send("Email already in use")


        return res.status(409).json({
            status : "error [409]",
            timestamp : Date.now(),
            data : {
                message : "Email already in use",
                status : 409
            }
        })
    }

    // ** email is not already taken **


    // validate user_type 
    if (user_type != "Admin" && user_type != "Technician" && user_type != "Visitor"){
        
        return res.status(400).json({
            status : "error [400]",
            timestamp : Date.now(),
            data : {
                message : "Invalid user type",
                status : 400
            }
        })
    }


    // validate the email
    if (!validEmail(email)){ // invalid email

        // status 
        return res.status(400).json({
            status: "error [400]",
            timestamp : Date.now(),
            data : {
                message : "Invalid Email",
                status : 400
            }
        })
    }

    // SYNC
    // generate api_key
    const api_key = randomString(16);


    // generate salt 
    const salt = randomString(10);


    // salt + password
    const saltedPassword = password + salt;

    const hashedsaltedPassword = hash(saltedPassword);


    // add to database

    try{
        const registeredUser = await registerUser(email, username, hashedsaltedPassword, user_type, salt, api_key);
    } 
    catch (error){
        console.log(error)
        return res.status(500).json({
            status : "error [500]",
            timestamp : Date.now(),
            data : {
                message : "Database insert error:" + error, 
                status : 500
            }
        })
    }

    return res.status(200).json({
        status : "success [200]",
        timestamp : Date.now(),
        data : {
            message : "User successfully registered",
            status : 200,

            user_api_key : api_key
        }
    })
}) 


// -------------------- remove a user (admin only) --------------------
app.delete("/userRemove/:id", async (req, res) =>{
    const { id } = req.params;

    // const {user_type} = localStorage.getItem("user_type")

    const {user_type} = req.body; // for testing purposes. later use localStorage
    const {api_key} = req.body; // localStorage.getItem("api_key")

    // check api_key

    const apiKeyCheck = await checkApiKey(api_key);

    if (apiKeyCheck.length <= 0){ // api_key exists

        return res.status(401).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "UNAUTHORISED! - Invalid or missing api_key",
               status: 401
            }
        })
    }
    const actingUser = apiKeyCheck[0];

    


    // check if user_type == "Admin"
    if (user_type != "Admin"){
        
        return res.status(403).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "FORBIDDEN! - Only 'Admin' users can remove other users",
                status: 403
            }
        })
    }


    const userToDeleteExists = await getUser(id);
    // check if user exists in database
    // const userExists = await getUser(id);

    if (!userToDeleteExists){
        return res.status(404).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "User does not exist in database",
               status: 404
            }
        })
    }

    
    // check if id is not same as Admin deleting it
    if (actingUser.id === parseInt(id, 10)) { // Assuming actingUser.id is a number
        return res.status(403).json({ // 403 Forbidden is suitable
            status: "error",
            timestamp: Date.now(),
            data: {
                message: "FORBIDDEN! - An administrator cannot delete their own account.",
                status: 403
            }
        });
    }



    // ** valid user (admin with api_key in db) **

    try {
        // removeUser should ideally return true/false based on affectedRows
        const successfullyRemoved = await removeUser(id); // Ensure removeUser is correctly implemented

        if (successfullyRemoved) {
            return res.status(200).json({
                status: "success",
                timestamp: Date.now(),
                data: {
                    message: `User (id : ${id}) successfully removed from Database`,
                    status: 200
                }
            });
        } else {
            return res.status(500).json({
                status: "error",
                timestamp: Date.now(),
                data: {
                    message: `Failed to remove user (id : ${id}) from Database.`,
                    status: 500
                }
            });
        }

    } catch (error) {
        console.error("Database user remove error:", error);
        return res.status(500).json({
            status: "error",
            timestamp: Date.now(),
            data: {
                message: `Database user remove error: ` + (error.message || error),
                status: 500
            }
        });
    }
    
})

// -------------------- login (any user) --------------------
    // 1. validate email + password (if they are given)
    // 2. db select for salt and password and api and user_type
    // 3. set api_key and user_type to localStorage
    // 4. validate password

    // 5. 
    // look up session alternatives in js / nodejs


// -------------------- logout (any user) --------------------



// -------------------- get all logs (admin) --------------------
app.get("/logs", async (req, res) => {

    // const {user_type} = localStorage.getItem("user_type")

    const {user_type} = req.body; // for testing purposes. later use localStorage
    const {api_key} = req.body; // localStorage.getItem("api_key")

    // check api_key

    const apiKeyCheck = await checkApiKey(api_key);

    if (apiKeyCheck.length <= 0){ // api_key exists

        return res.status(401).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "UNAUTHORISED! - Invalid or missing api_key",
               status: 401
            }
        })
    }


    // check if user_type == "Admin"
    if (user_type != "Admin"){
        
        return res.status(403).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "FORBIDDEN! - Only 'Admin' users can access log records",
                status: 403
            }
        })
    }

    let logs;

    try{
       logs = await getLogs();

       if (logs.length > 0){
            return res.status(200).json({
                status : "success",
                timestamp : Date.now(),
                data : {
                    message: "GET log - Successfull",
                    status: 200,
                    logs: logs,
                }  
            })
        } else {
            return res.status(404).json({
                status : "error",
                timestamp : Date.now(),
                data: {
                    message: `No logs in database`,
                    status: 404
                }
            })
        }
    }
    catch (error){
        return res.status(500).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: `Database GET logs error: ` + error, 
               status: 500
            }
        })
    }

})

// -------------------- get all technician's logs (admin and technician) --------------------
app.get("/techLogs/:id", async (req, res) => {
    const {id} = req.params;

    const {user_type} = req.body; // for testing purposes. later use localStorage
    const {api_key} = req.body; // localStorage.getItem("api_key")

    // check api_key

    const apiKeyCheck = await checkApiKey(api_key);

    if (apiKeyCheck.length <= 0){ // api_key exists

        return res.status(401).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "UNAUTHORISED! - Invalid or missing api_key",
               staus: 401
            }
        })
    }

    // check if user_type == "Admin"
    if (user_type != "Admin" && user_type != "Technician"){
        
        return res.status(403).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "FORBIDDEN! - Only 'Admin' and 'Technician' users can access specific location records",
                status: 403
            }
        })
    }



    // check if the user id is valid user in database

    let user;

    try{
        user = await getUser(id);

        if (!user){
            return res.status(404).json({
                status : "error",
                timestamp : Date.now(),
                data : {
                    message: `User (id: ${id}) not in database`,
                    status: 404
                }
            })
        }

    } catch (error){
        return res.status(500).json({
            status: "error",
            timestamp: Date.now(),
            data : {
                message :`Database GET user error: ` + error,
                status : 500
            }
        })
    }



    let logs;

    try{
       logs = await getTechLogs(id);

        if (logs){
            return res.status(200).json({
                status : "success",
                timestamp : Date.now(),
                data : {
                    message: "GET technician logs - Successfull",
                    status: 200,
                    assigned_logs: logs,
                }
            })
        } else {
            return res.status(404).json({
                status : "error",
                timestamp : Date.now(),
                data: {
                    message: `Technician (id: ${id}) not assigned any logs`,
                    status: 404
                }
            })
        }

    }
    catch (error){
        console.log(error)
        return res.status(500).json({
            status : "error",
            timestamp : Date.now(),
            data: {
                message: `Database GET technician logs error: ` + (error.message || error),
                status: 500
            }
        })
    }

})

// -------------------- get specific log (admin and techncian) --------------------
app.get("/logs/:id", async (req, res) => {
    const { id } = req.params;

    const {user_type} = req.body; // for testing purposes. later use localStorage
    const {api_key} = req.body;  // localStorage.getItem("api_key")


    // check api_key
    const apiKeyCheck = await checkApiKey(api_key);

    if (apiKeyCheck.length <= 0){ // api_key exists

        return res.status(401).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "UNAUTHORISED! - Invalid or missing api_key",
               staus: 401
            }
        })
    }

    // check if user_type == "Admin" or "Technician"
    if (user_type != "Admin" && user_type != "Technician"){
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "FORBIDDEN! - Only 'Admin' and 'Technician' users can access specific log records",
                status: 403
            }
        })
    }

    let log;

    try{
        log = await getLog(id)

        if (log){
            return res.status(200).json({
                status : "success",
                timestamp : Date.now(),
                data : {
                    message: "GET log - Successfull",
                    status: 200,
                    log: log,
                }  
            })
        } else {
            return res.status(404).json({
                status : "error",
                timestamp : Date.now(),
                data: {
                    message: `User (id: ${id}) not in database`,
                    status: 404
                }
            })
        }
    } 

    catch (error){
        return res.status(500).json({
            status: "error",
            timestamp: Date.now(),
            data: {
                message: `Database GET log error: ` + error, 
                status: 500
            }
        })
    }
})

// -------------------- create log (any user) --------------------
app.post("/createLog", async (req, res) => {
    const {title} = req.body;
    const {description} = req.body;
    let {priority} = req.body;
    // const {status} = req.body;
    const {machine_id} = req.body;
    // const {location_id} = req.body;

    // check machine id and location id are valid in their table (Promis.all()) // sync
    // const {machineID, locationID} = Promise.all([getMachine(machine_id), getLocations(location_id)]); /// check

    // default priority = 'low'
    if (!priority){
        priority = 'Low';
    }

    // check if title in body exists
    if (!title){
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "Missing title parameter",
                status: 400
            }
        })
    }

    // check if machine_id in body exists
    else if (!machine_id){
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "Missing machine id parameter",
                status: 400
            }
        })
    }

    let machine;

    try{
       machine = await getMachine(machine_id); ////////------

       if (!machine){
            return res.status(404).json({
                status : "error",
                timestamp : Date.now(),
                data : {
                    message: `Invalid machine_id`,
                    status: 404
                }
            })
        }
    }
    catch (error){
        return res.status(500).json({
            status : "error",
            timestamp : Date.now(),
            data : {
                message :`Database GET machine error: ` + error,
                status : 500
            }
        })
    }

    
    let newLog;

    try{
       newLog = await createLog(title, description, priority, machine_id, machine.location_id); ////////------
    }
    catch (error){
        return res.status(500).json({
            status : "error",
            timestamp : Date.now(),
            data : {
                message : `Database POST log error: ` + error,
                status : 500
            }
        })
    }

    return res.status(200).json({
        status : "success",
        timestamp : Date.now(),
        data : {
            message : "Location successfully added",
            status : 200,

            new_log : newLog
        }
    })

})

// -------------------- update log status (admin and techncian) --------------------
app.post("/updateStatus/:id", async (req, res) => {
    // getting assigned to in body, (log to assign as param)

    const { id } = req.params;

    const {user_type} = req.body; // for testing purposes. later use localStorage
    const {api_key} = req.body;  // localStorage.getItem("api_key")

    const {status} = req.body;

    
    // check api_key
    const apiKeyCheck = await checkApiKey(api_key);

    if (apiKeyCheck.length <= 0){ // api_key exists

        return res.status(401).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "UNAUTHORISED! - Invalid or missing api_key",
               staus: 401
            }
        })
    }


    // check if user_type == "Admin" or "Technician"
    if (user_type != "Admin" && user_type != "Technician"){
        return res.status(403).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "Invalid user type - (Only 'Admin', and 'Technician' can update log status)",
                status: 403
            }
        })
    }

    // check if tech_id in body exists
    if (!status){
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "Missing status parameter",
                status: 400
            }
        })
    } else if (status != "Pending" && status != "Active" && status != "Resolved"){
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "Invalid status parameter - ['Pending', 'Active', 'Resolved']",
                status: 400
            }
        })
    }


    // check if the log id is valid log in database

    let logCheck;

    try{
        logCheck = await getLog(id);

        if (!logCheck){
            return res.status(404).json({
                status : "error",
                timestamp : Date.now(),
                data : {
                    message: `Log (id: ${id}) not in database`,
                    status: 404
                }
            })
        }

    } catch (error){
        return res.status(500).json({
            status: "error",
            timestamp: Date.now(),
            data: {
                message: `Database GET log error: ` + (error.message || error),
                status: 500
            }
        })
    }


    // assign log

    let successfullyRemoved;

    try{
       successfullyRemoved = await updateLogStatus(status, id); ////////------

    //    if (successfullyRemoved) {
    //         return res.status(200).json({
    //             status : "success",
    //             timestamp : Date.now(),
    //             data : [
    //                 `Machine (id : ${id}) status successfully updated`,
    //                 await getLog(id),
    //             ]
    //         });
    //     }

    }
    catch (error){
        console.log(error)
        return res.status(500).json({
            status : "error",
            timestamp : Date.now(),
            data: {
                message: `Database POST log status error: ` + (error.message || error),
                status: 500
            }
        })
    }

    return res.status(200).json({
            status : "success",
            timestamp : Date.now(),
            data: {
                message: `Log (id : ${id}) status successfully updated`,
                status: 200
            }
        });
})

// -------------------- assign log (admin) --------------------
app.post("/assignlog/:id", async (req, res) => {
    // getting assigned to in body, (log to assign as param)

    const { id } = req.params;

    const {user_type} = req.body; // for testing purposes. later use localStorage
    const {api_key} = req.body;  // localStorage.getItem("api_key")

    const {tech_id} = req.body;

    
    // check api_key
    const apiKeyCheck = await checkApiKey(api_key);

    if (apiKeyCheck.length <= 0){ // api_key exists

        return res.status(401).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "UNAUTHORISED! - Invalid or missing api_key",
               status: 401
            }
        })
    }


    // check if user_type == "Admin"
    if (user_type != "Admin"){
        return res.status(403).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "FORBIDDEN! - Only 'Admin' users can assign logs",
                status: 403
            }
        })
    }

    // check if tech_id in body exists
    if (!tech_id){
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "Missing tech id parameter",
                status: 400
            }
        })
    }


    // check if the log id is valid log in database

    let logCheck;

    try{
        logCheck = await getLog(id);

        if (!logCheck){
            return res.status(404).json({
                status : "error",
                timestamp : Date.now(),
                data : {
                    message: `Log (id: ${id}) not in database`,
                    status: 404
                }
            })
        }

    } catch (error){
        return res.status(500).json({
            status: "error",
            timestamp: Date.now(),
            data: {
                message: `Database GET log error: ` + (error.message || error),
                status: 500
            }
        })
    }

    let technician;

    try{
        technician = await getUser(tech_id);

        if (!technician){
            return res.status(404).json({
                status : "error",
                timestamp : Date.now(),
                data : {
                    message: `Technician (id: ${tech_id}) not in database`,
                    status: 404
                }
            })
        }

    } catch (error){
        return res.status(500).json({
            status: "error",
            timestamp: Date.now(),
            data: {
                message: `Database GET user log error: ` + (error.message || error),
                status: 500
            }
        })
    }

    // assign log

    let log;

    try{
       log = await assignLog(tech_id, id); ////////------
    }
    catch (error){
        // console.log(error)
        return res.status(500).json({
            status : "error",
            timestamp : Date.now(),
            data: {
                message:  `Database POST assign log error: ` + (error.message || error),
                status: 500
            }
        })
    }

    return res.status(200).json({
        status : "success",
        timestamp : Date.now(),
        data: {
            message: `Log (id : ${id}) successfully assigned to Technician (id: ${tech_id})`,
            status: 200,
            assigned_log: await getLog(id),
            technician: technician
        }
    })
})

// -------------------- get all machines (anyone)  --------------------
app.get("/machines", async (req, res) => {

    // const {user_type} = localStorage.getItem("user_type")

    const {user_type} = req.body; // for testing purposes. later use localStorage
    const {api_key} = req.body; // localStorage.getItem("api_key")

    // check api_key

    const apiKeyCheck = await checkApiKey(api_key);

    if (apiKeyCheck.length <= 0){ // api_key exists
        return res.status(401).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "UNAUTHORISED! - Invalid or missing api_key",
               staus: 401
            }
        })
    }


    // // check if user_type == "Admin"
    if (user_type != "Admin" && user_type != "Technician" && user_type != "Visitor"){
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "Invalid user type - (Only 'Admin', 'Technician' and 'Visitor' can access machine records)",
                status: 403
            }
        })
    }


    let machines;

    try{
       machines = await getMachines();

       if (machines.length > 0){
            return res.status(200).json({
                status : "success",
                timestamp : Date.now(),
                data : {
                    message: "GET machines - Successfull",
                    status: 200,
                    locations: machines,
                }  
            })
        } else {
            return res.status(404).json({
                status : "error",
                timestamp : Date.now(),
                data: {
                    message: `No machines in database`,
                    status: 404
                }
            })
        }
    }
    catch (error){
        return res.status(500).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: `Database GET machines error: ` + error, 
               status: 500
            }
        })
    }
})

// -------------------- get specific machine (admin) --------------------
app.get("/machines/:id", async (req, res) => {
    const { id } = req.params;

    const {user_type} = req.body; // for testing purposes. later use localStorage
    const {api_key} = req.body;  // localStorage.getItem("api_key")


    // check api_key
    const apiKeyCheck = await checkApiKey(api_key);

    if (apiKeyCheck.length <= 0){ // api_key exists

        return res.status(401).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "UNAUTHORISED! - Invalid or missing api_key",
               staus: 401
            }
        })
    }

    // check if user_type == "Admin"
    if (user_type != "Admin"){
        return res.status(403).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "FORBIDDEN! - Only 'Admin' users can access specific machine records",
                status: 403
            }
        })
    }

    let machine;

    try{
        machine = await getMachine(id)

        if (machine){
            return res.status(200).json({
                status : "success",
                timestamp : Date.now(),
                data : {
                    message: "GET machine - Successfull",
                    status: 200,
                    machine: machine,
                }
            })
        } else {
            return res.status(404).json({
                status : "error",
                timestamp : Date.now(),
                data: {
                    message: `Machine (id: ${id}) not in database`,
                    status: 404
                }
            })
        }
    } 

    catch (error){
        return res.status(500).json({
            status: "error",
            timestamp: Date.now(),
            data: {
                message: `Database GET machine error: ` + error, 
                status: 500
            }
        })
    }
})

// -------------------- add a machine (admin) --------------------
app.post("/addMachine", async (req, res) => {

    const {user_type} = req.body; // for testing purposes. later use localStorage
    const {api_key} = req.body; // localStorage.getItem("api_key")

    const {location_id} = req.body;
    const {name} = req.body;


    // check api_key

    const apiKeyCheck = await checkApiKey(api_key);

    if (apiKeyCheck.length <= 0){ // api_key exists
        return res.status(401).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "UNAUTHORISED! - Invalid or missing api_key",
               status: 401
            }
        })
    }


    // check if user_type == "Admin"
    if (user_type != "Admin"){
        return res.status(404).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "FORBIDDEN! - Only 'Admin' users can add locations",
                status: 403
            }
        })
    }

    // check if name in body exists
    if (!name){
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "Missing name parameter",
                status: 400
            }
        })
    }

    // check if location_id in body exists
    else if (!location_id){
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "Missing location id parameter",
                status: 400
            }
        })
    }


    // check location id is valid in table // sync
    // const {machineID, locationID} = Promise.all([getMachine(machine_id), getLocations(location_id)]); /// check

    let location;

    try{
       location = await checkLocationID(location_id); ////////------

       if (!location){
            return res.status(404).json({
                status : "error",
                timestamp : Date.now(),
                data : {
                    message: "Invalid location_id",
                    status: 404
                }
            })
        }
    }
    catch (error){
        return res.status(500).json({
            status : "error",
            timestamp : Date.now(),
            data : {
                message :`Database GET location error: ` + error,
                status : 500
            }
        })
    }

    //

    let newMachine;

    try{
       newMachine = await addMachine(name, location_id); ////////------
    }
    catch (error){
        return res.status(500).json({
            status : "error",
            timestamp : Date.now(),
            data : {
                message : `Database POST machine error: ` + error,
                status : 500
            }
        })
    }

    return res.status(200).json({
        status : "success",
        timestamp : Date.now(),
        data : {
            message : "Location successfully added",
            status : 200,

            new_machine : newMachine
        }
    })

})

// -------------------- remove a machine (admin) --------------------
app.delete("/machineRemove/:id", async (req, res) =>{
    const { id } = req.params;

    // const {user_type} = localStorage.getItem("user_type")

    const {user_type} = req.body; // for testing purposes. later use localStorage
    const {api_key} = req.body; // localStorage.getItem("api_key")

    // check api_key

    const apiKeyCheck = await checkApiKey(api_key);

    if (apiKeyCheck.length <= 0){ // api_key exists

        return res.status(401).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "UNAUTHORISED! - Invalid or missing api_key",
               status: 401
            }
        })
    }


    // check if user_type == "Admin"
    if (user_type != "Admin"){
        
        return res.status(403).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "FORBIDDEN! - Only 'Admin' users can remove machines",
                status: 403
            }
        })
    }
    

    let machineExists;

    try{
        machineExists = await getMachine(id);
        // console.log(location);

        if (!machineExists){
            return res.status(404).json({
                status : "error",
                timestamp : Date.now(),
                data : {
                    message: "Machine id does not exist in database",
                    status: 404
                }
            })
        }
        
    }
    catch (error){
        return res.status(500).json({
            status : "error",
            timestamp : Date.now(),
            data: {
                message: `Database machine remove error: ` + (error.message || error),
                status: 500
            }
        })
    }


    // ** valid user (admin with api_key in db) **

    try{
        const successfullyRemoved = await removeMachine(id);

        if (successfullyRemoved) {
            return res.status(200).json({
                status : "success",
                timestamp : Date.now(),
                 data: {
                    message: `Machine (id : ${id}) successfully removed from Database`,
                    status: 200
                }
            });
        } else {
            return res.status(500).json({
                status : "error",
                timestamp : Date.now(),
                data: {
                    message: `Failed to remove machine (id : ${id}) from Database.`,
                    status: 500
                }
            });
        }
    }
    catch (error){
        return res.status(500).json({
            status : "error",
            timestamp : Date.now(),
            data: {
                message: `Database machine remove error: ` + (error.message || error),
                status: 500
            }
        })
    }
    
})

// -------------------- get all specific machineHistory (admin) --------------------
app.get("/machineHistory/:id", async (req, res) => {
    const {id} = req.params;

    const {user_type} = req.body; // for testing purposes. later use localStorage
    const {api_key} = req.body; // localStorage.getItem("api_key")

    // check api_key

    const apiKeyCheck = await checkApiKey(api_key);

    if (apiKeyCheck.length <= 0){ // api_key exists

        return res.status(401).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "UNAUTHORISED! - Invalid or missing api_key",
               status: 401
            }
        })
    }

    // check if user_type == "Admin"
    if (user_type != "Admin" && user_type != "Technician"){
        
        return res.status(403).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "FORBIDDEN! - Only 'Admin' and 'Technician' users can access machine history records",
                status: 403
            }
        })
    }



    // check if the machine id is valid machine in database

    let machine;

    try{
        machine = await getMachine(id);

        if (!machine){
            return res.status(404).json({
                status : "error",
                timestamp : Date.now(),
                data : {
                    message: `Machine (id: ${id}) not in database`,
                    status: 404
                }
            })
        }

    } catch (error){
        return res.status(500).json({
            status: "error",
            timestamp: Date.now(),
            data: {
                message: `Database GET machine error: ` + (error.message || error),
                status: 500
            }
        })
    }



    let history;

    try{
       history = await getMachineHistory(id);

        if (history){
            return res.status(200).json({
                status : "success",
                timestamp : Date.now(),
                data: {
                    message: `Machine (id : ${id}) history successfully retrieved from Database`,
                    status: 200, 
                    machine_history : history
                }
            })
        } else {
            return res.status(404).json({
                status : "error",
                timestamp : Date.now(),
                data : {
                    message: `Machine (id: ${id}) has no past logs`,
                    status: 404
                }
            })
        }

    }
    catch (error){
        return res.status(500).json({
            status : "error",
            timestamp : Date.now(),
            data: {
                message: `Database GET machine history error: ` + (error.message || error),
                status: 500
            }
        })
    }

})

// // -------------------- get specific log (admin and techncian) --------------------
// app.get("/logs/:id", async (req, res) => {
//     const { id } = req.params;

//     const {user_type} = req.body; // for testing purposes. later use localStorage
//     const {api_key} = req.body;  // localStorage.getItem("api_key")


//     // check api_key
//     const apiKeyCheck = await checkApiKey(api_key);

//     if (apiKeyCheck.length <= 0){ // api_key exists

//         return res.status(401).json({
//             status : "error",
//             timestamp : Date.now(),
//             data : [
//                "UNAUTHORISED! - Invalid or missing api_key"
//             ]
//         })
//     }

//     // check if user_type == "Admin" or "Technician"
//     if (user_type != "Admin" && user_type != "Technician"){
//         return res.status(400).json({
//             status : "error",
//             timestamp : Date.now(),
//             data : [
//                "Invalid user type - (Only 'Admin' or 'Technician' can access specific log records)"
//             ]
//         })
//     }

//     let log;

//     try{
//         log = await getLog(id)

//         if (log){
//             return res.status(200).json({
//                 status : "success",
//                 timestamp : Date.now(),
//                 data : {
//                     log : log
//                 }
//             })
//         } else {
//             return res.status(404).json({
//                 status : "error",
//                 timestamp : Date.now(),
//                 data: [
//                     `Log (id: ${id}) not in database`
//                 ]
//             })
//         }
//     } 

//     catch (error){
//         return res.status(500).json({
//             status: "error",
//             timestamp: Date.now(),
//             data: [
//                 `Database GET log error: ` + error
//             ]
//         })
//     }
// })

// -------------------- get all locations (anyone) --------------------
app.get("/locations", async (req, res) => {

    // const {user_type} = localStorage.getItem("user_type")

    const {user_type} = req.body; // for testing purposes. later use localStorage
    const {api_key} = req.body; // localStorage.getItem("api_key")

    // check api_key

    const apiKeyCheck = await checkApiKey(api_key);

    if (apiKeyCheck.length <= 0){ // api_key exists

        return res.status(401).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "UNAUTHORISED! - Invalid or missing api_key",
               staus: 401
            }
        })
    }


    // check if user_type == "Admin" or "Technician" or "Visitor"
    if (user_type != "Admin" && user_type != "Technician" && user_type != "Visitor"){
        
        return res.status(403).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "Invalid user type - (Only 'Admin', 'Technician' and 'Visitor' can access location records)",
                status: 403
            }
        })
    }

    let locations;

    try{
       locations = await getLocations();

        if (locations.length > 0){
            return res.status(200).json({
                status : "success",
                timestamp : Date.now(),
                data : {
                    message: "GET locations - Successfull",
                    status: 200,
                    locations: locations,
                }  
            })
        } else {
            return res.status(404).json({
                status : "error",
                timestamp : Date.now(),
                data: {
                    message: `No locations in database`,
                    status: 404
                }
            })
        }
    }
    catch (error){
        return res.status(500).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: `Database GET locations error: ` + error, 
               status: 500
            }
        })
    }

})

// -------------------- get specific location (admin) --------------------
app.get("/locations/:id", async (req, res) => {
    const { id } = req.params;

    const {user_type} = req.body; // for testing purposes. later use localStorage
    const {api_key} = req.body;  // localStorage.getItem("api_key")


    // check api_key
    const apiKeyCheck = await checkApiKey(api_key);

    if (apiKeyCheck.length <= 0){ // api_key exists

        return res.status(401).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "UNAUTHORISED! - Invalid or missing api_key",
               staus: 401
            }
        })
    }

    // check if user_type == "Admin"
    if (user_type != "Admin"){
        return res.status(403).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "FORBIDDEN! - Only 'Admin' users can access specific location records",
                status: 403
            }
        })
    }

    let location;

    try{
        location = await getLocation(id)

        if (location){
            return res.status(200).json({
                status : "success",
                timestamp : Date.now(),
                data : {
                    message: "GET location - Successfull",
                    status: 200,
                    location: location,
                }
            })
        } else {
            return res.status(404).json({
                status : "error",
                timestamp : Date.now(),
                data: {
                    message: `Location (id: ${id}) not in database`,
                    status: 404
                }
            })
        }
    } 

    catch (error){
        return res.status(500).json({
            status: "error",
            timestamp: Date.now(),
            data: {
                message: `Database GET location error: ` + error, 
                status: 500
            }
        })
    }
})


// -------------------- add a location (admin) --------------------
app.post("/addLocation", async (req, res) => {

    const {name} = req.body;

    const {user_type} = req.body; // for testing purposes. later use localStorage
    const {api_key} = req.body; // localStorage.getItem("api_key")



    // check api_key

    const apiKeyCheck = await checkApiKey(api_key);

    if (apiKeyCheck.length <= 0){ // api_key exists
        return res.status(401).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "UNAUTHORISED! - Invalid or missing api_key",
               status: 401
            }
        })
    }

 
    // check if user_type == "Admin"
    if (user_type != "Admin"){
        return res.status(403).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "FORBIDDEN! - Only 'Admin' users can add locations",
                status: 403
            }
        })
    }

    // check if name in body exists
    if (!name){
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "Missing name parameter",
                status: 400
            }
        })
    }

    //

    let newLocation;

    try{
       newLocation = await addLocation(name);
    }
    catch (error){
        return res.status(500).json({
            status : "error",
            timestamp : Date.now(),
            data : {
                message : "Database POST location error:" + error, 
                status : 500
            }
        })
    }

    return res.status(200).json({
        status : "success",
        timestamp : Date.now(),
        data : {
            message : "Location successfully added",
            status : 200,

            new_location : newLocation
        }
    })

})

// -------------------- remove a location (admin) --------------------
app.delete("/locationRemove/:id", async (req, res) =>{
    const { id } = req.params;

    // const {user_type} = localStorage.getItem("user_type")

    const {user_type} = req.body; // for testing purposes. later use localStorage
    const {api_key} = req.body; // localStorage.getItem("api_key")

    // check api_key

    const apiKeyCheck = await checkApiKey(api_key);

    if (apiKeyCheck.length <= 0){ // api_key exists

        return res.status(401).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "UNAUTHORISED! - Invalid or missing api_key",
               status: 401
            }
        })
    }


    // check if user_type == "Admin"
    if (user_type != "Admin"){
        
        return res.status(403).json({
            status : "error",
            timestamp : Date.now(),
            data : {
               message: "FORBIDDEN! - Only 'Admin' users can remove locations",
                status: 403
            }
        })
    }
    

    let locationExists;

    try{
        locationExists = await getLocation(id);
        // console.log(location);

        if (!locationExists){
            return res.status(404).json({
                status : "error",
                timestamp : Date.now(),
                data : {
                    message: "Location id does not exist in database",
                    status: 404
                }
            })
        }
        
    }
    catch (error){
        return res.status(500).json({
            status : "error",
            timestamp : Date.now(),
            data: {
                message: `Database GET location error: ` + (error.message || error),
                status: 500
            }
        })
    }


    // ** valid user (admin with api_key in db) **

    try{
        const successfullyRemoved = await removeLocation(id);

        if (successfullyRemoved) {
            return res.status(200).json({
                status : "success",
                timestamp : Date.now(),
                data: {
                    message: `Location (id : ${id}) successfully removed from Database`,
                    status: 200
                }
            });
        } else {
            return res.status(500).json({
                status : "error",
                timestamp : Date.now(),
                data: {
                    message: `Failed to remove location (id : ${id}) from Database.`,
                    status: 500
                }
            });
        }
    }
    catch (error){
        return res.status(500).json({
            status : "error",
            timestamp : Date.now(),
            data: {
                message: `Database DELETE location error: ` + (error.message || error),
                status: 500
            }
        })
    }
    
})



// app.use((err, req, res, next) => {
//     console.error(err.stack)
//     res.status(500).send("Something broke!")
// })

app.listen(8080, () => {
    console.log("Server running on port: 8080")
})