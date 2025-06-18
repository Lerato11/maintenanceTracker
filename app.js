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
async function validEmail(email) {
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
    const users = await getUsers();
    res.send(users);
})


// -------------------- get specific user --------------------
app.get("/users/:id", async (req, res) => {
    const {id} = req.params;

    const [user] = await getUser(id);
    res.send(user);
})


// -------------------- create user (registration) --------------------
app.post("/register", async (req, res) => {
    // registration input from user : email, username, password, user_type
    const {email} = req.body;
    const {username} = req.body;
    const {password} = req.body;
    const {user_type} = req.body;



    //  validate the password 

    let hasNumber = /\d/.test(password); 
    let hasUppercase = /[A-Z]/.test(password); 
    let hasLowercase = /[a-z]/.test(password); 
    let hasSymbol = /[^A-Za-z0-9]/.test(password); 
    let isLongEnough = password.length >= 8; // longer than 7 characters

    if (!hasNumber || !hasUppercase || !hasLowercase || !hasSymbol || !isLongEnough){
        // status

        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               "Invalid form credentials"
            ]
        })
    }


    // check if email already exists
        // if so : can't add
        // else : can add 

    const emailCheck = await checkEmail(email)

    if (emailCheck.length > 0){ // email exists
        // res.status(409).send("Email already in use")


        return res.status(409).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               "Email already in use"
            ]
        })
    }

    // ** email is not already taken **


    // validate user_type 
    if (user_type != "Admin" && user_type != "Technician" && user_type != "Visitor"){
        
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               "Invalid user type"
            ]
        })
    }


    // validate the email
    if (!validEmail(email)){ // invalid email

        // status 
        return res.status(400).json({
            status: "error",
            timestamp : Date.now(),
            data : [
                "Invalid Email"
            ]
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
            status : "error",
            timestamp : Date.now(),
            data : [
               `Database insert error: ` + error
            ]
        })
    }

    return res.status(200).json({
        status : "success",
        timestamp : Date.now(),
        data : {
           api_key : api_key
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
            data : [
               "UNAUTHORISED! - Invalid or missing api_key"
            ]
        })
    }


    // check if user_type == "Admin"
    if (user_type != "Admin"){
        
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               "Invalid user type - (Only 'Admin' can remove users)"
            ]
        })
    }

    // check if user exists in database
    const userExists = await getUser(id);

    if (userExists.length == 0){
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               "User does not exist in database"
            ]
        })
    }

    // ** valid user (admin with api_key in db) **

    try{
        const [newUsers] = await removeUser(id);
    }
    catch (error){
        return res.status(500).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               `Database user remove error: ` + error
            ]
        })
    }

    return res.status(200).json({
        status : "success",
        timestamp : Date.now(),
        data : [
            `User (id : ${id}) successfully removed from Database `
        ]
    })
    
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
            data : [
               "UNAUTHORISED! - Invalid or missing api_key"
            ]
        })
    }


    // check if user_type == "Admin"
    if (user_type != "Admin"){
        
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               "Invalid user type - (Only 'Admin' can access all logs)"
            ]
        })
    }

    let logs;

    try{
       logs = await getLogs();
    }
    catch (error){
        return res.status(500).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               `Database GET logs error: ` + error
            ]
        })
    }

    return res.status(200).json({
        status : "success",
        timestamp : Date.now(),
        data : {
            logs : logs
        }
    })

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
            data : [
               "UNAUTHORISED! - Invalid or missing api_key"
            ]
        })
    }

    // check if user_type == "Admin"
    if (user_type != "Admin" && user_type != "Technician"){
        
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               "Invalid user type - (Only 'Admin' and 'Technician' can access log records)"
            ]
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
                data: [
                    `User (id: ${id}) not in database`
                ]
            })
        }

    } catch (error){
        return res.status(500).json({
            status: "error",
            timestamp: Date.now(),
            data: [
                `Database GET user error: ` + error
            ]
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
                    logs : logs
                }
            })
        } else {
            return res.status(404).json({
                status : "error",
                timestamp : Date.now(),
                data: [
                    `Technician (id: ${id}) not assigned any logs`
                ]
            })
        }

    }
    catch (error){
        console.log(error)
        return res.status(500).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               `Database GET technician logs error: ` + error
            ]
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
            data : [
               "UNAUTHORISED! - Invalid or missing api_key"
            ]
        })
    }

    // check if user_type == "Admin" or "Technician"
    if (user_type != "Admin" && user_type != "Technician"){
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               "Invalid user type - (Only 'Admin' or 'Technician' can access specific log records)"
            ]
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
                    log : log
                }
            })
        } else {
            return res.status(404).json({
                status : "error",
                timestamp : Date.now(),
                data: [
                    `Log (id: ${id}) not in database`
                ]
            })
        }
    } 

    catch (error){
        return res.status(500).json({
            status: "error",
            timestamp: Date.now(),
            data: [
                `Database GET log error: ` + error
            ]
        })
    }
})

// -------------------- create log (any user) --------------------
app.post("/createLog", async (req, res) => {
    const {title} = req.body;
    const {description} = req.body;
    const {priority} = req.body;
    // const {status} = req.body;
    const {machine_id} = req.body;
    const {location_id} = req.body;

    // check machine id and location id are valid in their table (Promis.all()) // sync
    // const {machineID, locationID} = Promise.all([getMachine(machine_id), getLocations(location_id)]); /// check


    // check if title in body exists
    if (!title){
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               "Missing title parameter"
            ]
        })
    }

    // check if location_id in body exists
    else if (!location_id){
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               "Missing location id"
            ]
        })
    }

    // check if machine_id in body exists
    else if (!machine_id){
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               "Missing machine id"
            ]
        })
    }

    let machine;

    try{
       machine = await checkMachineAndLocationID(machine_id, location_id); ////////------

       if (!machine){
            return res.status(404).json({
                status : "error",
                timestamp : Date.now(),
                data: [
                    `Invalid machine_id or location_id`
                ]
            })
        }
    }
    catch (error){
        return res.status(500).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               `Database POST log error: ` + error
            ]
        })
    }


    

    // if (machineID == null){
    //     return res.status(400).json({
    //         status : "error",
    //         timestamp : Date.now(),
    //         data : [
    //            "Invalid machine ID - Please enter correct machine_id"
    //         ]
    //     })
    // } else if (locationID == null){
    //     return res.status(400).json({
    //         status : "error",
    //         timestamp : Date.now(),
    //         data : [
    //            "Invalid location ID - Please enter correct location_id"
    //         ]
    //     })
    // }


    //

    let newLog;

    try{
       newLog = await createLog(title, description, priority, machine_id, location_id); ////////------
    }
    catch (error){
        return res.status(500).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               `Database POST log error: ` + error
            ]
        })
    }

    return res.status(200).json({
        status : "success",
        timestamp : Date.now(),
        data : [
            newLog
        ]
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
            data : [
               "UNAUTHORISED! - Invalid or missing api_key"
            ]
        })
    }


    // check if user_type == "Admin" or "Technician"
    if (user_type != "Admin" && user_type != "Technician"){
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               "Invalid user type - (Only 'Admin' or 'Technician' can access machine records)"
            ]
        })
    }

    // check if tech_id in body exists
    if (!status){
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               "Missing status parameter"
            ]
        })
    } else if (status != "Pending" && status != "Active" && status != "Resolved"){
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               "Invalid status parameter - ['Pending', 'Active', 'Resolved']"
            ]
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
                data: [
                    `Log (id: ${id}) not in database`
                ]
            })
        }

    } catch (error){
        return res.status(500).json({
            status: "error",
            timestamp: Date.now(),
            data: [
                `Database GET log error: ` + error
            ]
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
            data : [
               `Database POST log status update error: ` + error
            ]
        })
    }

    return res.status(200).json({
        status : "success",
        timestamp : Date.now(),
        data : [
             `Machine (id : ${id}) status successfully updated`,
            await getLog(id)   // data[0]
        ]
    })
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
            data : [
               "UNAUTHORISED! - Invalid or missing api_key"
            ]
        })
    }


    // check if user_type == "Admin"
    if (user_type != "Admin"){
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               "Invalid user type - (Only 'Admin' can access machine records)"
            ]
        })
    }

    // check if tech_id in body exists
    if (!tech_id){
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               "Missing tech id parameter"
            ]
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
                data: [
                    `Log (id: ${id}) not in database`
                ]
            })
        }

    } catch (error){
        return res.status(500).json({
            status: "error",
            timestamp: Date.now(),
            data: [
                `Database GET log error: ` + error
            ]
        })
    }

    let technician;

    try{
        technician = await getUser(tech_id);

        if (!technician){
            return res.status(404).json({
                status : "error",
                timestamp : Date.now(),
                data: [
                    `Technician (id: ${tech_id}) not in database`
                ]
            })
        }

    } catch (error){
        return res.status(500).json({
            status: "error",
            timestamp: Date.now(),
            data: [
                `Database GET technician error: ` + error
            ]
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
            data : [
               `Database POST assign log error: ` + error
            ]
        })
    }

    return res.status(200).json({
        status : "success",
        timestamp : Date.now(),
        data : [
            await getLog(id),   // data[0]
            technician          // data[1]
        ]
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
            data : [
               "UNAUTHORISED! - Invalid or missing api_key"
            ]
        })
    }


    // // check if user_type == "Admin"
    // if (user_type != "Admin"){
    //     return res.status(400).json({
    //         status : "error",
    //         timestamp : Date.now(),
    //         data : [
    //            "Invalid user type - (Only 'Admin' can access machine records)"
    //         ]
    //     })
    // }


    let machines;

    try{
       machines = await getMachines();
    }
    catch (error){
        return res.status(500).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               `Database GET machines error: ` + error
            ]
        })
    }

    return res.status(200).json({
        status : "success",
        timestamp : Date.now(),
        data : {
            machines : machines
        }
    })
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
            data : [
               "UNAUTHORISED! - Invalid or missing api_key"
            ]
        })
    }

    // check if user_type == "Admin"
    if (user_type != "Admin"){
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               "Invalid user type - (Only 'Admin' can access machine records)"
            ]
        })
    }

    let machine;

    try{
        machine = await getMachine(id)

        if (machine){
            return res.status(200).json({
                status : "success",
                timestamp : Date.now(),
                data : [
                    machine
                ]
            })
        } else {
            return res.status(404).json({
                status : "error",
                timestamp : Date.now(),
                data: [
                    `Machine (id: ${id}) not in database`
                ]
            })
        }
    } 

    catch (error){
        return res.status(500).json({
            status: "error",
            timestamp: Date.now(),
            data: [
                `Database GET machine error: ` + error
            ]
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
            data : [
               "UNAUTHORISED! - Invalid or missing api_key"
            ]
        })
    }


    // check if user_type == "Admin"
    if (user_type != "Admin"){
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               "Invalid user type - (Only 'Admin' can access machine records)"
            ]
        })
    }

    // check if name in body exists
    if (!name){
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               "Missing name parameter"
            ]
        })
    }

    // check if location_id in body exists
    else if (!location_id){
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               "Missing location id"
            ]
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
                data: [
                    `Invalid location_id`
                ]
            })
        }
    }
    catch (error){
        return res.status(500).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               `Database POST log error: ` + error
            ]
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
            data : [
               `Database POST log error: ` + error
            ]
        })
    }

    return res.status(200).json({
        status : "success",
        timestamp : Date.now(),
        data : [
            newMachine
        ]
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
            data : [
               "UNAUTHORISED! - Invalid or missing api_key"
            ]
        })
    }


    // check if user_type == "Admin"
    if (user_type != "Admin"){
        
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               "Invalid user type - (Only 'Admin' can remove machine)"
            ]
        })
    }
    

    let machineExists;

    try{
        machineExists = await getMachine(id);
        // console.log(location);

        if (!machineExists){
            return res.status(400).json({
                status : "error",
                timestamp : Date.now(),
                data : [
                "Machine id does not exist in database"
                ]
            })
        }
        
    }
    catch (error){
        return res.status(500).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               `Database machine check error: ` + error
            ]
        })
    }


    // ** valid user (admin with api_key in db) **

    try{
        const successfullyRemoved = await removeMachine(id);

        if (successfullyRemoved) {
            return res.status(200).json({
                status : "success",
                timestamp : Date.now(),
                data : [
                    `Machine (id : ${id}) successfully removed from Database`
                ]
            });
        } else {
            return res.status(500).json({
                status : "error",
                timestamp : Date.now(),
                data : [
                    `Failed to remove machine (id : ${id}) from Database.`
                ]
            });
        }
    }
    catch (error){
        return res.status(500).json({
            status : "error",
            timestamp : Date.now(),
            data : [
                // console.log(error)
               `Database machine remove error: ` + error
            ]
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
            data : [
               "UNAUTHORISED! - Invalid or missing api_key"
            ]
        })
    }

    // check if user_type == "Admin"
    if (user_type != "Admin" || user_type != "Technician"){
        
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               "Invalid user type - (Only 'Admin' and 'Technician' can access log records)"
            ]
        })
    }



    // check if the user id is valid user in database

    let machine;

    try{
        machine = await getUser(id);

        if (!machine){
            return res.status(404).json({
                status : "error",
                timestamp : Date.now(),
                data: [
                    `Machine (id: ${id}) not in database`
                ]
            })
        }

    } catch (error){
        return res.status(500).json({
            status: "error",
            timestamp: Date.now(),
            data: [
                `Database GET machine error: ` + error
            ]
        })
    }



    let history;

    try{
       history = await getMachineHistory(id);

        if (history){
            return res.status(200).json({
                status : "success",
                timestamp : Date.now(),
                data : {
                    history : history
                }
            })
        } else {
            return res.status(404).json({
                status : "error",
                timestamp : Date.now(),
                data: [
                    `Machine (id: ${id}) has no past logs`
                ]
            })
        }

    }
    catch (error){
        return res.status(500).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               `Database GET machine history error: ` + error
            ]
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
            data : [
               "UNAUTHORISED! - Invalid or missing api_key"
            ]
        })
    }

    // check if user_type == "Admin" or "Technician"
    if (user_type != "Admin" && user_type != "Technician"){
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               "Invalid user type - (Only 'Admin' or 'Technician' can access specific log records)"
            ]
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
                    log : log
                }
            })
        } else {
            return res.status(404).json({
                status : "error",
                timestamp : Date.now(),
                data: [
                    `Log (id: ${id}) not in database`
                ]
            })
        }
    } 

    catch (error){
        return res.status(500).json({
            status: "error",
            timestamp: Date.now(),
            data: [
                `Database GET log error: ` + error
            ]
        })
    }
})

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
            data : [
               "UNAUTHORISED! - Invalid or missing api_key"
            ]
        })
    }


    // // check if user_type == "Admin"
    // if (user_type != "Admin"){
        
    //     return res.status(400).json({
    //         status : "error",
    //         timestamp : Date.now(),
    //         data : [
    //            "Invalid user type - (Only 'Admin' can access machine records)"
    //         ]
    //     })
    // }

    let locations;

    try{
       locations = await getLocations();
    }
    catch (error){
        return res.status(500).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               `Database GET locations error: ` + error
            ]
        })
    }

    return res.status(200).json({
        status : "success",
        timestamp : Date.now(),
        data : [
            locations
        ]
    })

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
            data : [
               "UNAUTHORISED! - Invalid or missing api_key"
            ]
        })
    }

    // check if user_type == "Admin"
    if (user_type != "Admin"){
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               "Invalid user type - (Only 'Admin' can access machine records)"
            ]
        })
    }

    let location;

    try{
        location = await getLocation(id)

        if (location){
            return res.status(200).json({
                status : "success",
                timestamp : Date.now(),
                data : [
                    location
                ]
            })
        } else {
            return res.status(404).json({
                status : "error",
                timestamp : Date.now(),
                data: [
                    `Location (id: ${id}) not in database`
                ]
            })
        }
    } 

    catch (error){
        return res.status(500).json({
            status: "error",
            timestamp: Date.now(),
            data: [
                `Database GET location error: ` + error
            ]
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
            data : [
               "UNAUTHORISED! - Invalid or missing api_key"
            ]
        })
    }

 
    // check if user_type == "Admin"
    if (user_type != "Admin"){
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               "Invalid user type - (Only 'Admin' can access machine records)"
            ]
        })
    }

    // check if name in body exists
    if (!name){
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               "Missing name parameter"
            ]
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
            data : [
               `Database POST location error: ` + error
            ]
        })
    }

    return res.status(200).json({
        status : "success",
        timestamp : Date.now(),
        data : [
            newLocation
        ]
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
            data : [
               "UNAUTHORISED! - Invalid or missing api_key"
            ]
        })
    }


    // check if user_type == "Admin"
    if (user_type != "Admin"){
        
        return res.status(400).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               "Invalid user type - (Only 'Admin' can remove loactions)"
            ]
        })
    }
    

    let locationExists;

    try{
        locationExists = await getLocation(id);
        // console.log(location);

        if (!locationExists){
            return res.status(400).json({
                status : "error",
                timestamp : Date.now(),
                data : [
                "Location id does not exist in database"
                ]
            })
        }
        
    }
    catch (error){
        return res.status(500).json({
            status : "error",
            timestamp : Date.now(),
            data : [
               `Database location check error: ` + error
            ]
        })
    }


    // ** valid user (admin with api_key in db) **

    try{
        const successfullyRemoved = await removeLocation(id);

        if (successfullyRemoved) {
            return res.status(200).json({
                status : "success",
                timestamp : Date.now(),
                data : [
                    `Location (id : ${id}) successfully removed from Database`
                ]
            });
        } else {
            return res.status(500).json({
                status : "error",
                timestamp : Date.now(),
                data : [
                    `Failed to remove location (id : ${id}) from Database.`
                ]
            });
        }
    }
    catch (error){
        return res.status(500).json({
            status : "error",
            timestamp : Date.now(),
            data : [
                // console.log(error)
               `Database location remove error: ` + error
            ]
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