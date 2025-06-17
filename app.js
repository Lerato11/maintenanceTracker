// ------ express code for the server ------- //

import express from "express"

import {getUsers, getUser, registerUser, checkEmail, getLogs, getLog, createLog, updateLogStatus,
    assignLog, getMachines, getMachine, addMachine, getMachineHistory, getLocations, getLocation,
    checkApiKey,
    removeUser} from "./database.js";


// const { createHash } = require('crypto');
import {createHash} from "crypto";

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
app.get("/user/:id", async (req, res) => {
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
        const [registeredUser] = await registerUser(email, username, hashedsaltedPassword, user_type, salt, api_key);
    } 
    catch (error){
        return res.json({
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
        return res.json({
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
        return res.json({
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

// -------------------- get all technician's logs (technician) --------------------


// -------------------- get specific log (admin and techncian) --------------------


// -------------------- create log (any user) --------------------


// -------------------- update log status (admin and techncian) --------------------


// -------------------- assign log (admin) --------------------


// -------------------- get all machines (admin)  --------------------
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

    let machines;

    try{
       machines = await getMachines();
    }
    catch (error){
        return res.json({
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


// -------------------- add a machine (admin) --------------------


// -------------------- get all specific machineHistory (admin) --------------------


// -------------------- get all locations (admin)  --------------------
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

    let locations;

    try{
       locations = await getLocations();
    }
    catch (error){
        return res.json({
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
        data : {
            locations : locations
        }
    })

})

// -------------------- get specific location (admin) --------------------


// -------------------- add a location (admin) --------------------


// -------------------- remove a location (admin) --------------------




// app.use((err, req, res, next) => {
//     console.error(err.stack)
//     res.status(500).send("Something broke!")
// })

app.listen(8080, () => {
    console.log("Server running on port: 8080")
})