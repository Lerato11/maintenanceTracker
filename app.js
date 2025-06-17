// ------ express code for the server ------- //

import express from "express"

import {getUsers, getUser, registerUser, checkEmail, getLogs, getLog, createLog, updateLogStatus,
    assignLog, getMachines, getMachine, addMachine, getMachineHistory, getLocations, getLocation} from "./database.js";


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


// -------------------- get specific users --------------------
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





// app.use((err, req, res, next) => {
//     console.error(err.stack)
//     res.status(500).send("Something broke!")
// })

app.listen(8080, () => {
    console.log("Server running on port: 8080")
})