import express from "express"
import mongoose from "mongoose"
import cookieParser from "cookie-parser"
import path from "path"
import jwt from "jsonwebtoken"
import bcrypt from "bcrypt"


var loginErrorText = ""
var registerErrorText = ""
// Connection to Database and Defining Schema
mongoose.connect("mongodb://127.0.0.1:27017", {dbName: 'backend'}).then(console.log("Connected to Databse")).catch("Failed to Connect to Database")
const loginSchema = new mongoose.Schema({username:String, password: String})
const account = mongoose.model("accounts", loginSchema)

// Creating an express app and some uses
const app = express()
app.use(express.static(path.join(path.resolve(), "public")))
app.use(express.urlencoded({extended:true}))
app.use(cookieParser())
app.set("view engine", "ejs")


const isAuthenticated = async (req, res, next)=>{
    const {token} = req.cookies 
    if(token){
        const decodedToken = jwt.verify(token, "kashif")
        req.user = await account.findById(decodedToken._id)
        next()
    }
    else{
        res.render("login", {loginErrors: loginErrorText})
    }
    loginErrorText = ""
}

app.get("/", isAuthenticated, (req, res)=>{
    res.render("logout", {name:req.user.username.split("@")[0]})
})


// Handling Login API
app.post("/login", async (req, res)=>{
    let isCorrectPassword
    let dbData = await account.findOne({username: req.body.username})
    if(dbData!=null) {
        await dbData
        isCorrectPassword = await bcrypt.compare(req.body.password, dbData.password)
    } else{
        isCorrectPassword = false 
    }

    
    
    
    if(dbData==null){
        loginErrorText = "Register First"
    }
    if(dbData!=null && !(isCorrectPassword)){
        loginErrorText = "Wrong Password"
    }
    if(dbData!=null && isCorrectPassword){
        const token = jwt.sign({_id:dbData.id}, "kashif")
         res.cookie("token", token, {expires: new Date(Date.now()+100000)})
}
res.redirect("/")
    
})




// Register Route
app.get("/register", (req, res)=>{
    res.render("register", {registerErrors: registerErrorText})
    registerErrorText = ""
})



// Registering the user in database
app.post("/register", async (req, res)=>{
    if((await account.findOne({username: req.body.username}))!=null){
        registerErrorText = "User already Exists"
        res.redirect("/register")
        return
    }
    const hashedPassword = await bcrypt.hash(req.body.password, 10)
    const user = await account.create({username:req.body.username, password: hashedPassword})
    const token = jwt.sign({_id:user.id}, "kashif")
    res.cookie("token", token, {expires: new Date(Date.now()+100000)})
    res.redirect("/")
})



// Logout API
app.get("/logout", (req, res)=>{
    res.cookie("token", null, {
        expires: new Date(Date.now())
    })
    res.redirect("/")
})


// Starting Listening
app.listen(5000, ()=>{
    console.log("Listening")
})