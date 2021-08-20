require('dotenv').config();
const express=require("express");
const ejs=require("ejs");
const bodyparser=require("body-parser");
const mongoose = require('mongoose');
const session = require('express-session');
const passport=require("passport");
const findOrCreate = require('mongoose-findorcreate')
const passportLocalMongoose=require("passport-local-mongoose");
var GoogleStrategy = require('passport-google-oauth20').Strategy;// USING GOOGLE AUTH 2.0
var FacebookStrategy=require("passport-facebook");


// for encryption --- const encrypt=require("mongoose-encryption");
//const md5=require("md5");
// for bcrypt const bcrypt=require("bcrypt");const saltRounds = 10;

const app=express();
app.set('view engine','ejs');
app.use(bodyparser.urlencoded({extended:true}));
app.use(express.static("public"));


// For passport and session start
app.use(session({
  secret: "Our little secret",
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());



mongoose.connect('mongodb://localhost:27017/UserDB', { useNewUrlParser: true,useUnifiedTopology: true });
mongoose.set('useCreateIndex', true);
const userschema=new mongoose.Schema({
    email:String,
    password:String,
    googleId:String,
    facebookId:String,
    secret:String
    
});


userschema.plugin(passportLocalMongoose);  // for Passport-local-mongoose plugin
userschema.plugin(findOrCreate);
// plugin for encryption ----- userschema.plugin(encrypt, { secret: process.env.SECRET , encryptedFields: ["password"] });

const User=mongoose.model("User",userschema);

// for passport-local-mongoose configuration
passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());


// for authenticating using google i.e google oauth2.0
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,     // for getting the id and secerts from .env
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
      console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


// for facebook
passport.use(new FacebookStrategy({
    clientID: process.env.CLIENT_ID_FACEBOOK,
    clientSecret: process.env.CLIENT_SECRET_FACEBOOK,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/auth/facebook",
  passport.authenticate('facebook',{ scope: ['user_friends', 'manage_pages'] }));

app.get("/auth/facebook/secrets",
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });


// get request for google authentication
app.get("/auth/google",                                      // used to redirect us to signup with google screen 
  passport.authenticate('google', { scope: ["profile"] }));   

  app.get("/auth/google/secrets",  // after authetification it will redirect us to this get route and it is same that we mentioned in Authorized redirect URIs in google cloud platform
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home or to secerts page in this project.
    res.redirect('/secrets');
  });  

app.get("/",function(req,res){
    res.render("home");
});


app.get("/login",function(req,res){
    res.render("login");
});

app.get("/register",function(req,res){
    res.render("register");
});

app.get("/secrets",function(req,res){
   User.find({"secret":{$ne:null}},function(err,found){
     if(err) console.log(err);
     else{
     if(found) res.render("secrets",{userSecret:found});
     }
   });
});


app.get("/logout",function(req,res){
req.logout();
res.redirect("/");

});

app.get("/submit",function(req,res){
  if(req.isAuthenticated()){
    res.render("submit");
}
else res.redirect("/login");
  
})

app.post("/submit",function(req,res){
const submiited=req.body.secret;
User.findById(req.user.id,function(err,found){  // passport save the info about the user that logged in so we can use it
  if(err) console.log(err);
  else{
    if(found) {
      found.secret=submiited;
      found.save(function(){
        res.redirect("/secrets");
      });
    }
  }
})
});

app.post("/register",function(req,res){

// register using passport-local-mongoose which make a new user and save it to mongodb by interactiong with mongoose

User.register({username:req.body.username},req.body.password,function(err,user){

   if(err){
       console.log(err);
       res.redirect("/register");
   }
   else{
       passport.authenticate("local")(req,res,function(){
           res.redirect("/secrets");
       })
   } 
});






    /* For BCRYPT 
bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    const newUser=new User({
        email:req.body.username,
        // for encryption ----password:req.body.password
        password:hash
    });
    newUser.save(function(err){
        if(err) console.log(err);
        else res.render("secrets")
    })
    

    });    
/*
For md5
const newUser=new User({
    email:req.body.username,
    // for encryption ----password:req.body.password
    password:md5(req.body.password)
});
newUser.save(function(err){
    if(err) console.log(err);
    else res.render("secrets")
})

*/
});

app.post("/login",function(req,res){

// using passport library to login
const user=new User({
    username:req.body.username,
    password:req.body.password
});
req.login(user,function(err){
    if(err) console.log(err);
    else{
        passport.authenticate("local")(req,res,function(){
            res.redirect("/secrets");
        })
    }
});








    /*for bcrypt and md5 
 const username=req.body.username;
// for encryption--const password=req.body.password;
// for md5 const password=md5(req.body.password);
const password=req.body.password;

User.findOne({email:username},function(err,found){
    if(err) console.log(err);
    else{
        if(found){
            bcrypt.compare(password, found.password, function(err, result) {
                // result == true
                if(result==true) res.render("secrets");
            });

            // for md5 if(found.password == password ) res.render("secrets");
            
        }
    }
});
*/

});










app.listen(3000,function(req,res){
    console.log("server started");
})