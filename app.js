require('dotenv').config();
const ejs = require('ejs');
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const encrypt = require('mongoose-encryption');
const crypto = require('crypto');
const session = require('express-session');
const passport = require('passport');
const passportLocal = require('passport-local');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

// const md5 = require('md5');
// const bcrypt = require('bcrypt');
// var saltRounds = 10;

const app = express();

app.set("view engine","ejs");
app.use(express.static("public"));
app.use(bodyParser.urlencoded({
  extended:true
}));

app.use(session({
  secret: "this is our little secret",
  saveUninitialized: false,
  resave: false,
  cookie:{}
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB",{useNewUrlParser:true,useUnifiedTopology: true});
mongoose.set('useCreateIndex',true);

const userSchema = mongoose.Schema({
  email:String,
  password:String,
  googleId:String
});

// var encKey;
// var sigKey;
// crypto.randomBytes(32,function(err,buffer){
//   encKey = buffer.toString('base64');
//   console.log(encKey);
// })
//
// crypto.randomBytes(64,function(err,buffer){
//   sigKey = buffer.toString('base64');
//   console.log(sigkey);
// })

// const options = {encryptionKey: encKey, signingKey: sigKey}

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);



// userSchema.plugin(encrypt,{secret:process.env.SECRET,encryptedFields:['password']});

const User = mongoose.model("user",userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileURL:'https://www.googleapis.com/oauth2/v3/userinfo'
},
function(accessToken, refreshToken, profile, cb) {
  User.findOrCreate({ googleId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));

app.get("/",function(req,res){
  res.render("home");
});

app.get("/register",function(req,res){
  res.render("register");
});

app.get("/secrets",function (req,res) {
  if (!req.isUnauthenticated()) {
    res.render("secrets");
  } else {
    res.redirect("/login");
  }
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

  app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.post("/register",function(req,res) {
  // bcrypt.hash(req.body.password,saltRounds,function(err,hash){
  //   if(!err){
  //     const doc = User({
  //       email:req.body.username,
  //       password:hash
  //     });
  //     doc.save(function(err){
  //       if(!err){
  //         res.render("secrets");
  //       }else{
  //         console.log(err);
  //       }
  //     });
  //   }else{
  //     console.log(err);
  //   }
  // });


  User.register({username:req.body.username,active:false},req.body.password,function(err,user) {
    if(!err){
      passport.authenticate('local')(req,res,function() {
        res.redirect("/secrets");
      })
    }else{
      console.log(err);
    }
  })

})

app.get("/login",function(req,res){
  res.render("login");
});

app.post("/login",function(req,res) {
  // bcrypt.hash(req.body.password,saltRounds,function(err,hash){
  //   if(!err){
  //     User.findOne({email:req.body.username},function(err,foundUser){
  //       if(!err){
  //         if(foundUser.password === hash){
  //           res.render("secrets");
  //         }else{
  //           res.send("password is wrong");
  //         }
  //       }else{
  //         res.send("email is wrong");
  //         console.log(err);
  //       }
  //     })
  //   }else{
  //     console.log(err);
  //   }
  // });

  const user = User({
    username:req.body.username,
    password:req.body.password
  });

  req.logIn(user,function(err) {
    if(err){
      console.log(err);
    }else{
      res.redirect("/secrets");
    }
  })
});


app.get('/logout', function(req, res){
  req.logOut();
  res.redirect('/');
});

app.listen(3000,()=>console.log("Started Server"));
