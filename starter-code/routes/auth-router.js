const express = require('express');
const router  = express.Router();
const bcrypt = require("bcrypt");

const User = require("../models/user-model.js")

router.get("/signup", (req,res,next)=>{
  res.render("auth-views/signup-form.hbs")
})

router.post("/adduser", (req,res,next)=>{
  const{usernameEntry, originalPassword} = req.body;

  if(!originalPassword || !usernameEntry || originalPassword.match(/[0-9]/) === null){
    req.flash("error", "Password or Username can't be blank and password must contain a number")
    res.redirect("/signup")
    return;
  }
  const username = usernameEntry.toLowerCase()
  User.findOne({username : {$eq : username}})
    .then(data => {
      if(data){
        req.flash("error", "Username already exists")
        res.redirect("/signup")
        return;
      }
      
      const encryptedPassword = bcrypt.hashSync(originalPassword, 10)
      User.create({username, encryptedPassword})
      .then(data => {
        req.flash("success", "success signup")
        res.redirect('/')
      })
      .catch(err=>next(err))
    })
    .catch(err=>next(err))

})


router.get("/login", (req,res,next)=>{
  res.render("auth-views/login-form.hbs")
})

router.post("/check-login", (req,res,next)=>{
  const {usernameGuess, passwordGuess} = req.body;

  User.findOne({username : {$eq : usernameGuess}})
    .then(data=>{
      if(!data){
        req.flash("error", "Username not found")
        res.redirect('/login')
        return;
      }
      if(bcrypt.compareSync(passwordGuess, data.encryptedPassword)){
        req.flash("success", "Success Login")
        res.redirect("/")
      }
      else{
        req.flash("error", "wrong password")
        res.redirect("/login")
      }
    })
    .catch(err=>next(err))
})



module.exports = router;