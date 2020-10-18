const express = require('express');
const createError = require('http-errors');
const bcrypt = require('bcryptjs');
const notifier = require('node-notifier');
const db = require('../models/queries');
const { sendMail } = require('../services/mailservice');
const { captchaVerification } = require ('../services/captchVerificationService');
const { generateRandomCode } = require('../services/generateRandomCode');
const {checkEmailExist , checkUsernameExist , passwordValidation } = require('../services/signUpFormValidation');



const router = express.Router();

router.get('/', function signupHandler(_req, res, _next) {
  res.render('signup', {});
});

router.post('/', async function signupHandler(req, res, next) {
  try {
    const email = req.body.email.toLowerCase();
    const login = req.body.username.toLowerCase();
    const {password} = req.body;
    const passwordConfirm = req.body.confirmPassword;
    const captcha = req.body['g-recaptcha-response'];
    if (login.length === 0){
      notifier.notify('Veuillez renseigné un Username Valide')
      res.redirect('/signup');
      return;
    }
    if (password !== passwordConfirm){
      notifier.notify('Les mots de passe rensegnés ne sont pas identiques');
      res.redirect('/signup');
      return;
    }
    const usernameExist = await checkUsernameExist(login)
    if(usernameExist === true) {
        notifier.notify("Un compte assicié à ce username exist déja ! Veuillez renouveller votre inscription en choissisant un nouveau login :) ")
        res.redirect('/signup');
        return;
    }

    const emailexist = await checkEmailExist(req.body.email)
    if(emailexist === true) {
        notifier.notify("Un compte assicié à cet email exist déja !, Veuillez renouveler votre inscription avec un nouveau Mail")
        res.redirect('/signup');
        return;
    }
    passwordValidation(req.body.password)
    .catch(e => {
        notifier.notify(" Password faible ! Utiliser 8 caractères minimum dont une lettre miniscule, une lettre majuscule, un caractère spécial, et un chiffre")
        console.log(e);
        res.redirect('/signup');
        
    });
    const captchavalid = await captchaVerification(captcha)
    if(!captchavalid){
        res.redirect('/signup')
    } 
    sendMail({mail : email}) 
    const code = await generateRandomCode();

    const link = `/signup/confirm?code=${code}`;
    const html = `<p>Appuyez <a href="${link}"> ici </a> pour confirmer votre adresse mail.</p>`
    sendMail({mail : email , html})
    .catch(()=>{
      console.log("Erreur lors de lenoie ");
    })
    const saltRounds = 10
    bcrypt.hash(password, saltRounds,async function(err,hash){
    if (hash){
      await db.addUser(login, email, hash);
      const user = await db.getUserByEmail(email);
      const {userid}  = user.rows[0];
      await db.addTempUser(userid,code);
      res.render('messageInfo', {html});
    }else {
        console.log(err)
    }
})
    
      // res.redirect('/');
  } catch (e) {
    console.log(e)
    next(createError(500, e));
  }
});


router.get("/confirm", async function signupHandler(req, res, next) {
    try {
    const {code} = req.query;
    const user = await db.getTempUserIdByCode(code);
    const {userid}  = user.rows[0];
    await db.confirmUser(userid);
    await db.deleteTempUser(userid);
    res.render('successfulSignUp',{})
  }catch (e) {
    console.log(e)
    next(createError(500, e));
  }

})
module.exports = router;
