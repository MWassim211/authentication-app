const express = require('express');
const { JWT, JWK : { asKey } } = require('jose');
const createError = require('http-errors');
const crypto = require('crypto');
const notifier = require('node-notifier');
const nodemailer = require('nodemailer'); 
const bcrypt = require('bcryptjs');
const db = require('../models/queries');
const {passwordValidation2 } = require('../services/signUpFormValidation');


const router = express.Router();

// JWK will base64 encode the secret
const jwtResetKey = asKey(
  process.env.NODE_ENV === 'development' ? Buffer.from(process.env.SECRET_KEY || 'secret') : crypto.randomBytes(16)
);

const jwtExpirySeconds = 3600 * 24;

/* GET home Reset page. */
router.get('/', function rootHandler(req, res, _next) {
  res.render('forgot', {});
});

router.post('/',async function HandleReset(req,res,next){
  const {email} = req.body;
  const token = JWT.sign(
    {ident: email},
    jwtResetKey,
    {expiresIn: `${jwtExpirySeconds} s`});
    
  const user = await db.getUserByEmail(email);
  if(user.rows.length === 0){
    notifier.notify("Aucune utilisateur ne correspond à cet email !")
    return res.render('forgot');
  }
  const expireToken = Date.now() + 3600000 // 1 heure
  await db.addResetToken(email,token,expireToken)
  const link = `${process.env.SERVER_IP}:${process.env.PORT}/reset/${token}`


  const transport = nodemailer.createTransport({
    // host : 'smtp.gmail.com',
    // port : 587,
    host: 'smtp.univ-lyon1.fr',
    port: 25,
    secure: false, // true for 465, false for other ports
  
    })

  const messageInfo = {
    from : "process.env.MAIL_NAME",
    to : 'carireg640@swanticket.com',
    subject : "Réinitialisation du mot de passe",
    html : 
    `<p>Vous avez demandé la réinitilisation de votre mot de passe <p>
    <p> Cliquer sur ce  <a href="${link}"> lien </a> afin de réinitialiser votre mot de passe</p>`
  }



    transport.sendMail(messageInfo,(err, info) => {
        if (err){
            console.log( err);  
        } 
        else {
             console.log(info.response)
        }
    });

    res.render("resetInfo", { messageInfo });
    next();
})


router.get('/:token', async function(req,res,next){
  try{
    const {token} = req.params;
    const response = await db.getUserbyResetCode(token)
    const payload = JWT.verify(token, jwtResetKey, {
      ident : response.email
    });
    if(payload.ident)
      res.render('resetForm',{token})
  }catch(err){
    if (
      err.code === 'ERR_JWT_CLAIM_INVALID' ||
      err.code === 'ERR_JWT_MALFORMED' ||
      err.code === 'ERR_JWS_VERIFICATION_FAILED'
     ){
        // res.render("failedReset")
        console.log(err)
     }
    next(createError(500, err));
  }
  
})


router.post('/:token', async function Handle(req,res){
  const {token} = req.params;
  const {password} = req.body;
  const result = await db.getUserbyResetCode(token)
  const  useremail = result.email;
    if(!useremail){
     return res.redirect('/login')
    }
    if(req.body.password === req.body.confirmPassword){
      const strenthpassword = passwordValidation2(password)
      if(strenthpassword === true){
        const saltRounds = 10
          bcrypt.hash(req.body.password, saltRounds, async function(err,hash){
            if(hash){
              await db.updateUserPassword(useremail,hash);
              res.render("SuccesfullReset", {})
            }
          })
      }else{
        notifier.notify(" Password faible ! Utiliser 8 caractères minimum dont une lettre miniscule, une lettre majuscule, un caractère spécial, et un chiffre")
        return res.redirect(req.get('referer'));
      }
    }else{
      notifier.notify('Les mots de passe rensegnés ne sont pas identiques');
      // res.redirect('/reset/${token}');
      return res.redirect();
    }

})

module.exports = router;
