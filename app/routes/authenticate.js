// prettier-ignore
const { JWT, JWK : { asKey } } = require('jose');
const debug = require('debug')('app:authenticate');
const createError = require('http-errors');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const notifier = require('node-notifier');
const db = require('../models/queries');


// JWK will base64 encode the secret
const jwtServerKey = asKey(
  process.env.NODE_ENV === 'development' ? Buffer.from(process.env.SECRET_KEY || 'secret') : crypto.randomBytes(16)
);
console.log(jwtServerKey)
// token duration in seconds
const jwtExpirySeconds = 3600;
const issuerID = 'TIW4-SSI -- LOGON App';

// call postgres to verify request's information
// if OK, creates a jwt and stores it in a cookie, 401 otherwise
async function authenticateUser(req, res, next) {
  const { login } = req.body;
  const pwd = req.body.password;
  debug(`authenticate_user(): attempt from "${login}" with password "${pwd}"`);
  try {
    const existuser = await db.checkUsernameExist(login)
    if(!existuser){
      notifier.notify("Aucun utilisateur enregistrer à ce nom , Veuillez créer un compte !")
      return res.render("login",{})
    }
    const isUserverified = await db.isUserVerified(login)
    if (!isUserverified){
      notifier.notify("Vous n'avez pas valider votre enregistrement ! ")
      return res.render("login",{})
    }
    // const pwdDB = await db.getPasswordByLogin(login);
    await db.setLastConnexionTime(login);
    const resbd = await db.getPasswordByLogin(login);
    debug(`pwd : ${resbd}`);
    // const pwdDBasString = JSON.stringify(await db.getPasswordByLogin(login))
    const pwdDBasString = resbd.password;
    const ok = await bcrypt.compare(pwd, pwdDBasString)
    .then(async function(result){
      const nbFailedTry = await db.getNbTryFailed(login);
      debug(`result : ${result}`);
      debug(`nbFailedTry : ${nbFailedTry}`);
      if (result===true && nbFailedTry.trycount < 3){
        return result;
      }  
        if(nbFailedTry.trycount < 3){
          await db.updateTotalTyForUser(login);
          notifier.notify("Invalid login/Password")
          return false;
        }
          const lastTryFailed = await db.getLastTryfailed(login)
          const date = new Date(lastTryFailed.lasttry);
          date.setTime(date.getTime() + (30 * 60 * 1000));
          const datetime = new Date();
          if(datetime < date){
            notifier.notify("Vous avez échoué plusieurs fois ! Veuillez réessayer plus tard");
            // return false;
          }
          // await db.updateTotalTyForUser(login);
          return false;
    })
    .catch((err)=>console.error(err))
    
    debug(`password from db : ${pwdDBasString}`);
    debug(`pwd : ${pwd}`);
    debug(` ok : ${ok}`)
    if (!ok) {
      res.render('login', {});
      return false;
    }
    
      db.ResetTryToZero(login);
      // inspiration from https://www.sohamkamani.com/blog/javascript/2019-03-29-node-jwt-authentication/
      const payload = {
        sub: login,
        // fields 'iat' and 'exp' are automatically filled from  the expiresIn parameter
      };

      const options = {
        algorithm: 'HS256',
        issuer: issuerID,
        expiresIn: `${jwtExpirySeconds} s`,
        header: {
          typ: 'JWT',
        },
      };

      // Create a new token
      // https://github.com/panva/jose/blob/master/docs/README.md#jwtsignpayload-key-options
      const token = JWT.sign(payload, jwtServerKey, options);
      // Add the jwt into a cookie for further reuse
      // see https://www.npmjs.com/package/cookie
      res.cookie('token', token, { maxAge: jwtExpirySeconds * 1000 * 2 });

      debug(`authenticate_user(): "${login}" logged in ("${token}")`);
      next();
      return true;
    
  } catch (e) {
    next(createError(500, e));
    return false;
  }
}

// checks if jwt is present and pertains to some user.
// stores the value in req.user
// eslint-disable-next-line consistent-return
function checkUser(req, _res, next) {
  const { token } = req.cookies;
  debug(`check_user(): checking token "${token}"`);

  if (!token) {
    return next(createError(401, 'No JWT provided'));
  }

  try {
    const payload = JWT.verify(token, jwtServerKey, {
      algorithms: ['HS256'],
      issuer: issuerID,
    });

    if (!payload.sub) next(createError(403, 'User not authorized'));

    debug(`check_user(): "${payload.sub}" authorized`);
    req.user = payload.sub;
    return next();
  } catch (err) {
    if (
      err.code === 'ERR_JWT_CLAIM_INVALID' ||
      err.code === 'ERR_JWT_MALFORMED' ||
      err.code === 'ERR_JWS_VERIFICATION_FAILED'
    ) {
      // if the error thrown is because the JWT is unauthorized, return a 401 error
      next(createError(401, err));
    } else {
      // otherwise, return a bad request error
      next(createError(400, err));
    }
  }
}

module.exports = { checkUser, authenticateUser };
