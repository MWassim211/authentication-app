const { Pool } = require('pg');
const debug = require('debug')('app:postgres');
require('dotenv').config();

// loads configuraiton from environnement variables overrided by '.env' file
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASS,
  port: process.env.DB_PORT,
});

// The list of all users
async function getUsers() {
  debug(`getUsers()`);
  const result = await pool.query('SELECT username, email FROM users;');
  return result.rows;
}

// Inserts a user
async function addUser(username, email, pwd) {
  debug(`addUser("${username}", "${email}", "${pwd}")`);
  const result = await pool.query('INSERT INTO users(username, email, password) VALUES ($1, $2, $3);', [
    username,
    email,
    pwd,
  ]);
  return result;
}

// getUserByemail
async function getUserByEmail(email){
  debug(`getUserByEmail("${email}")`);
  const result = await pool.query('select userid from users where email=$1',[
    email
  ]);
  return result;
}

async function getPasswordByLogin(login){
  debug(`getPasswordByLogin("${login}")`);
  const result = await pool.query('select password from users where username=$1',[
    login
  ]);
  return result.rows[0];
}

async function isUserVerified(login){
  debug(`isUserVerified("${login}")`);
  const result = await pool.query('select from users where username=$1 and verified=$2',[
    login,
    true
  ]);
  return result.rowCount === 1;
}

async function confirmUser(userid){
  debug(`confirmUser("${userid}")`);
  const result = await pool.query('Update users set verified=$1 where userid=$2', [
    true,
    userid,
  ]);
  return result;
}

async function getTempUserIdByCode(code){
  debug(`getTempUserIdByCode("${code}")`);
  const result = await pool.query('select userid from users_temp where code=$1',[
    code
  ]);
  return result;
}



async function addTempUser(userid, code) {
  debug(`addTempUser("${userid}", "${code}")`);
  const result = await pool.query('INSERT INTO users_temp(userid, code) VALUES ($1, $2);', [
    userid,
    code,
  ]);
  return result;
}

async function deleteTempUser(userid){
  debug(`addTempUser("${userid}")`);
  const result = await pool.query('DELETE from users_temp where userid=$1', [
    userid
  ]);
  return result;
}

// Boolean query to check a user/password
async function checkUser(login, pwd) {
  debug(`checkUser("${login}", "${pwd}")`);
  const result = await pool.query('SELECT  FROM users WHERE username=$1 AND password=$2;', [login, pwd]);
  return result.rowCount === 1;
}


async function checkUsernameExist(login){
  debug(`checkUsernameExist("${login}")`);
  const result = await pool.query('Select from users where username=$1',[
    login
  ]);
  return result.rowCount !== 0;
}

async function checkEmailExist(email){
  debug(`checkEmailExist("${email}")`);
  const result = await pool.query('Select from users where email=$1',[
    email
  ]);
  return result.rowCount !== 0;
}


async function addResetToken(email,resetToken,resetTokenExipredOn){
  debug(`addResetToken("${email}","${resetToken}","${resetTokenExipredOn}")`);
  const result = await pool.query('update users set resettokenexipredon=current_timestamp where email=$1',[
    email,
  ]);  
  const result2 = await pool.query('update users set resetToken=$2 where email=$1', [
    email,
    resetToken
  ]);
  return { result, result2}
}


async function getUserbyResetCode(resettoken){
  debug(`getUserbyResetCode("${resettoken}")`);
  const result = await pool.query('select email from users where resettoken=$1',[
    resettoken
  ])
  debug(`ResultgetUserbyResetCode("${result.rows[0]}")`);
  return result.rows[0];
  
}

async function updateUserPassword(email,encryptpassword){
  debug(`updateUserPassword("${email}", "${encryptpassword}")`);
  const result = await pool.query('update users set password=$2 where email=$1',[
    email,
    encryptpassword,
  ])
  return result;
}

async function updateTotalTyForUser(username){
  debug(`updateTotalTyForUser("${username}")`);
  const result = await pool.query('update users set trycount=trycount+1 where username=$1',[
    username,
  ])
  return result;
}

async function setLastConnexionTime(username){
  debug(`setLastConnexionTime("${username}")`);
  const result = await pool.query('update users set lasttry = current_timestamp where username=$1',[
    username,
  ])
  return result;
}

async function getNbTryFailed(username){
  debug(`getNbTryFailed("${username}")`);
  const result = await pool.query('select trycount from users where username=$1',[
    username,
  ])
  return result.rows[0];
}

async function getLastTryfailed(username){
  debug(`getLastTryfailed("${username}")`);
  const result = await pool.query('select lasttry from users where username=$1',[
    username,
  ])
  return result.rows[0];
}

async function ResetTryToZero(username){
  debug(`ResetTryToZero("${username}")`);
  const result = await pool.query('update users set trycount=0 where username=$1',[
    username,
  ])
  return result;
}

module.exports = { getUsers, checkUser, addUser, getLastTryfailed , addTempUser, confirmUser, deleteTempUser, getUserByEmail,
   getTempUserIdByCode, checkUsernameExist , ResetTryToZero ,checkEmailExist , setLastConnexionTime ,updateTotalTyForUser ,
    getNbTryFailed, isUserVerified, addResetToken , getUserbyResetCode, updateUserPassword, getPasswordByLogin};
