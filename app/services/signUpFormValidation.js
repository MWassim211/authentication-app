const db = require('../models/queries');

async function checkEmailExist(email){
    const res = await db.checkEmailExist(email);
    return res;
};

async function checkUsernameExist(username){
    return  db.checkUsernameExist(username);
}


async function passwordValidation (password) {
    return new Promise((resolve,reject)=>{
        const strongRegex = new RegExp("^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])(?=.{8,})");
        return strongRegex.test(password) ? resolve() : reject();
    })
};

function passwordValidation2 (password) {
        const strongRegex = new RegExp("^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])(?=.{8,})");
        return strongRegex.test(password) 
};

module.exports = {checkEmailExist , checkUsernameExist , passwordValidation , passwordValidation2 }
