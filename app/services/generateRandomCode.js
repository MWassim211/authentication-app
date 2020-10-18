const bcrypt = require('bcrypt');

function generateRandomCode(){
    let result = '';
    const saltround = 10;
    const codelength = 30;
    const characters =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const charactersLength = characters.length;
    for (let i = 0; i < codelength; i+=1) {
      result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    result = bcrypt.hashSync(result, saltround);
    return result;
}

function generateRandomCodeWithoutSpecialChars(length) {
  const randomChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for ( let i = 0; i < length; i+=1 ) {
      result += randomChars.charAt(Math.floor(Math.random() * randomChars.length));
  }
  return result;
}

module.exports = {generateRandomCodeWithoutSpecialChars , generateRandomCode}