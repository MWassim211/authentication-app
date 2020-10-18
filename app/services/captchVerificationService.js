const fetch = require('node-fetch');

module.exports.captchaVerification =  async function captchaVerification( captcha ){
    
    const captchaSecretKey = process.env.CAPTCHA_SECRET
    const verificationUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${captchaSecretKey}&response=${captcha}`;
        console.log(verificationUrl)
        const res =  await fetch(verificationUrl)
                    .then(response => response.json())
                    .catch(err => console.log(err));
            console.log(res);
        return res.success;
}