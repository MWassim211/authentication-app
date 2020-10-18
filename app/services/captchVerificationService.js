const fetch = require('node-fetch');

module.exports.captchaVerification =  async function captchaVerification( captcha ){
    
    const captchaSecretKey = process.env.CAPTCHA_SECRET
    const verificationUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${captchaSecretKey}&response=${captcha}`;

        const res =  await fetch(verificationUrl)
                    .then(response => response.json())
        return res.success;
}