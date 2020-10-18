const nodemailer = require('nodemailer'); 

module.exports.sendMail = async function sendMail(params){
    return new Promise((resolve,reject)=>{
        // const link = `${process.env.SERVER_IP}:${process.env.PORT}/signup/confirm?code=${params.code}`;
     const transport = nodemailer.createTransport({
         // host : 'smtp.gmail.com',
         // port : 587,
         service: 'gmail',
         auth: {
            user: 'fm_beldjillali@esi.dz', // generated ethereal user
            pass: '', // generated ethereal password
          },
        
        
     });
     transport.verify((error, success)=>{
         if (error)
             console.log(error)
         else
             console.log(success);
     })

    //  const html = `<p>Appuyez <a href="${link}"> ici </a> pour confirmer votre adresse mail.</p>`

     const messageInfo = {
         from : "process.env.MAIL_NAME",
         to : params.mail,
         subject : 'Confirmation de votre adresse mail.',
         html : params.html
     }

     transport.sendMail(messageInfo,(err, info) => {
        if (err){
            console.log( err);
            reject();  
        } 
        else {
             console.log(info.response)
             resolve();
        }

    });
});
}
