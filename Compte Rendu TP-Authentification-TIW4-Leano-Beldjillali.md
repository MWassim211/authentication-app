#  Compte Rendu TP-Authentification-TIW4

## Partie A & B : 

### 1- Mise en place du https :

##### Genération d'une clé RSA : 

​	openssl genrsa -out ./.ssh/key-new.pem 2048

##### Modification des droits sur la clé :

​	chmod 400 ./ssh/key-new.pem

##### Transfère de la clé en local :

​	scp -i .ssh/TIW4-VM-authentif.pem ubuntu@192.168.74.140:~/.ssh/key-new.pem /home/wassim/M2/SSI//tiw4-authentication/tiw4-ca/

##### Création des variables d'environnement  nécessaire aux fichiers de configurations :

​	export BASE_COUNTRY="FR" 

​	export BASE_STATE="Auvergne-Rhône-Alpes" 

​	export BASE_LOCALITY="Villeurbanne" 

​	export BASE_ORG="Université Claude Bernard - Lyon 1" 

​	export BASE_OU="Département Informatique" 

​	export BASE_CN="Autorité de Certification (AC) (TIW4-CA)" 

​	export BASE_SAN="email:romuald.thion@univ-lyon1.fr" 

​	export CLIENT_SAN="IP:192.168.74.140,DNS:tiw4-authentication-12.tiw4.os.univ-lyon1.fr" 

​	export CLIENT_CN="TIW4-TP2"

##### Génération du certificat signing request  :

​	openssl req -config ./conf/client.conf -key key-new.pem -new -out ./server-csr-new.csr

##### La signiature du certificat générée par la clé privée de l'autorithée : 

​	openssl ca -config conf/tiw4-ca.conf -passin pass:"kn4uxJKRe4oRmjCHxa9gYmmjVgMHuXbU" -in ./server-csr-new.csr -extensions server_cer

##### Transfère du certificat généré à la VM : 

​	scp -i ~/.ssh/TIW4-VM-authentif.pem ./newcerts/1002.pem ubuntu@192.168.74.140:~/

##### Configuration du serveur nginx : 

 - nous plaçons la clé générée dans le serveur (key-new.pem) et le certificat transférée (1002.pem) dans le dossier /etc/ssl/certs/

 - Nous configurons le serveur nginx pour qu'il utilise le nouveau certificat généré e ajoutant les deux lignes suivantes dans le fichier default de /etc/nginx/sites-availables :

    - ssl_certificate /etc/ssl/certs/1002.pem

    - ssl_certificate_key /etc/ssl/certs/key-new.pem

          upstream nodejs {
              zone nodejs 64k;
              server localhost:3000;
          }
          
          server {
              listen 443 ssl http2;
              listen [::]:443 ssl http2 ipv6only=on;
          #include /etc/nginx/snippets/snakeoil.conf;
          include /etc/nginx/snippets/ssl_params.conf;
          ssl_certificate /etc/ssl/certs/1002.pem;
          ssl_certificate_key /etc/ssl/certs/key-new.pem;
          
          location / {
             include /etc/nginx/snippets/proxy_set_header.conf;
             proxy_pass http://nodejs;
          	}
          }


      ###### Redirection  des requetes http en https :

      Ajouter la directive du redirection permanente 308.

      ```
      server {
      	listen 80;
          listen [::]:80;
          location / {
               return 308 https://192.168.74.140$request_uri;
          }
      }
      ```

      

      ### 2 - Sécuriser le serveur contre les attaques par repli  : 

      L'attaque par repli est une attaque consistant à passer d'un fonctionnement sécurisé à un fonctionnement moins sécurisé.

      cette attaque a été utilisée grâce à une faille dans [OpenSSL](https://fr.wikipedia.org/wiki/OpenSSL) permettant à l'attaquant de négocier l'utilisation d'une version obsolète du [protocole réseau TLS](https://fr.wikipedia.org/wiki/Transport_Layer_Security), induisant ainsi un chiffrement faible entre le client et le serveur.

      La suppression de la [rétrocompatibilité](https://fr.wikipedia.org/wiki/Compatibilité_ascendante_et_descendante) (par exemple, le serveur empêchant une connexion non chiffrée ou chiffrée de manière obsolète) est souvent le seul moyen d'empêcher cette attaque

      Nous allons mettre en place cette mesure de sécurité en interdissant la version TLSv1 du protocale SSL, Pour cela, nous allons modifié le fichier nginx.conf se trouvant dans /etc/nginx/nginx.conf

      

      ```
      ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3; # Dropping SSLv3, ref: POODLE
      ssl_prefer_server_ciphers on;
      ```

      ##### Reload le service nginx : 

      ```sudi
      sudo service nginx reload
      ```

      

      ### 3 - Mise en place du FireWall : 

      ​	1 - https://restorebin.com/ufw-firewall-lemp/

      ##### Installation : 

      ```
      sudo nano /etc/default/ufw
      ```

      ##### Pour refuser toutes les connexions entrantes : 

      ```
      sudo ufw default deny incoming
      ```

      ##### Autorise les connexions SSH : 

      ```
      sudo ufw allow 22
      ```

      ##### Autoriser Http et Https : 

      ```
      sudo ufw allow 'Nginx Full'
      ```

      ##### Activer le FireWall : 

      ```
      sudo ufw enable
      ```

      ##### Vérification du status du ufw : 

      ![ufw](/home/wassim/Pictures/ufw.png)

      

      ### 4- Mise en place de fail2ban : 

      	- https://www.youtube.com/watch?v=-rmK50PbqC

      Afin de limiter d'avoir une vu sur les tentatives de connexions par brute force sur un serveur web, nous utilisons fail2ban pour limiter les tentatives de connexions et bannir les adresses IPs suspects.

      ##### Installation : 

      ```
      sudo apt-get install fail2ban
      ```

      ##### Configuration :

      ```
      sudo nano /etc/fail2ban/jail.conf
      ```

      Nous nous interessons particulièrement aux directives ``` bantime``` et ```maxretry``` 

      ```
      bantime : Temps de banissement des IPs suspectes.
      maxtry : le nombre maximale de tentatives de connexion permise avant banissement.
      ```

      Nous pouvons également lancer des actions sur le fichier de log d'authentification, en repèrant par example les tentatives de connexions échouées. 

      ```
      sudo fail2ban-regex /var/log/auth.log ./filter.d/sshd.conf
      ```

      Puis en intéragissant avec le client fail2ban, nous pouvons avoir plusieurs informations concernant les jail créer.

      ```
      sudo fail2ban-client status
      ```

      

      ### 5 - HTTP Strict Transport Security (HSTS) :

      ​	- https://www.nginx.com/blog/http-strict-transport-security-hsts-and-nginx/

      Lorsqu'un utilisateur entre manuellement dans un domaine Web (en fournissant le nom de domaine sans le préfixe **http: //** ou **https: //** ) ou suit un simple lien **http: //** , la première demande adressée au site Web est envoyée non chiffrée, en utilisant HTTP ordinaire. La plupart des sites Web sécurisés renvoient immédiatement une redirection pour mettre à niveau l'utilisateur vers une connexion HTTPS, mais un attaquant peut lancer une attaque d'interception (MITM) pour intercepter la requête HTTP initiale et contrôler la session.

      

      HSTS cherche à gérer la vulnérabilité potentielle en indiquant au navigateur qu'un domaine n'est accessible qu'en HTTPS. Même si l'utilisateur entre un simple lien HTTP, le navigateur met strictement à niveau la connexion vers HTTPS.

      

      Une stratégie HSTS est publiée en envoyant l'en-tête de réponse HTTP suivant à partir de sites Web sécurisés (HTTPS): 

      ```
      Strict-Transport-Security: max-age=31536000
      ```

      Lorsqu'un navigateur voit cet en-tête d'un site Web HTTPS, il «apprend» que ce domaine ne doit être accessible qu'en utilisant HTTPS (SSL ou TLS). Il met en cache ces informations pour la `max-age`période (généralement 31 536 000 secondes, soit environ 1 an).

      La définition de l'en-tête de réponse STS (Strict Transport Security) dans NGINX et NGINX Plus est relativemenparamétrage du rate limiting (attentiot simple, il suffit d'ajouter la ligne suivante dans le fichier /etc/nginx/sites-availables/default, puis recharger le service nginx.

      ```
      add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
      ```

      Le `includeSubDomains`paramètre facultatif indique au navigateur que la stratégie HSTS s'applique également à tous les sous-domaines du domaine actuel.

      Le `always`paramètre garantit que l'en-tête est défini pour toutes les réponses, y compris les réponses d'erreur générées en interne.

      

      ### 6 - Cross-Site Scripting (XSS) : 

      ​	https://geekflare.com/http-header-implementation/#X-XSS-Protection

      ​	https://www.attosol.com/http-security-headers-with-nginx/

      L'en-tête X-XSS-Protection permet d'activer la protection contre les attaques XSS incluse dans les navigateurs Internet compatibles (IE, Chrome, Safari...). Cette en-tête peut prendre 4 valeurs différentes :

      ```
      0 : Filtre XSS désactivé.
      1 :	Filtre XSS activé et le navigateur nettoie la page si une attaque est détectée.
      1; mode = bloc : Filtre XSS activé et empêche le rendu de la page si une attaque est détectée.
      1; rapport = http: //example.com/report_URI	Filtre XSS activé et signalé la violation si une attaque est détectée.
      ```

      Nous avons Ajouté ce qui suit dans nginx.conf sous le bloc http : 

      ```
      add_header X-XSS-Protection "1; mode = bloc";
      ```

      ### 7 - Options X-Frame (à faire) : 

      L'en-tête X-Frame-Options est utilisé pour éviter **Clickjacking** (détournement de click) vulnérabilité sur votre site Web. En implémentant cet en-tête, vous indiquez au navigateur de ne pas intégrer votre page Web dans un cadre / une iframe. 

      ```
      add_header X-Frame-Options «DENY»;
      ```

      ### 8 - Politique de fonctionnalité (à faire):

      L'Ajout du header ```Feature-Policy ``` permet de contrôler les fonctionnalités du navigateur telles que la géolocalisation, le plein écran, le haut-parleur, le microphone, le paiement,  etc. pour activer ou désactiver dans une application Web.

      ```
      add_header Feature-Policy "geolocation 'none'; camera 'none'; speaker 'none';";
      ```

      ### 9 - Les attaques DOS :

      Une **attaque par déni de service** est une attaque ayant pour but de rendre indisponible un service, d'empêcher les utilisateurs légitimes d'un service de l'utiliser.

      - l’[inondation](https://fr.wikipedia.org/wiki/Flood_(Internet)) d’un [réseau](https://fr.wikipedia.org/wiki/Réseau_informatique) afin d'empêcher son fonctionnement ;
      - la perturbation des connexions entre deux machines, empêchant l'accès à un service particulier ;
      - l'obstruction d'accès à un service pour une personne en particulier ;

      Pour Empecher cela, nous allons ajouté deux directives dans le fichier /etc/nginx/nginx.conf : 

       - ```limit_req```  : permet de limiter le nombre de requetes maximum par IP et par seconde
       - ```limit_conn :```  permet de limiter le nombre de connexions maximum par IP

      Au début du bloc http, on ajoute donc les lignes suivantes :

      ```
      limit_req_zone $binary_remote_addr zone=flood:10m rate=100r/s;
      limit_req zone=flood burst=100 nodelay;
      ```

      Nous pouvons également limiter une IP à 100 connexions simultanées ou 100 requêtes par seconde. Si une personne devait dépasser l’une de ces limites le serveur lui servirait alors d'une erreur 503.

      ```
      limit_conn_zone $binary_remote_addr zone=ddos:10m;
      limit_conn ddos 100;
      ```

      ### 10 - **Options de type de contenu X** :

      Afin de prévenir les risques de sécurité des types **MIME**  nous ajoutant l'en-tête ``` X-Content-Type-Options ``` à la réponse HTTP des pages Web. Cet en-tête indique au navigateur de considérer les types de fichiers comme définis et d'interdire le reniflage de contenu.

      ```
      add_header X-Content-Type-Options nosniff;
      ```

      ### Conclusion :

      La sécurisation du serveur constitue une étape très importante pour faire face aux diverses attaques des
      malfaiteurs, sur cette partie nous avons essayé de détecter les failles les plus importantes par lesquelles notre
      serveur peut être attaqué et mettre en place les mesures nécessaires pour les empêcher, néanmoins nous
      n’avons pas pu corriger toutes les failles de sécurité.

      

      ##  **Partie C :**	

      ### 1 - Le stockage des mots de passes dans PostgreSQL et leurs gestion coté applicatif : 

      Nous avons constaté que les mots de passe etaient stockés en clair dans la base de donnée, ce qui est à éviter absolument dans n’importe quelle situation ! Pour corriger cela, nous avons utilisé ```bcrypt``` coté applicatif afin de chiffrer les mots de passe puis les stocker dans la base de données.

      pour les utilisateur existant dans la base, nous avons décidés de modifier leur mot de passe à chaine de caractères vide, puis il seront obligés au moment de connexion de réinitialiser leur mot, qui sera cette fois-ci crypté par l'application et envoyé à la base de donnée.

      Nous avons également opèré la modification suivante sur le schéma de la base de donnéesafin de contenir les mots de passe cryptés : 

      ```
      - Changement du type de l'attribut password de varchar(8) à text 
      ```

      pour crypté le mot de passe, dans le fichier ``` routes/signup.js ``` nous générons un sel puis nous  compressons  le mot de passe avant de le stocker dans la base de données.

      ```javascript
       const saltRounds = 10
       bcrypt.hash(password, saltRounds,async function(err,hash){
           ...
       })
      ```

      Pour le login, dans routes/authenticate.js , nous récupérons le mdp chiffré de la base de données puis on
      le compare avec le password tapé par le client

      ```javascript
       const resbd = await db.getPasswordByLogin(login);
       const pwdDBasString = resbd.password;
       const ok = await bcrypt.compare(pwd, pwdDBasString)
      ```

      

      ### 2 - Le processus de création de compte : 

      ##### 		2.1 Dureté du mot de passe : 

      Nous vérifions la puissance du mot passe au moment de la création du compte, en utilisant une expression régulière qui exige les contrantes suivantes sur les mot de passe : 

      ```
      - Avoir au minimum 8 caractères.
      - Avoir une lettre miniscule.
      - Avoir une lettre Majuscule.
      - Avoir un caractère spéciale.
      ```

      L'expression règulière vérifiant cela : 

      ```javascript
      async function passwordValidation (password) {
          return new Promise((resolve,reject)=>{
              const strongRegex = new RegExp("^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])(?=.{8,})");
              return strongRegex.test(password) ? resolve() : reject();
          })
      };
      ```

      #### 	2.2 Contrôle de saisie : 

      Sur le côté serveur dans le fichier signup.js , à la création d'un nouveau compte, nous vérifions l’existence de l’utilisateur ou de l’email dans la base de données. nous vérifions également la présence d'un login valide et la conformité des champs password et passwordConfirmation.

      ```javascript
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
              notifier.notify("Un compte assicié à cet email exist déja !, Veuillez renouveler votre inscription avec un nouveau 			Mail")
              res.redirect('/signup');
              return;
          }
      
          passwordValidation(req.body.password)
          .catch(e => {
              notifier.notify(" Password faible ! Utiliser 8 caractères minimum dont une lettre miniscule, une lettre majuscule, 			un caractère spécial, et un chiffre")
              console.log(e);
              res.redirect('/signup');  
          });
      ```

      ####  	2.3 mesures anti bots : 

      Pour cette partie, afin d'empêcher les attaques de bots, qui peuvent exoloser le nombre d'enregitrements de notre base données avec des scipts automatisés, nous avons utilisé API google pour mettre en place un captcha à l'aide des deux clés client et serveur. Néomoins, la captcha n'a pas fonctionné dans la VM, nous recevons pas la reponse de l'api google à notre requete, nous soupcenons que cela est du au firewell qui bloque les ports et donc les connexions exteérieure, mais nous nous sommes pas sure de ce point.

      ```javascript
      async function captchaVerification( captcha ){
          const captchaSecretKey = process.env.CAPTCHA_SECRET
          const verificationUrl = `https://www.google.com/recaptcha/api/siteverifysecret=${captchaSecretKey}&response=${captcha}`;
              console.log(verificationUrl)
              const res =  await fetch(verificationUrl)
                          .then(response => response.json())
                          .catch(err => console.log(err));
                  console.log(res);
              return res.success;
      }
      ```

      ### 3 -Limitation d'accès à la liste des utilisateurs :

      Nous avons limité l'accès à la liste des utilisateur qu'au users authontifiés.

      ```javascript
      router.get('/', checkUser);
      ```

      ### 4 - Processus de récuppération de mot passe :

      Nous avons mis en place un processus de réinitialisation de mot de passe ou :

       1. l'utilisateur introduit son mail afin de réinitialiser le mot de passe.

       2. le serveur vérifier l'existence du mail dans la bdd.

          ```javascript
          const user = await db.getUserByEmail(email);
            if(user.rows.length === 0){
              notifier.notify("Aucune utilisateur ne correspond à cet email !")
              return res.render('forgot');
            }.
          ```

          3 - Le serveur génére un token qui s'expire après 24h pour l'utilisateur concerné.

          ```javascript
           const token = JWT.sign(
              {ident: email},
              jwtResetKey,
              {expiresIn: `${jwtExpirySeconds} s`});
          ```

          4. un mail est envoyé à l'utilisateur contenant un lien valable pour 24 qui mène vers la page reset ou l'utilisateur introduit son nouveau mot de passe.

          ### 5 - limitations du nombre de tentatives : 

          Nous avons implementé un mecanisme qui permet de bloquer les utilisateurs ayant échoués 4 fois lors de l'authentification à leur compte pendant 20 minutes. pour cela nous avont ajouté les columnes suivantes dans la base de données.

          ```
          alter table users add column trycount integer default 0; ==> cette columne contiendra le nombre de tentatives effectuées pour un compte donné.
          alter table users add colum lasttry timestamp; ==> cette columne contiendra la date de la dernière tentative
          ```

          ```javascript
          const lastTryFailed = await db.getLastTryfailed(login)
                    const date = new Date(lastTryFailed.lasttry);
                    date.setTime(date.getTime() + (30 * 60 * 1000));
                    const datetime = new Date();
                    if(datetime < date){
                      notifier.notify("Vous avez échoué plusieurs fois ! Veuillez réessayer plus tard");
                    }
          ```

          ### 6 - Maintien d'une session (à faire) : 

          Initialement, le token permetait à l'utilisateur de rester connecté pour une minute, nous avons augmenté cela à une heure.

          Nous avons souhaité de créer un mécanisme qui permets d'utiliser deux token, access token and refresh token, que nous avons recontré pendant notre recherche, mais il s'avère que nous nous pouvons pas le mettre en ouevre car pour notre application , nous n'avons pas un code qui s'execute dans le navigateur. 

          Le mecanisme consiste à utiliser deux token : 

          	 - access token : contiennent les informations nécessaires pour accéder directement à une ressource. En
          d'autres termes, lorsqu'un client passe un jeton d'accès à un serveur gérant une ressource, ce serveur
          peut utiliser les informations contenues dans le jeton pour décider si le client est autorisé ou non. Les
          jetons d'accès ont généralement une date d'expiration et sont de courte durée.
            - refreshs token : contiennent les informations nécessaires pour obtenir un nouveau jeton d'accès. En
            d'autres termes, chaque fois qu'un jeton d'accès est requis pour accéder à une ressource spécifique, un
            client peut utiliser un jeton d'actualisation pour obtenir un nouveau jeton d'accès émis par le serveur
            d'authentification.

          ### 7 - Sécurisation des cookies : 

          Nous avons constaté que la transmission du token pour notre application se fait dans les cookies, pour cela nous avons souhaité modifier les options des cookies mais nous n'avons pas pu faire cela faute de temps: 

          ```
          secure - Garantit que le navigateur n’envoie le cookie que sur HTTPS.
          httpOnly - Garantit que le cookie n’est envoyé que sur HTTP(S), pas au JavaScript du client, ce qui
          renforce la protection contre les attaques de type cross-site scripting.
          domain - Indique le domaine du cookie ; utilisez cette option pour une comparaison avec le domaine du
          serveur dans lequel l’URL est demandée. S’ils correspondent, vérifiez ensuite l’attribut de chemin.
          expires - Utilisez cette option pour définir la date d’expiration des cookies persistants.
          ```

          

