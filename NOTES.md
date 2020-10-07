## PROF 
- fichier de config nginx
- fichier des changements SQL
- garder traces du travail (backups)
- pas toucher ssh (ouvrir un ssh et un autre pour le test)

## DEMO
dans ssh on a des clefs ou certs, et known_hosts ET config
config : declarations ou on peut donner 
    - un nom a la machine 
    - ip 
    - utilisateur
 proxyjump 

byobu

on version pas .env ???
renomer le fichier DEV_ENV 

## TP 07/10/2020
### questions discord
Question : que fait la ligne #10 de ce fichier ? (/etc/nginx/sites-available/default)
    include /etc/nginx/snippets/snakeoil.conf;

    * ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem; 
    
    Specifies a file with the certificate in the PEM format for the given virtual server. If intermediate certificates should be specified in addition to a primary certificate, they should be specified in the same file in the following order: the primary certificate comes first, then the intermediate certificates. A secret key in the PEM format may be placed in the same file. 

    * ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;

     Specifies a file with the secret key in the PEM format for the given virtual server.

    The value engine:name:id can be specified instead of the file (1.7.9), which loads a secret key with a specified id from the OpenSSL engine name.

    The value data:$variable can be specified instead of the file (1.15.10), which loads a secret key from a variable without using intermediate files. Note that inappropriate use of this syntax may have its security implications, such as writing secret key data to error log.

    * ssl_prefer_server_ciphers on
    Specifies that server ciphers should be preferred over client ciphers when using the SSLv3 and TLS protocols.  

## TP PARTIE A
changement de la redirection de http a https vers notre ip 
- AVANT
server {
    listen 80;
    listen [::]:80;
    location / {
         return 308 https://192.168.74.142/$request_uri;
    }
}

- MAINTENANT
server {
    listen 80;
    listen [::]:80;
    location / {
         return 308 https://192.168.74.140/$request_uri;
    }
}


## TP PARTIE B

### COMMANDES
* pour la generation d'une cle :
    openssl genrsa -out ./.ssh/ key.pem 2048

* pour copier la cle a notre machine
    scp -i ~/.ssh/TIW4-VM-authentif.pem ubuntu@192.168.74.140:~/.ssh/key.pem /home/wassim/M2/SSI/

* generation du CSR:
    - creation des variables d'environement
        export BASE_COUNTRY="FR"
        export BASE_STATE="Auvergne-Rhône-Alpes"
        export BASE_LOCALITY="Villeurbanne"
        export BASE_ORG="Université Claude Bernard - Lyon 1"
        export BASE_OU="Département Informatique"
        export BASE_CN="Autorité de Certification (AC) (TIW4-CA)"
        export BASE_SAN="email:romuald.thion@univ-lyon1.fr"
        export CLIENT_SAN="IP:192.168.74.140,DNS:tiw4-authentication-12.tiw4.os.univ-lyon1.fr"
        export CLIENT_CN="tiw4-authentication-12.tiw4.os.univ-lyon1.fr"

    - openssl req -config ./tiw4-authentication/tiw4-ca/conf/client.conf -key key.pem -new -out ./server-csr-2.csr

* generation du certificat
    - openssl ca -config conf/tiw4-ca.conf -passin pass:"kn4uxJKRe4oRmjCHxa9gYmmjVgMHuXbU" -in ./server-csr-2.csr -extensions server_cert

### Firewall 
* https://restorebin.com/ufw-firewall-lemp/
