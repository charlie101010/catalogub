# Welcome to My Linux Server configuration.  

### This provides web access to my Catalog application.  The details below include how you can access the project and also steps that were used in order to complete it.

IP address: `34.211.189.79`
The application uses SSH `Port 2200` if you have access to an SSH key.

You can visit the live application by going to:  `http://34.211.189.79/`

This application required the installing of the following sofware packages onto the server:

Git
Postgresql
Apache
WSGI

The python application required the following modules:

Flask
Pyscopg2
SQLAlchemy
Requests
Oauth2client

### In order to to configure the server, the following steps were required.

#### Setup the grader user.

1) Create the grader user `sudo adduser <username>`.
2) Login as a user with sudo permission and add the new user to `/etc/sudoers.d` file.
3) A note...we ca force the new user password to expire using `Sudo passwd -e <username>`
4) An SSH key should be generated for this user using the `ssh-keygen` command.  This should be done locally.
5) The filename for the keypair should be `/Users/<username on computer>/.ssh/<filename you want to use>`
6) This process will output 2 files.  The second file will be `/Users/<username on computer>/.ssh/<filename you want to use>.pub` which is what will be added to the server as the public key.
7) To install this public key, we login to the server as the new user and create a `.ssh` direction inside of which we place a `.ssh/authorized_keys` file.  Copy the text in the local `.pub` file from the pervious step into the `authorized_keys` file on the server.  Place one key per line (if multiple keys exist).
8) Now we must setup security on the `.ssh/authorized_keys` file so other users cannot tamper with it.  To do this, we can run `chmod 700 .ssh` and then `chmod 644 .ssh/authorized_keys`.
9) To disable password based authentication run `sudo nano /etc/ssh/sshd_config` and then inside of this file change "password authentication" from "yes" to "no".
10) Its very important to restart the server once this change is made because sshd_config only runs when the server is restarted.


#### Configure the firewall
1) Ubuntu comes with a firewall installed by default called "ufw".



