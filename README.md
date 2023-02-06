# GroupEncrypt
Encrypts/decrypts files for a group of users

This standalone webapp, which can also run from file, is based on NaCl ans SCRYPT. It uses the following open-source code from GitHub, included in the /lib-opensrc folder:

Tweet NaCl crypto library by Dmitry Chestnykh, v1.0.3. https://github.com/dchest/tweetnacl-js

scrypt-async-js KDF by Dmitry Chestnykh, v2.0.1. https://github.com/dchest/scrypt-async-js

User access to the encrypted output is controlled by the file GroupKeys.js, which must be edited for each particular implementation. This file, which should reside in the same folder as the index.html (or whatever name you gave it) that loads the app, contains the public keys of all the users in the group, up to a maximum of 255 users, plus optional lists of users. Example:

const GroupKeys = {

Alice:
"jxibnf9gpdpttf1acu3gamob4kt9ys8swd8ug2xaiLz2u7uqhq"
,

Bob:
"oretLgajwccwb63iLdg0rneviL2tv507tr4h3rjwsom72k6rL6"
,

Carol:

"tjbo7otm9pyj3xuqewLygfcx985ssbsa26wtr1dn79xb40ftsy"
,

$Girls:
"Alice, Carol"

};

This means that, during the app rollout period, each one of the users must load the app and enter a unique Password in the top box. This displays his/her public key in the box below it, which then he/she copies and sends to the system administrator by the most convenient means. They can be dictated over the phone. One recommended method is for the administrator to change the contents of this file before it is sent to the other users so it contains only the public key matching a temporary password that the administrator does not intend to use after deployment. This way group members can write their respective public keys in a text file and encrypt it with the app itself so only the administrator can decrypt it. These encrypted files can be placed in shared storage.

The administrator then composes the permanent GroupKeys.js file with any text editor, giving each user an identifying name, followed by a colon, and then his/her public key within quotes. Some entries can contain a list of user names instead. There must be a comma between entries, but spaces and carriage returns don't affect the result. Then the administrator uploads the file to the server (best if encrypted with the app) or distributes it to the users if they are going to run the app from file. Each user then replaces the new GroupKeys.js file in place of the old one. The app can be loaded from a web server just as easily, in which case the administrator simply replaces this file at the server.

When encryption of a file takes place, the input file is encrypted so that each one of the selected users (default: all on the list) can decrypt the output file, and nobody else. This involves first doing symmetric encryption of the file with a random 32-byte "message key", plus a random 24-byte nonce. Then the message key is encrypted asymmetrically using each user's public key, obtained from the GroupKeys.js file, and the result is added to the encrypted file. Decryption by a particular user involves finding that user's encryted message key in the encrypted file, decrypting it with his/her private key, which derives from his/her Password, and finally using the message key to decrypt the main file content.

The GroupKeys.js file also contains an entry for the unique header that encrypted files begin with, and which the app uses to determine whether or not a file loaded onto it has been previously encrypted by the app. This entry is an array of numbers 0 to 255 representing bytes. The only important thing is that none of the files to be encrypted should begin with this sequence of bytes. The more bytes, the smaller the likelihood that this will happen. Example:

const headTag = new Uint8Array([27,27,27,27,27,27,27])

GroupEncrypt is based on the elliptic curve public key cryptography algorithms of the NaCl suite, which also includes XSalsa20 for symmetric encryption, plus the SCRYPT key derivation algorithm. Key length is 256 bits. The user-supplied Password is analyzed for strength, and the parameters of the SCRYPT algorithm are varied so that weaker Passwords are subjected to more rounds of key stretching. We call this the WiseHash algorithm, which makes the keyspace quite resistant to dictionary attack, since attackers are penalized for including weak Passwords in their search, or otherwise risk missing them. The encryption algorithm is similar to the Anonymous mode in PassLok, also by F. Ruiz, except that it uses no extra data such as user email, and there is no padding that might contain a secret message. Files encrypted by this app cannot be decrypted in PassLok, and vice-versa.

Processing is done by the browser's built-in JavaScript engine, which makes the app very fast and cross-browser compatible. It can run on mobile devices as well. Files up to 1 GB in size can be handled, subject to memory availability. In this implementation, the data is input and output as local files, but it is easy to modify the code so the data is exchanged with a server instead. The format for the file data is uint8 arrays, each element containing one binary byte. The name of the input file data is fileInBin, that of the output data is fileOutBin.
