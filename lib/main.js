//for showing and hiding text in the Password box
function showPwd(){
	if(pwdBox.type == "password"){
		pwdBox.type = "text";
		showPwdMode.src = "images/hide-24.png"
	}else{
		pwdBox.type = "password";
		showPwdMode.src = "images/eye-24.png"
	}
	keyStrength(pwdBox.value,true)
}

//to display password strength
function pwdKeyup(evt){
	evt = evt || window.event;
	var key = evt.keyCode || evt.which || evt.keyChar;
	if(key == 13){acceptPwd()} else{
		 if(pwdBox.value){
			 keyStrength(pwdBox.value,true)
		 }else{
			 pwdMsg.textContent = "Please enter your Password"
		 }
	}
}

//makes 'pronounceable' hash of a string, so user can be sure the password was entered correctly
var vowel = 'aeiou',
	consonant = 'bcdfghjklmnprstvwxyz',
	hashiliTimer;
function hashili(msgID,string){
	var element = document.getElementById(msgID);
	clearTimeout(hashiliTimer);
	hashiliTimer = setTimeout(function(){
		if(!string.trim()){
			element.innerText += ''
		}else{
			var code = nacl.hash(nacl.util.decodeUTF8(string.trim())).slice(-2),			//take last 4 bytes of the SHA512		
				code10 = ((code[0]*256)+code[1]) % 10000,		//convert to decimal
				output = '';

			for(var i = 0; i < 2; i++){
				var remainder = code10 % 100;								//there are 5 vowels and 20 consonants; encode every 2 digits into a pair
				output += consonant[Math.floor(remainder / 5)] + vowel[remainder % 5];
				code10 = (code10 - remainder) / 100
			}
//	return output
			element.textContent += '\r\n' + output
		}
	}, 1000);						//one second delay to display hashili
}

//The rest is modified from WiseHash. https://github.com/fruiz500/whisehash
//function to test key strength and come up with appropriate key stretching. Based on WiseHash
function keyStrength(pwd,display) {
	if(pwd){
		var entropy = entropycalc(pwd);
	}else{
		document.getElementById('pwdMsg').textContent = 'Type your Password in the box';
		return
	}
	
	if(entropy == 0){
		var msg = 'This is a known bad password!';
		var colorName = 'magenta'
	}else if(entropy < 20){
		var msg = 'Terrible!';
		var colorName = 'magenta'
	}else if(entropy < 40){
		var msg = 'Weak!';
		var colorName = 'red'
	}else if(entropy < 60){
		var msg = 'Medium';
		var colorName = 'darkorange'
	}else if(entropy < 90){
		var msg = 'Good!';
		var colorName = 'green'
	}else if(entropy < 120){
		var msg = 'Great!';
		var colorName = 'blue'
	}else{
		var msg = 'Overkill  !';
		var colorName = 'cyan'
	}

	var iter = Math.max(1,Math.min(20,Math.ceil(24 - entropy/5)));			//set the scrypt iteration exponent based on entropy: 1 for entropy >= 120, 20(max) for entropy <= 20
	if(display){	
		msg = 'entropy ' + Math.round(entropy*100)/100 + ' bits. ' + msg;
	
		pwdMsg.textContent = msg;
		pwdMsg.style.color = colorName;
		hashili('pwdMsg',pwd)
	}
	return iter
}

//takes a string and calculates its entropy in bits, taking into account the kinds of characters used and parts that may be in the general wordlist (reduced credit) or the blacklist (no credit)
function entropycalc(pwd){

//find the raw Keyspace
	var numberRegex = new RegExp("^(?=.*[0-9]).*$", "g");
	var smallRegex = new RegExp("^(?=.*[a-z]).*$", "g");
	var capRegex = new RegExp("^(?=.*[A-Z]).*$", "g");
	var base64Regex = new RegExp("^(?=.*[/+]).*$", "g");
	var otherRegex = new RegExp("^(?=.*[^a-zA-Z0-9/+]).*$", "g");

	pwd = pwd.replace(/\s/g,'');										//no credit for spaces

	var Ncount = 0;
	if(numberRegex.test(pwd)){
		Ncount = Ncount + 10;
	}
	if(smallRegex.test(pwd)){
		Ncount = Ncount + 26;
	}
	if(capRegex.test(pwd)){
		Ncount = Ncount + 26;
	}
	if(base64Regex.test(pwd)){
		Ncount = Ncount + 2;
	}
	if(otherRegex.test(pwd)){
		Ncount = Ncount + 31;											//assume only printable characters
	}

//start by finding words that might be on the blacklist (no credit)
	var pwd = reduceVariants(pwd);
	var wordsFound = pwd.match(blackListExp);							//array containing words found on the blacklist
	if(wordsFound){
		for(var i = 0; i < wordsFound.length;i++){
			pwd = pwd.replace(wordsFound[i],'');						//remove them from the string
		}
	}

//now look for regular words on the wordlist
	wordsFound = pwd.match(wordListExp);									//array containing words found on the regular wordlist
	if(wordsFound){
		wordsFound = wordsFound.filter(function(elem, pos, self) {return self.indexOf(elem) == pos;});	//remove duplicates from the list
		var foundLength = wordsFound.length;							//to give credit for words found we need to count how many
		for(var i = 0; i < wordsFound.length;i++){
			pwd = pwd.replace(new RegExp(wordsFound[i], "g"),'');									//remove all instances
		}
	}else{
		var foundLength = 0;
	}

	pwd = pwd.replace(/(.+?)\1+/g,'$1');								//no credit for repeated consecutive character groups

	if(pwd != ''){
		return (pwd.length*Math.log(Ncount) + foundLength*Math.log(wordLength + blackLength))/Math.LN2
	}else{
		return (foundLength*Math.log(wordLength + blackLength))/Math.LN2
	}
}

//take into account common substitutions, ignore spaces and case
function reduceVariants(string){
	return string.toLowerCase().replace(/[óòöôõo]/g,'0').replace(/[!íìïîi]/g,'1').replace(/[z]/g,'2').replace(/[éèëêe]/g,'3').replace(/[@áàäâãa]/g,'4').replace(/[$s]/g,'5').replace(/[t]/g,'7').replace(/[b]/g,'8').replace(/[g]/g,'9').replace(/[úùüû]/g,'u');
}

//stretches a password string with a salt string to make a 256-bit Uint8Array Key
function wiseHash(pwd,salt){
	var iter = keyStrength(pwd,false),
		secArray = new Uint8Array(32),
		keyBytes;

	scrypt(pwd,salt,iter,8,32,0,function(x){keyBytes=x;});		//does a variable number of rounds of scrypt, using nacl libraries

	for(var i=0;i<32;i++){
			secArray[i] = keyBytes[i]
	}
	return secArray
}

const lockListFileName = 'GroupKeys.txt';							//file containing public keys

//global variables used for key box expiration
var keytimer = 0,
    keytime = new Date().getTime();

//these derive from the Key after running through scrypt stretching.
var myKey,			//uint256 bit array
	myLock,			//uint256 bit array
	fileOutBin;

//If the timer has run out the Password is deleted from its box, and stretched keys are deleted from memory
function refreshKey(){
	clearTimeout(keytimer);
	var period = 300000;

//start timer to erase Key
	keytimer = setTimeout(function() {
		resetKeys();
	}, period);

	keytime = new Date().getTime();

//now check that the binary Key is still there, and return false if not
	if (!myKey){
		pwdMsg.textContent = 'Please enter your secret Key and press Accept';
		fileMsg.textContent = 'Please enter your secret Key and press Accept';
		return false
	}
	return true
}

//resets the Keys in memory when the timer ticks off
function resetKeys(){
	myKey = '';
	myLock = '';
	pwdBox.value = '';
	fileInBin = '';
	fileOutBin = '';
	fileIn.disabled = true;
	fileMsg.textContent = 'Enter your Password first';
	pwdMsg.style.color = 'red';
	pwdMsg.textContent = 'Password forgotten due to inactivity. Please enter it again'
}
//executed when user presses Accept button; creates uint8 secret arrays, displays Lock, and starts timer to delete said arrays
function acceptPwd(){
	var key = pwdBox.value.trim();
    if(key == ''){
        pwdMsg.textContent = 'Please enter your Password';
        return
    }
    if(key.length < 4){
        pwdMsg.textContent = 'This Password is too short!';
        return
    }

	pwdMsg.textContent = '';
    var blinker = document.createElement('span'),
        msgText = document.createElement('span');
    blinker.className = "blink";
    blinker.textContent = "LOADING...";
    msgText.textContent = " for best speed, use at least a Medium strength Password";
    pwdMsg.appendChild(blinker);
    pwdMsg.appendChild(msgText);

	//now make the binary secret Key from the password
	setTimeout(function(){
		myKey = wiseHash(key,GroupName);									//global variable GroupName is used as salt
		myLock = makePub(myKey);											//matching public key
		var myEzLock = changeBase(nacl.util.encodeBase64(myLock).replace(/=+$/,''), base64, base36);	//for display as text; easy to dictate
		while(myEzLock.length < 50) myEzLock = 'a' + myEzLock;											//prepend zeroes to reach max length
		textBox.textContent = myEzLock;
		if(lockIndex(myLock,locks,32) == -1){										//check for active user status; use all bytes
			pwdMsg.style.color = 'red';
			pwdMsg.textContent = 'This Password is not listed for any active user but its public key is shown below';
			showPublicCheck.checked = true;
			publicKeyArea.style.display='block';
			return
		}
		pwdMsg.style.color = '';
		pwdMsg.textContent = 'Password accepted; public key displayed in bottom box';
		pwdBox.value = '';																		//all done, so empty the password box
		fileIn.disabled = false;
		fileMsg.textContent = 'Click this button to load the file, or drag the file onto it';
		refreshKey()					//start timer to erase secret keys
	},10)								//short delay to allow blinking message to load
}

//to display public keys as text
const base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
	base36 = "abcdefghijkLmnopqrstuvwxyz0123456789";

//from http://snippetrepo.com/snippets/bignum-base-conversion, by kybernetikos
function changeBase(number, inAlpha, outAlpha) {
	var targetBase = outAlpha.length,
		originalBase = inAlpha.length;
    var result = "";
    while (number.length > 0) {
        var remainingToConvert = "", resultDigit = 0;
        for (var position = 0; position < number.length; ++position) {
            var idx = inAlpha.indexOf(number[position]);
            if (idx < 0) {
                throw new Error('Symbol ' + number[position] + ' from the'
                    + ' original number ' + number + ' was not found in the'
                    + ' alphabet ' + inAlpha);
            }
            var currentValue = idx + resultDigit * originalBase;
            var remainDigit = Math.floor(currentValue / targetBase);
            resultDigit = currentValue % targetBase;
            if (remainingToConvert.length || remainDigit) {
                remainingToConvert += inAlpha[remainDigit];
            }
        }
        number = remainingToConvert;
        result = outAlpha[resultDigit] + result;
    }
    return result;
}

//loads the input file into memory
function loadFile(){
	var fileToLoad = fileIn.files[0],
		fileReader = new FileReader();
	fileReader.onload = function(fileLoadedEvent){
		var fileName = fileToLoad.name;
		window.fileInBin = new Uint8Array(fileLoadedEvent.target.result);			//using byte arrays; makes global variable fileInBin
		fileMsg.textContent = 'File loaded. Size: '+ fileInBin.length + ' bytes';
		var isEncrypted = true;														//check that the file begins with the encrypt marker
		for(var i = 0; i < headTag.length; i++){
			if(fileInBin[i] != headTag[i]){
				isEncrypted = false;
				break
			}
		}
		if(isEncrypted){fileOutBox.value = fileName.slice(0,-6); decrypt()}else{fileOutBox.value = fileName + '.crypt'; encrypt()}	//call encryption or decryption depanding on how the file starts
    };
    if(fileToLoad) fileReader.readAsArrayBuffer(fileToLoad)
}

//checks that a certain array is present in a certain array of arrays, up to a certain length
function lockIndex(lock,array,legth2check){
	for(var i = 0; i < array.length; i++){
		var isThisLock = true;
		for(var j = 0; j < legth2check; j++){
			isThisLock = isThisLock && (lock[j] == array[i][j])			//check first few elements; return false if even one does not match
		}
		if(isThisLock) return i											//return index in array if found
	}
	return -1														  //lock not found
}

//crypto functions; similar to Signed mode in PassLok, except that 8 bytes of sender's public key are added in order to identify this user
function encrypt(){
	if(!fileInBin) return;
	if(!refreshKey()) return;			//check that the Key is active and stop if not
	if(locks.length <= 0) return;

	startBlink(true);

setTimeout(function(){										//delay to allow blinker to start
	var recipients = new Uint8Array([locks.length]);		//byte after header will be the number of recipients; array of length 1
	locks = shuffle(locks);									//so encrypted keys are not always in the same order

	var	msgKey = nacl.randomBytes(32),	//message key for symmetric encryption
		nonce = nacl.randomBytes(24);	//nonce so each encryption is unique; 24 bytes

	fileOutBin = concatUi8([headTag,recipients,nonce,myLock.slice(0,8)]);	//global output starts with header, No. of recipients, 24-byte nonce, first 8 bytes of sender's public Key			
	
	var cipher = symEncrypt(fileInBin,nonce,msgKey);					//main encryption event, but don't add the result yet

	//for each public key, encrypt the message key and add it, prefaced by the first 8 bytes of the ciphertext obtained when the item is encrypted with the message nonce and the shared key. Notice: same nonce, but different key for each item (unless someone planted two recipients who have the same key, but then the encrypted result will also be identical).
	for (index = 0; index < locks.length; index++){
		var sharedKey = makeShared(locks[index],myKey),								//use encrypter's private key: signed mode
			cipher2 = nacl.secretbox(msgKey,nonce,sharedKey);						//message Key encrypted for each recipient

		var	idTag = nacl.secretbox(locks[index],nonce,sharedKey).slice(0,8);		//8 bytes of each public key, encrypted; this precedes each encrypted message Key

		fileOutBin = concatUi8([fileOutBin,idTag,cipher2]);
	}
	//all recipients done at this point; finish off by adding the encrypted message

	fileOutBin = concatUi8([fileOutBin,cipher]);
	fileMsg.style.color = 'green';
	if(showOutNameCheck.checked){
		fileMsg.textContent = 'Encryption successful. Edit filename if needed and save it with the button';
		pwdMsg.textContent = 'Encryption successful. Edit filename if needed and save it with the button'
	}else{
		fileMsg.textContent = 'Encryption successful. File saved to Downloads';
		pwdMsg.textContent = 'Encryption successful. File saved to Downloads';
		saveFileOut()							//download automatically if the Save button is not showing
	}

},20)
}

function decrypt(){
	if(!fileInBin) return;
	if(!refreshKey()) return;			//check that the Key is active and stop if not
	if(locks.length <= 0) return;

	startBlink(false);
	
setTimeout(function(){
	var	recipients = fileInBin[headTag.length],								//number of recipients. '0' reserved for special cases
		cipherArray = new Array(recipients),
		stuffForId = myLock,
		isLegacy = false;

	var nonce = fileInBin.slice(headTag.length+1,headTag.length+25),		//24 bytes
		lockID = fileInBin.slice(headTag.length+25,headTag.length+33),		//first 8 bytes of sender's public key
		cipherInput = fileInBin.slice(headTag.length+33);					//rest of it; contains IDtags + encrypted message keys, and encrypted file

	var index = lockIndex(lockID,locks,8);									//find whose public key was used to encrypt

	if(index == -1){														//not found; try finding it in legacy array
		index = lockIndex(lockID,legacyLocks,8);
		if(index == -1){													//still not found: display message and bail out; it won't decrypt anyway
			fileMsg.style.color = 'red';
			fileMsg.textContent = 'File encrypted by unknown user';
			return
		}else{
			isLegacy = true													//set flag to look in legacy arrays from now on
		}
	}

	//cut the rest into pieces; first the ID tags with their encrypted keys, then the encrypted file	
	for(var i = 0; i < recipients; i++){
		cipherArray[i] = cipherInput.slice(56*i,56*(i+1))					//8 bytes for ID tag, 48 for encrypted key
	}
	var cipher = cipherInput.slice(56*recipients);							//file after symmetric encryption; key yet to be extracted

	if(isLegacy){
		var	sharedKey = makeShared(legacyLocks[index],myKey)
	}else{
		var	sharedKey = makeShared(locks[index],myKey)
	}
	
	var	idKey = sharedKey;

	var idTag = nacl.secretbox(stuffForId,nonce,idKey).slice(0,8);			//this will be found right before the message key encrypted for me
	
	//look for my ID tag and return the bytes that follow it
	for(i = 0; i < recipients; i++){
		var success = true;
		for(var j = 0; j < 8; j++){										//just the first 8 bytes
			success = success && (idTag[j] == cipherArray[i][j])		//find the idTag bytes at the start of cipherArray[i]
		}
		if(success){
			var msgKeycipher = cipherArray[i].slice(8);
			break
		}
	}

	if(!success){														//ID tag not found; display error and bail out
		fileMsg.style.color = 'red';
		fileMsg.textContent = 'This file is not encrypted for you';
		return
	}

	var msgKey = nacl.secretbox.open(msgKeycipher,nonce,sharedKey);		//decrypt the message key
	if(!msgKey){
		fileMsg.style.color = 'red';
		fileMsg.textContent = 'Decryption has failed';
		fileOutBin = '';
		return
	}

	fileOutBin = symDecrypt(cipher,nonce,msgKey);						//decrypt the main message; false if error

	if(!fileOutBin){
		fileMsg.style.color = 'red';
		fileMsg.textContent = 'Decryption has failed';
		fileOutBin = ''
	}else{
		if(isLegacy){
			var sender = 'former user ' + legacyUsers[index]
		}else{
			var sender = users[index]
		}
		fileMsg.style.color = 'green';									//success!
		if(showOutNameCheck.checked){
			fileMsg.textContent = 'Decryption successful. Edit file name if needed and save it with the button. Last encrypted by ' + sender
		}else{
			fileMsg.textContent = 'Decryption successful. File saved to Downloads. Last encrypted by ' + sender;
			saveFileOut()							//download automatically if the Save button is not showing
		}
	}

},20)						//delay to allow blinker to start
}

//makes the DH public string of a DH secret key array. Returns a Uint8 array
function makePub(sec){
	return pub = nacl.box.keyPair.fromSecretKey(sec).publicKey
}

//Diffie-Hellman combination of a DH public key array and a DH secret key array. Returns Uint8Array
function makeShared(pub,sec){
	return nacl.box.before(pub,sec)
}

//encrypt string with a symmetric Key, returns a uint8 array
function symEncrypt(plainBin,nonce,symKey){
	return nacl.secretbox(plainBin,nonce,symKey)
}

//decrypt uint8 array with a symmetric Key
function symDecrypt(cipherBin,nonce,symKey){
	var	plainBin = nacl.secretbox.open(cipherBin,nonce,symKey);				//decryption instruction
	if(!plainBin) return false;												//to display error message
	return plainBin
}

//just to shuffle randomly an array; no pretensions of crypto strength
function shuffle(a) {
    var j, x, i;
    for (i = a.length; i; i -= 1) {
        j = Math.floor(Math.random() * i);
        x = a[i - 1];
        a[i - 1] = a[j];
        a[j] = x
    }
	return a
}

//to concatenate a few Uint8Arrays fed as an array
function concatUi8(arrays) {
	var totalLength = 0;
	for(var i = 0; i < arrays.length; i++) totalLength += arrays[i].length;
	
	var result = new Uint8Array(totalLength);
  
	var length = 0;
	for(var i = 0; i < arrays.length; i++) {
	  result.set(arrays[i], length);
	  length += arrays[i].length;
	}
	return result
}

//to start the blinker during encryption or decryption
function startBlink(isEncrypt){
	fileMsg.textContent = '';
    var blinker = document.createElement('span');
    blinker.className = "blink";
    if(isEncrypt){blinker.textContent = "ENCRYPTING..."}else{blinker.textContent = "DECRYPTING..."};
    fileMsg.appendChild(blinker)
}

//to save the output file to Downloads
function saveFileOut(){
	if(fileOutBin) downloadBlob(fileOutBin, fileOutBox.value, 'application/octet-stream')
}

//from StackOverflow, to download Uint8Array data as file. Usage: downloadBlob(myBinaryBlob, 'some-file.bin', 'application/octet-stream');
var downloadBlob, downloadURL;

downloadBlob = function(data, fileName, mimeType) {
  var blob, url;
  blob = new Blob([data], {
    type: mimeType
  });
  url = window.URL.createObjectURL(blob);
  downloadURL(url, fileName);
  setTimeout(function() {
    return window.URL.revokeObjectURL(url);
  }, 1000);
};

downloadURL = function(data, fileName) {
  var a;
  a = document.createElement('a');
  a.href = data;
  a.download = fileName;
  document.body.appendChild(a);
  a.style = 'display: none';
  a.click();
  a.remove();
};

var locks = [], users = [];					//locks contains public keys for intended recipients in uint8 format, users contains the matching names
var legacyLocks = [], legacyUsers = [];		//public keys of former users still in database; their names

//recognize pure base36 and length is 50: ezLock
function isLock(string){
	return !string.match(/[^a-kLm-z0-9]/) && (string.length == 50)
}

//grab the names in GroupKeys.js and put them in the selection box
function fillList(){
	var headingColor = '639789';
	groupList.textContent = '';
	var fragment = document.createDocumentFragment(),
		opt2 = document.createElement("option");
	opt2.disabled = true;
	opt2.selected = true;
	opt2.textContent = "Select users (ctrl-click for several)";
	fragment.appendChild(opt2);

	for(var name in GroupKeys){
		if(name.charAt(0) != '$'){							//not a legacy user
			var opt = document.createElement("option");
			opt.value = name;
			opt.textContent = name;
			fragment.appendChild(opt);
			if(isLock(GroupKeys[name])){					//make array just with public keys in Uint8 format
				var lock64 = changeBase(GroupKeys[name].trim().replace(/l/g,'L'),base36,base64);		//make capital 'L' in case it was smallcase
				while (lock64.length < 43) lock64 = 'A' + lock64;										//prepend zeros to get correct length
				locks.push(nacl.util.decodeBase64(lock64));
				users.push(name)
			}
		}else{												//legacy user: do not list, but add public key to legacyLocks array
			if(isLock(GroupKeys[name])){
				var lock64 = changeBase(GroupKeys[name].trim().replace(/l/g,'L'),base36,base64);		//make capital 'L' in case it was smallcase
				while (lock64.length < 43) lock64 = 'A' + lock64;										//prepend zeros to get correct length
				legacyLocks.push(nacl.util.decodeBase64(lock64));
				legacyUsers.push(name.slice(1,name.length))
			}
		}
	}
	groupList.style.color = '#' + headingColor;
	groupList.appendChild(fragment);
	groupList.options[0].selected = false;
	users = users.sort();							//alphabetical order
	userList.textContent = users.join(', ')
}

//deselect all entries on selection box
function deselectList(){
	for (var i = 1; i < groupList.options.length; i++) {
        groupList.options[i].selected = false
      }
}

//updates recipient lists from entries selected in the selection element
function updateUsers(){
	var list = [];
	users = [];				//reset users and locks lists
	locks = [];

	//make first list of selected names, some of which may be lists
	for(var i = 1; i < groupList.options.length; i++){		//skip header entry
    	if(groupList.options[i].selected){
			list.push(groupList.options[i].value)
		}
	}

	if(list.length == 0){									//if no selection, add all single names
		for(var name in GroupKeys){
			if(name.charAt(0) != '$'){						//only active users
				if(isLock(GroupKeys[name])){
					users.push(name)
				}
			}
		}
	}else{
		//convert the entries that are themselves lists into individual names
		for(var i = 0; i < list.length; i++){
			if(isLock(GroupKeys[list[i]])){						//single member, add the name to users list
				users.push(list[i])	
			}else{
				users = users.concat(GroupKeys[list[i]].split(', '))		//list, so add all the names
			}
		}
		users = users.filter(onlyUnique);						//remove duplicates
	}

	for(var i = 0; i < users.length; i++){					//remove names that are not in database; length will change
		if(!GroupKeys[users[i]]) users.splice(i,1)
	}
	
	users = users.sort();									//alphabetize

	for(var i = 0; i < users.length; i++){					//fill locks array
			locks.push(nacl.util.decodeBase64(changeBase(GroupKeys[users[i]],base36,base64)))
	}

	userList.textContent = users.join(', ')
}

//to remove duplicates in an array
function onlyUnique(value, index, self) {
	return self.indexOf(value) === index;
}

//add event listeners and some processing of users in GroupKeys.js
window.onload = function() {
	groupNameBox.textContent = GroupName;
	fillList();
	acceptBtn.addEventListener('click', acceptPwd);
	showPwdMode.addEventListener('click', showPwd);
	technical.addEventListener('click', function(){window.open('technical.html')});
	pwdBox.addEventListener('keyup', pwdKeyup, false);
	groupList.addEventListener('change',updateUsers);
	fileIn.addEventListener('change',loadFile);
	saveBtn.addEventListener('click', saveFileOut);
	showPublicCheck.addEventListener('click', function(){
		if(showPublicCheck.checked){publicKeyArea.style.display='block'}else{publicKeyArea.style.display=''}
	})
	showOutNameCheck.addEventListener('click', function(){
		if(showOutNameCheck.checked){outNameArea.style.display='block'}else{outNameArea.style.display=''}
	})
	showListCheck.addEventListener('click', function(){
		if(showListCheck.checked){
			selectArea.style.display='block'
		}else{
			selectArea.style.display='';
			deselectList();
			updateUsers()
		}
	})
}
