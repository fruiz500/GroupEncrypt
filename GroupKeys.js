//Group name, which gets used to salt the user Passwords
const GroupName = "Sample Group";

//this object contains user names and their public keys; make sure there are commas between entries; public keys within quotes
const GroupKeys = {

Alice:
"it0oh6L44k2fnb4793kekbkanet8kdkfu9y5541kpojb3mk5om"
,

Bob:
"acnkhinpurLgcjgcuLk1gwtn3zLyy68ystissirxumtxm4ctw6"
,

Carol:
"r9t28eq9xa0L35wx66pngko0zao7p3r8kr3ahtjnw74aar3fgu"
,

$Adam:                                                  //former user; kept so that files encrypted by this user can still be decrypted
"wv6ndfmn8ntifp6k4xbncs3vjf8rxi8g7f9czfsab78vuyyxsa"
,

"==Girls==":
"Alice, Carol"


};

//Code added at the start of encrypted files, so they can be recognized
const headTag1 = new Uint8Array([27,27,27,27,27,27,27]);                  //File mode; no need to change this, but it can be done
const headTag2 = new Uint8Array([27,27,27,27,27,27,81])                   //Folder mode