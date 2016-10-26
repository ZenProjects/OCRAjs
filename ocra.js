/*
 * This an implementation of OCRA - OATH Challenge-Response Algorithm 
 * based on ocra java reference implementation
 * from https://tools.ietf.org/html/rfc6287
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

// https://su12147fct0:12002/ocrajs/index.html

function HmacWeb()
{

  this.result = null;

   // convert String to Uint8 ArrayBuffer View
   this.convertStringToArrayBufferView = function(str)
   {
     if (typeof str === 'string' || str instanceof String)
     {
       var bytes = new Uint8Array(str.length);
       for (var iii = 0; iii < str.length; iii++) 
       {
	   bytes[iii] = str.charCodeAt(iii);
       }

       return bytes;
     }
     else
       return str;
   };


  this.setResult = function(result)
  {
    this.result = new Uint8Array(result);
  }

  this.setError = function(err)
  {
    this.error=err;
  }


  // hmac_hash with Web Cryptography API
  // https://www.w3.org/TR/WebCryptoAPI/
  //
  // this api are supported on chrome 49+, firefox 47+, edge, and ms prefix old version on ie11
  // http://caniuse.com/#feat=cryptography 
  //
  // based on sample from https://jswebcrypto.azurewebsites.net/demo.html#/hmac
  // and http://qnimate.com/digital-signature-using-web-cryptography-api/
  this.hmac_hash = function(hashAlgo, hashKey, hashText) 
  {
    var hmacSha = {name: 'HMAC', hash: {name: hashAlgo}};

    if (typeof hashKey === 'string' || hashKey instanceof String)
      var hmacKeyBuf = this.convertStringToArrayBufferView(hashKey);
    else
      var hmacKeyBuf = hashKey;

    if (typeof hashText === 'string' || hashText instanceof String)
      var hmacTextBuf = this.convertStringToArrayBufferView(hashText);
    else
      var hmacTextBuf = hashText;

    var promise = null;
    var _this = this; 

    var hmacresult = {};
    var crypto = window.crypto || window.msCrypto;

    hash = crypto.subtle.importKey("raw", hmacKeyBuf, hmacSha, true, ["sign", "verify"])
    .then(function(myCryptoKey) {
       crypto.subtle.sign(hmacSha, myCryptoKey, hmacKeyBuf)
       .then(function(result){
	  _this.result = new Uint8Array(result);
       })
       .catch(function(err){
	 alert(err);
       });
    }).catch(function(err){
	 alert(err);
    });
    return this.result;
  }
}

var OCRA = {

   // Convert a hex string to a byte array
   hexStr2Bytes : function(hex) 
   {
       for (var bytes = [], c = 0; c < hex.length; c += 2)
       bytes.push(parseInt(hex.substr(c, 2), 16));
       return bytes;
   },

   // Convert a byte array to a hex string
   bytesToHexStr : function(bytes) 
   {
       for (var hex = [], i = 0; i < bytes.length; i++) {
	   hex.push((bytes[i] >>> 4).toString(16));
	   hex.push((bytes[i] & 0xF).toString(16));
       }
       return hex.join("");
   },

   // convert ArrayBuffer to String
   ab2str : function (buf) 
   {
     return String.fromCharCode.apply(null, new Uint8Array(buf));
   },

   // convert String to Uint8 ArrayBuffer View
   convertStringToArrayBufferView : function(str)
   {
     if (typeof str === 'string' || str instanceof String)
     {
       var bytes = new Uint8Array(str.length);
       for (var iii = 0; iii < str.length; iii++) 
       {
	   bytes[iii] = str.charCodeAt(iii);
       }

       return bytes;
     }
     else
       return str;
   },

   // convert String to ArrayBuffer 
   str2ab : function(str) {
     if (typeof str === 'string' || str instanceof String)
     {
     var buf = new ArrayBuffer(str.length); 
     var bufView = new Uint8Array(buf);
     for (var i=0, strLen=str.length; i<strLen; i++) {
       bufView[i] = str.charCodeAt(i);
     }
     return bufView;
     }
     else
        return null;
   },

   // append ArrayBuffer to existing ArrayBuffer
   ArrayConcat : function(buffer1, buffer2) 
   {
      var tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
      tmp.set(new Uint8Array(buffer1), 0);
      tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
      return tmp.buffer;
   },

   // hmac_hash with Web Cryptography API
   // https://www.w3.org/TR/WebCryptoAPI/
   //
   // this api are supported on chrome 49+, firefox 47+, edge, and ms prefix old version on ie11
   // http://caniuse.com/#feat=cryptography 
   //
   // based on sample from https://jswebcrypto.azurewebsites.net/demo.html#/hmac
   // and http://qnimate.com/digital-signature-using-web-cryptography-api/
   hmacWeb_hash : function(hashAlgo, hashKey, hashText)
   {
        var hmacweb = new HmacWeb();
        var hmacresult= hmacweb.hmac_hash(hashAlgo,hashKey,hashText);
        return hmacresult.result;
   },

   hmac_hash : function(hashAlgo, hashKey, hashText)
   {
    if (typeof hashKey === 'string' || hashKey instanceof String)
      var hmacKeyBuf = this.convertStringToArrayBufferView(hashKey);
    else
      var hmacKeyBuf = hashKey;

    if (typeof hashText === 'string' || hashText instanceof String)
      var hmacTextBuf = this.convertStringToArrayBufferView(hashText);
    else
      var hmacTextBuf = hashText;


      var shaObj = new jsSHA(hashAlgo, "ARRAYBUFFER");
      shaObj.setHMACKey(hmacKeyBuf, "ARRAYBUFFER");
      shaObj.update(hmacTextBuf);
      return shaObj.getHMAC("ARRAYBUFFER");
   },

   // OCRA method
   generateOCRA : function(ocraSuite, key, counter, question, password, sessionInformation, timeStamp) 
   {
       var codeDigits = 0;
       var crypto = "";
       var result = null;
       var ocraSuiteLength = ocraSuite.length;
       var counterLength = 0;
       var questionLength = 0;
       var passwordLength = 0;
       var sessionInformationLength = 0;
       var timeStampLength = 0;
       // OCRA size modulo : 0 1 2 3 4 5 6 7 8
       var DIGITS_POWER = [1,10,100,1000,10000,100000,1000000,10000000,100000000];


       // The OCRASuites components
       var CryptoFunction = ocraSuite.split(":")[1];
       var DataInput = ocraSuite.split(":")[2];

       if(CryptoFunction.toLowerCase().indexOf("sha1") > 1)
	   crypto = "SHA-1";
       if(CryptoFunction.toLowerCase().indexOf("sha256") > 1)
	   crypto = "SHA-256";
       if(CryptoFunction.toLowerCase().indexOf("sha384") > 1)  // not supported by rfc
	   crypto = "SHA-384";
       if(CryptoFunction.toLowerCase().indexOf("sha512") > 1)
	   crypto = "SHA-512";

       // How many digits should we return
       codeDigits = parseInt(CryptoFunction.substring(
	       CryptoFunction.lastIndexOf("-")+1));

       // The size of the byte array message to be encrypted
       // Counter
       if(DataInput.toLowerCase().startsWith("c")) {
	   // Fix the length of the HEX string
	   while(counter.length < 16) 
		  counter = "0" + counter;
	   counterLength=8;
       }

       // Question - always 128 bytes
       if(DataInput.toLowerCase().startsWith("q") ||
	 (DataInput.toLowerCase().indexOf("-q") >= 0)) {
	   while(question.length < 256)
	       question = question + "0";
	   questionLength=128;
       }


       // Password - sha1
       if(DataInput.toLowerCase().indexOf("psha1") > 1){
	   while(password.length < 40)
	       password = "0" + password;
	   passwordLength=20;
       }

       // Password - sha256
       if(DataInput.toLowerCase().indexOf("psha256") > 1){
	   while(password.length < 64)
	       password = "0" + password;
	   passwordLength=32;
       }

       // Password - sha512
       if(DataInput.toLowerCase().indexOf("psha512") > 1){
	   while(password.length < 128)
	       password = "0" + password;
	   passwordLength=64;
       }

       // sessionInformation - s064
       if(DataInput.toLowerCase().indexOf("s064") > 1){
	   while(sessionInformation.length < 128)
	       sessionInformation = "0" + sessionInformation;
	   sessionInformationLength=64;
       }

       // sessionInformation - s128
       if(DataInput.toLowerCase().indexOf("s128") > 1){
	   while(sessionInformation.length < 256)
	       sessionInformation = "0" + sessionInformation;
	   sessionInformationLength=128;
       }

       // sessionInformation - s256
       if(DataInput.toLowerCase().indexOf("s256") > 1){
	   while(sessionInformation.length < 512)
	       sessionInformation = "0" + sessionInformation;
	   sessionInformationLength=256;
       }

       // sessionInformation - s512
       if(DataInput.toLowerCase().indexOf("s512") > 1){
	   while(sessionInformation.length < 1024)
	       sessionInformation = "0" + sessionInformation;
	   sessionInformationLength=512;
       }

       // TimeStamp
       if(DataInput.toLowerCase().startsWith("t") ||
	       (DataInput.toLowerCase().indexOf("-t") > 1)){
	   while(timeStamp.length < 16)
	       timeStamp = "0" + timeStamp;
	   timeStampLength=8;
       }

       // create a new array of Uint8Array with lenght of all zone
       // Remember to add "1" for the "00" byte delimiter
       var msgArrayBuffer = new ArrayBuffer(ocraSuiteLength +
		     counterLength +
		     questionLength +
		     passwordLength +
		     sessionInformationLength +
		     timeStampLength +
		     1);

       // creat view of ab
       var msg = new Uint8Array(msgArrayBuffer);

       for(var i=0;i<msg.byteLength;i++) msg[i]=0x00;

       // Put the bytes of "ocraSuite" parameters into the message
       var bArray = this.str2ab(ocraSuite);

       //System.arraycopy(bArray, 0, msg, 0, bArray.length);
       msg.set(bArray,0);

       // Delimiter
       msg[bArray.length] = 0x00;


       // Put the bytes of "Counter" to the message
       // Input is HEX encoded
       if(counterLength > 0 ){
	   bArray = this.hexStr2Bytes(counter);
	   //System.arraycopy(bArray, 0, msg, ocraSuiteLength + 1, bArray.length);
	   //msg.set(bArray,ocraSuiteLength + 1);
	   for (var i=0;i<bArray.length;i++) 
	      msg [i + ocraSuiteLength + 1] = bArray[i];
       }

       // Put the bytes of "question" to the message
       // Input is text encoded
       if(questionLength > 0 ){
	   bArray = this.hexStr2Bytes(question);
	   //System.arraycopy(bArray, 0, msg, ocraSuiteLength + 1 + counterLength, bArray.length);
	   //msg.set(bArray,ocraSuiteLength + 1 + counterLength);
	   for (var i=0;i<bArray.length;i++) 
	      msg [i + ocraSuiteLength + 1 + counterLength] = bArray[i];
       }

       // Put the bytes of "password" to the message
       // Input is HEX encoded
       if(passwordLength > 0){
	   bArray = this.hexStr2Bytes(password);
	   //System.arraycopy(bArray, 0, msg, ocraSuiteLength + 1 + counterLength +    questionLength, bArray.length);
	   //msg.set(bArray,ocraSuiteLength + 1 + counterLength + questionLength);
	   for (var i=0;i<bArray.length;i++) 
	      msg [i + ocraSuiteLength + 1 + counterLength + questionLength] = bArray[i];
       }

       // Put the bytes of "sessionInformation" to the message
       // Input is text encoded
       if(sessionInformationLength > 0 ){
	   bArray = this.hexStr2Bytes(sessionInformation);
	   //System.arraycopy(bArray, 0, msg, ocraSuiteLength + 1 + counterLength +     questionLength + passwordLength, bArray.length);
	   //msg.set(bArray,ocraSuiteLength + 1 + counterLength + questionLength + passwordLength);
	   for (var i=0;i<bArray.length;i++) 
	      msg [i + ocraSuiteLength + 1 + counterLength + questionLength + passwordLength] = bArray[i];
       }

       // Put the bytes of "time" to the message
       // Input is text value of minutes
       if(timeStampLength > 0){
	   bArray = this.hexStr2Bytes(timeStamp);
	   //System.arraycopy(bArray, 0, msg, ocraSuiteLength + 1 + counterLength + questionLength + passwordLength + sessionInformationLength, bArray.length);
	   //msg.set(bArray,ocraSuiteLength + 1 + counterLength + questionLength + passwordLength + sessionInformationLength);
	   for (var i=0;i<bArray.length;i++) 
	      msg [i + ocraSuiteLength + 1 + counterLength + questionLength + passwordLength + sessionInformationLength] = bArray[i];
       }

       bArray = this.hexStr2Bytes(key);
       var abKey = new Uint8Array(bArray);
       var msgstr = this.ab2str(msg);
       var hash = this.hmac_hash(crypto, abKey, msg);
       if (hash==null) return null;

       // put selected bytes into result int
       var offset = hash[hash.byteLength - 1] & 0xf;

       var binary =
	   ((hash[offset + 0] & 0x7f) << 24) |
	   ((hash[offset + 1] & 0xff) << 16) |
	   ((hash[offset + 2] & 0xff) << 8) |
	    (hash[offset + 3] & 0xff);

       var otp = binary % DIGITS_POWER[codeDigits];

       result = otp.toString();
       while (result.length < codeDigits) {
	   result = "0" + result;
       }
       return result;
   }
}
