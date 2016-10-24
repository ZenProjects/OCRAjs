//  This an example implementation of OCRA.
//  RFC 6287 
//  based on ocra java reference implementation
//  from https://tools.ietf.org/html/rfc6287

// Convert a hex string to a byte array
function hexStr2Bytes(hex) {
    for (var bytes = [], c = 0; c < hex.length; c += 2)
    bytes.push(parseInt(hex.substr(c, 2), 16));
    return bytes;
}

// Convert a byte array to a hex string
function bytesToHexStr(bytes) {
    for (var hex = [], i = 0; i < bytes.length; i++) {
        hex.push((bytes[i] >>> 4).toString(16));
        hex.push((bytes[i] & 0xF).toString(16));
    }
    return hex.join("");
}

function ab2str(buf) {
  return String.fromCharCode.apply(null, new Uint16Array(buf));
}

function str2ab(str) {
  var buf = new ArrayBuffer(str.length*2); // 2 bytes for each char
  var bufView = new Uint16Array(buf);
  for (var i=0, strLen=str.length; i<strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

//from https://jswebcrypto.azurewebsites.net/demo.html#/hmac
function hmac_sha1(crypto, key, text)
{
    var hmacSha = {name: 'hmac', hash: {name: crypto}};
    var keyBuf = str2ab(key);
    var buf = str2ab(text);

    crypto.subtle.importKey("raw", keyBuf, hmacSha, true, ["sign", "verify"]).then(function(result) {
       crypto.subtle.sign(hmacSha, result, buf).then(function(result) {
	  var hash = arrayBufferToHexString(new Uint8Array(result));
          return hash;
       })
    });
    return null;
}

// 0 1 2 3 4 5 6 7 8
var DIGITS_POWER = [1,10,100,1000,10000,100000,1000000,10000000,100000000 ];

function generateOCRA(ocraSuite, key, counter, question, password, sessionInformation, timeStamp) {
          var codeDigits = 0;
          var crypto = "";
          var result = null;
          var ocraSuiteLength = ocraSuite.length;
          var counterLength = 0;
          var questionLength = 0;
          var passwordLength = 0;
          var sessionInformationLength = 0;
          var timeStampLength = 0;

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
              while(counter.length() < 16) 
                     counter = "0" + counter;
              counterLength=8;
	  }

          // Question - always 128 bytes
	  if(DataInput.toLowerCase().startsWith("q") ||
            (DataInput.toLowerCase().indexOf("-q") >= 0)) {
              while(question.length() < 256)
                  question = question + "0";
              questionLength=128;
          }


          // Password - sha1
          if(DataInput.toLowerCase().indexOf("psha1") > 1){
              while(password.length() < 40)
                  password = "0" + password;
              passwordLength=20;
          }

          // Password - sha256
          if(DataInput.toLowerCase().indexOf("psha256") > 1){
              while(password.length() < 64)
                  password = "0" + password;
              passwordLength=32;
          }

          // Password - sha512
          if(DataInput.toLowerCase().indexOf("psha512") > 1){
              while(password.length() < 128)
                  password = "0" + password;
              passwordLength=64;
          }

          // sessionInformation - s064
          if(DataInput.toLowerCase().indexOf("s064") > 1){
              while(sessionInformation.length() < 128)
                  sessionInformation = "0" + sessionInformation;
              sessionInformationLength=64;
          }

          // sessionInformation - s128
          if(DataInput.toLowerCase().indexOf("s128") > 1){
              while(sessionInformation.length() < 256)
                  sessionInformation = "0" + sessionInformation;
              sessionInformationLength=128;
          }

          // sessionInformation - s256
          if(DataInput.toLowerCase().indexOf("s256") > 1){
              while(sessionInformation.length() < 512)
                  sessionInformation = "0" + sessionInformation;
              sessionInformationLength=256;
          }

          // sessionInformation - s512
          if(DataInput.toLowerCase().indexOf("s512") > 1){
              while(sessionInformation.length() < 1024)
                  sessionInformation = "0" + sessionInformation;
              sessionInformationLength=512;
          }

          // TimeStamp
          if(DataInput.toLowerCase().startsWith("t") ||
                  (DataInput.toLowerCase().indexOf("-t") > 1)){
              while(timeStamp.length() < 16)
                  timeStamp = "0" + timeStamp;
              timeStampLength=8;
          }

	  // create a new array of Uint8Array with lenght of all zone
          // Remember to add "1" for the "00" byte delimiter
	  /*
          var msg = new Uint8Array(ocraSuiteLength +
                        counterLength +
                        questionLength +
                        passwordLength +
                        sessionInformationLength +
                        timeStampLength +
                        1);
	  */

          // Put the bytes of "ocraSuite" parameters into the message
          var bArray = str2ab(ocraSuite);
          //System.arraycopy(bArray, 0, msg, 0, bArray.length);
	  msg=bArray;

          // Delimiter
          msg[bArray.length] = 0x00;

          // Put the bytes of "Counter" to the message
          // Input is HEX encoded
          if(counterLength > 0 ){
              bArray = hexStr2Bytes(counter);
              //System.arraycopy(bArray, 0, msg, ocraSuiteLength + 1, bArray.length);
	      msg.concat(bArray);
          }


          // Put the bytes of "question" to the message
          // Input is text encoded
          if(questionLength > 0 ){
              bArray = hexStr2Bytes(question);
              //System.arraycopy(bArray, 0, msg, ocraSuiteLength + 1 + counterLength, bArray.length);
	      msg.concat(bArray);
          }

          // Put the bytes of "password" to the message
          // Input is HEX encoded
          if(passwordLength > 0){
              bArray = hexStr2Bytes(password);
              //System.arraycopy(bArray, 0, msg, ocraSuiteLength + 1 + counterLength +    questionLength, bArray.length);
	      msg.concat(bArray);

          }

          // Put the bytes of "sessionInformation" to the message
          // Input is text encoded
          if(sessionInformationLength > 0 ){
              bArray = hexStr2Bytes(sessionInformation);
              //System.arraycopy(bArray, 0, msg, ocraSuiteLength + 1 + counterLength +     questionLength + passwordLength, bArray.length);
	      msg.concat(bArray);
          }

          // Put the bytes of "time" to the message
          // Input is text value of minutes
          if(timeStampLength > 0){
              bArray = hexStr2Bytes(timeStamp);
              //System.arraycopy(bArray, 0, msg, ocraSuiteLength + 1 + counterLength + questionLength + passwordLength + sessionInformationLength, bArray.length);
	      msg.concat(bArray);
          }

          bArray = hexStr2Bytes(key);
          var hash = hmac_sha1(crypto, bArray, msg);

          // put selected bytes into result int
          var offset = hash[hash.length - 1] & 0xf;

          var binary =
              ((hash[offset] & 0x7f) << 24) |
              ((hash[offset + 1] & 0xff) << 16) |
              ((hash[offset + 2] & 0xff) << 8) |
              (hash[offset + 3] & 0xff);

          var otp = binary % DIGITS_POWER[codeDigits];

          result = otp.toString();
          while (result.length() < codeDigits) {
              result = "0" + result;
          }
          return result;
}
