
function println(hLog,msg)
{
  hLog.insertAdjacentText('beforeend',msg + "\n");
}

function dechex(number) {
  if (number < 0) {
    number = 0xFFFFFFFF + number + 1
  }
  return parseInt(number, 10)
    .toString(16)
}

function doOCRATest (hLog) {

      var ocra = "";
      var seed = "";
      var ocraSuite = "";
      var counter = "";
      var password = "";
      var sessionInformation = "";
      var question = "";
      var qHex = "";
      var timeStamp = "";

      // PASS1234 is SHA1 hash of "1234"
      var PASS1234 = "7110eda4d09e062aa5e4a390b0a572ac0d2c0220";

      var SEED   = "3132333435363738393031323334353637383930";
      var SEED32 = "3132333435363738393031323334353637383930313233343536373839303132";
      var SEED64 = "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334";
      var STOP = 5;

      var myDate = new Date();
      var b = 0; 
      var sDate = "Mar 25 2008, 12:06:30 GMT";

      myDate = Date.parse(sDate);
      b = Math.floor(myDate/60000);


      println(hLog,"Time of \"" + sDate + "\" is in");
      println(hLog,"milli sec: " + myDate);
      println(hLog,"minutes: " + b.toString());
      println(hLog,"minutes (HEX encoded): " + b.toString(16).toUpperCase());
      println(hLog,"Time of \"" + sDate + "\"... ");
      println(hLog," is the same as this localized time, \"" + new Date(myDate) + "\"");

      println(hLog,"");
      println(hLog,"Standard 20Byte key: "+SEED);
      println(hLog,"Standard 32Byte key: "+SEED32);
      println(hLog,"Standard 64Byte key: "+SEED64);

      println(hLog,"");
      println(hLog,"Plain challenge response");
      println(hLog,"========================");
      println(hLog,"");

      ocraSuite = "OCRA-1:HOTP-SHA1-6:QN08";
      println(hLog,ocraSuite);
      println(hLog,"=======================");
      seed = SEED;
      counter = "";
      question = "";
      password = "";
      sessionInformation = "";
      timeStamp = "";
      for(i=0; i < 10; i++){
	  question = "" + i + i + i + i + i + i + i + i;
	  qHex = dechex(question);
	  ocra = OCRA.generateOCRA(ocraSuite,
	                      seed,
			      counter,
			      qHex,
			      password,
			      sessionInformation,
			      timeStamp,
			      "sjcl");
	   println(hLog,"Key: Standard 20Byte  Q: " + question + "  OCRA: " + ocra);
      }
      println(hLog,"");

      ocraSuite = "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1";
      println(hLog,ocraSuite);
      println(hLog,"=================================");
      seed = SEED32;
      counter = "";
      question = "12345678";
      password = PASS1234;
      sessionInformation = "";
      timeStamp = "";
      for(i=0; i < 10; i++){
	  counter = "" + i;
	  qHex = dechex(question);
	  ocra = OCRA.generateOCRA(ocraSuite,
			      seed,
			      counter,
			      qHex,
			      password,
			      sessionInformation,
			      timeStamp);
	  println(hLog,"Key: Standard 32Byte  C: " + counter + "  Q: " + question + "  PIN(1234): ");
	  println(hLog,password + "  OCRA: " + ocra);
      }
      println(hLog,"");

      ocraSuite = "OCRA-1:HOTP-SHA256-8:QN08-PSHA1";
      println(hLog,ocraSuite);
      println(hLog,"===============================");
      seed = SEED32;
      counter = "";
      question = "";
      password = PASS1234;
      sessionInformation = "";
      timeStamp = "";
      for(i=0; i < STOP; i++){
	  question = "" + i + i + i + i + i + i + i + i;

	  qHex = dechex(question);
	  ocra = OCRA.generateOCRA(ocraSuite,
			      seed,
			      counter,
			      qHex,
			      password,
			      sessionInformation,
			      timeStamp);
	  println(hLog,"Key: Standard 32Byte  Q: " + question + "  PIN(1234): ");
	  println(hLog,password + "  OCRA: " + ocra);
      }
      println(hLog,"");

      ocraSuite = "OCRA-1:HOTP-SHA512-8:C-QN08";
      println(hLog,ocraSuite);
      println(hLog,"===========================");
      seed = SEED64;
      counter = "";
      question = "";
      password = "";
      sessionInformation = "";
      timeStamp = "";
      for(i=0; i < 10; i++){
	  question = "" + i + i + i + i + i + i + i + i;
	  qHex = dechex(question);
	  counter = "0000" + i;
	  ocra = OCRA.generateOCRA(ocraSuite,
	                      seed,
			      counter,
			      qHex,
			      password,
			      sessionInformation,
			      timeStamp);
	  println(hLog,"Key: Standard 64Byte  C: " + counter + "  Q: " + question + "  OCRA: " + ocra);
      }
      println(hLog,"");
      ocraSuite = "OCRA-1:HOTP-SHA512-8:QN08-T1M";
      println(hLog,ocraSuite);
      println(hLog,"=============================");
      seed = SEED64;
      counter = "";
      question = "";
      password = "";
      sessionInformation = "";
      timeStamp = b.toString(16);
      for(i=0; i < STOP; i++){
	  question = "" + i + i + i + i + i + i + i + i;
	  counter = "";
	  qHex = dechex(question);
	  ocra = OCRA.generateOCRA(ocraSuite,
	                      seed,
			      counter,
			      qHex,
			      password,
			      sessionInformation,
			      timeStamp);

	  println(hLog,"Key: Standard 64Byte  Q: " + question +"  T: " + timeStamp.toUpperCase() + "  OCRA: " + ocra);
      }
      println(hLog,"");

      println(hLog,"");
      println(hLog,"Mutual Challenge Response");
      println(hLog,"=========================");
      println(hLog,"");

      ocraSuite = "OCRA-1:HOTP-SHA256-8:QA08";
      println(hLog,"OCRASuite (server computation) = "
			 + ocraSuite);
      println(hLog,"OCRASuite (client computation) = "
			 + ocraSuite);
      println(hLog,"===============================" +
	  "===========================");
      seed = SEED32;
      counter = "";
      question = "";
      password = "";
      sessionInformation = "";
      timeStamp = "";
      for(i=0; i < STOP; i++){
	  question = "CLI2222" + i + "SRV1111" + i;
	  qHex = OCRA.bytesToHexStr(OCRA.str2ab(question));
	  ocra = OCRA.generateOCRA(ocraSuite,
	                      seed,
			      counter,
			      qHex,
			      password,
			      sessionInformation,
			      timeStamp);
	  println(hLog, "(server)Key: Standard 32Byte  Q: " + question + "  OCRA: " + ocra);
	  question = "SRV1111" + i + "CLI2222" + i;
	  qHex = OCRA.bytesToHexStr(OCRA.str2ab(question));
	  ocra = OCRA.generateOCRA(ocraSuite,
	                      seed,
			      counter,
			      qHex,
			      password,
			      sessionInformation,
			      timeStamp);
	  println(hLog, "(client)Key: Standard 32Byte  Q: " + question + "  OCRA: " + ocra);
      }
      println(hLog,"");

      var ocraSuite1 = "OCRA-1:HOTP-SHA512-8:QA08";
      var ocraSuite2 = "OCRA-1:HOTP-SHA512-8:QA08-PSHA1";
      println(hLog,"OCRASuite (server computation) = " + ocraSuite1);
      println(hLog,"OCRASuite (client computation) = " + ocraSuite2);
      println(hLog,"================================================================");
      ocraSuite = "";
      seed = SEED64;
      counter = "";
      question = "";
      password = "";
      sessionInformation = "";
      timeStamp = "";
      for(i=0; i < STOP; i++){
	  ocraSuite = ocraSuite1;
	  question = "CLI2222" + i + "SRV1111" + i;
	  qHex = OCRA.bytesToHexStr(OCRA.str2ab(question));
	  password = "";
	  ocra = OCRA.generateOCRA(ocraSuite,
	                      seed,
			      counter,
			      qHex,
			      password,
			      sessionInformation,
			      timeStamp);
	  println(hLog, "(server)Key: Standard 64Byte  Q: " + question + "  OCRA: " + ocra);
	  ocraSuite = ocraSuite2;
	  question = "SRV1111" + i + "CLI2222" + i;
	  qHex = OCRA.bytesToHexStr(OCRA.str2ab(question));
	  password = PASS1234;
	  ocra = OCRA.generateOCRA(ocraSuite,
	                      seed,
			      counter,
			      qHex,
			      password,
			      sessionInformation,
			      timeStamp);
	  println(hLog,"(client)Key: Standard 64Byte  Q: " + question);
	  println(hLog,"P: " + password.toUpperCase() + "  OCRA: " + ocra);
      }
      println(hLog,"");

      println(hLog,"");
      println(hLog,"Plain Signature");
      println(hLog,"===============");
      println(hLog,"");
      ocraSuite = "OCRA-1:HOTP-SHA256-8:QA08";
      println(hLog,ocraSuite);
      println(hLog,"=========================");
      seed = SEED32;
      counter = "";
      question = "";
      password = "";
      sessionInformation = "";
      timeStamp = "";
      for(i=0; i < STOP; i++){
	  question = "SIG1" + i + "000";
	  qHex = OCRA.bytesToHexStr(OCRA.str2ab(question));
	  ocra = OCRA.generateOCRA(ocraSuite,
	                      seed,
			      counter,
			      qHex,
			      password,
			      sessionInformation,
			      timeStamp);
	  println(hLog, "Key: Standard 32Byte  Q(Signature challenge): " + question);
	  println(hLog,"   OCRA: " + ocra);
      }
      println(hLog,"");

      ocraSuite = "OCRA-1:HOTP-SHA512-8:QA10-T1M";
      println(hLog,ocraSuite);
      println(hLog,"=============================");
      seed = SEED64;
      counter = "";
      question = "";
      password = "";
      sessionInformation = "";
      timeStamp = b.toString(16);
      for(i=0; i < STOP; i++){
	  question = "SIG1" + i + "00000";
	  qHex = OCRA.bytesToHexStr(OCRA.str2ab(question));
	  ocra = OCRA.generateOCRA(ocraSuite,
	                      seed,
			      counter,
			      qHex,
			      password,
			      sessionInformation,
			      timeStamp);
	  println(hLog, "Key: Standard 64Byte  Q(Signature challenge): " + question);
	  println(hLog,"   T: " + timeStamp.toUpperCase() + "  OCRA: " + ocra);
      }
}
