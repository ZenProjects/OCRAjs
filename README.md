# OCRAjs - OCRA: OATH Challenge-Response Algorithm implementation in Javascript 

This project contains example implementations of the OATH OCRA Challenge Response algorithm for Javascript based [RFC 6287](http://tools.ietf.org/html/rfc6287).

This implementation are based on the reference implementation from the official OCRA specification.

The current version of the OCRA standard can be found here:

http://tools.ietf.org/html/rfc6287

# Use

The ocra suite format are defined in [rfc 6287 at §6](https://tools.ietf.org/html/rfc6287#page-8)

```
var ocraSuite = "OCRA-1:HOTP-SHA1-6:QN08";
var SEED   = "3132333435363738393031323334353637383930";
var ocra = OCRA.generateOCRA( ocraSuite,          // ocra suite
                              seed,               // shared secret key
                              counter,            // ocra counter 
                              question,           // question in hex string format
                              password,           // password string hash
                              sessionInformation, // session information 
                              timeStamp);         // timestamp 
alert(ocra);  // ocra result
```

# Test Unit

This Javascript implementation are accompanied by a unit test that validates the implementation against the test vectors from the RFC.

Clic [her](https://zenprojects.github.io/OCRAjs/test-sjcl.html) to test with [SJCL HAMC-SHA engine](http://bitwiseshiftleft.github.io/sjcl/) to execute test.

Clic [her]( https://zenprojects.github.io/OCRAjs/test-jsSHA.html) to test with [jsSHA HAMC-SHA engine](https://caligatio.github.io/jsSHA/) to execute test.

And compare with [reference test vector](https://tools.ietf.org/html/rfc6287#page-34).
