/**
 * Javascript Implementation Tests based on Java version included (Appendix B and C) in the RFC 6287.
 * https://datatracker.ietf.org/doc/html/rfc6287.
 *
 * The original java code are Licenced with this therm:
 *
 * Copyright (c) 2011 IETF Trust and the persons identified as
 * authors of the code. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, is permitted pursuant to, and subject to the license
 * terms contained in, the Simplified BSD License set forth in Section
 * 4.c of the IETF Trust's Legal Provisions Relating to IETF Documents
 * (http://trustee.ietf.org/license-info).
 *
 */

/**
 * Test OCRA vectors generation
 *
 * Based on Java reference implementation (RFC 6287 Appendix B & C)
 * @author Johan Rydell, PortWise (original Java)
 * @author Mathieu CARBONNEAUX (Javascript Port)
 */

class TestOCRA {

    // Helper function for conditional debug
    static debugLog(...args) {
        if (typeof window !== 'undefined' && window.debugMode) {
            console.log(...args);
        }
    }

    static asHex(buf) {
        const strbuf = [];
        let i;
        for (i = 0; i < buf.length; i++) {
            if ((buf[i] & 0xff) < 0x10)
                strbuf.push("0");
            strbuf.push((buf[i] & 0xff).toString(16));
        }
        return strbuf.join("");
    }

    /**
     * Main test execution
     */
    static async main() {
        let ocra = "";
        let seed = "";
        let ocraSuite = "";
        let counter = "";
        let password = "";
        let sessionInformation = "";
        let question = "";
        let qHex = "";
        let timeStamp = "";

        // PASS1234 is SHA1 hash of "1234"
        const PASS1234 = "7110eda4d09e062aa5e4a390b0a572ac0d2c0220";
        const SEED = "3132333435363738393031323334353637383930";
        const SEED32 = "31323334353637383930313233343536373839" +
            "30313233343536373839303132";
        const SEED64 = "31323334353637383930313233343536373839" +
            "3031323334353637383930313233343536373839" +
            "3031323334353637383930313233343536373839" +
            "3031323334";

        const STOP = 5;
        let myDate = new Date();
        let b = BigInt(0);
        const sDate = "Mar 25 2008, 12:06:30 GMT";

        try {
            myDate = new Date(sDate);  // parse sDate
            b = BigInt(myDate.getTime());  // getTime return Milliseconds since Jan 1, 1970, 00:00:00.000 GMT
            b = b / BigInt(60000);  // divise en minute

            console.log("Time of \"" + sDate + "\" is in");
            console.log("milli sec: " + myDate.getTime());
            console.log("minutes: " + b.toString());
            console.log("minutes (HEX encoded): " + b.toString(16).toUpperCase());
            console.log("Time of \"" + sDate + "\" is the same as this localized");
            console.log("time, \"" + new Date(myDate.getTime()) + "\"");
            console.log();

            // Debug of keys used
            this.debugLog("=== DEBUG TestOCRA Keys ===");
            this.debugLog("SEED length:", SEED.length);
            this.debugLog("SEED32 length:", SEED32.length);
            this.debugLog("SEED64 length:", SEED64.length);
            this.debugLog("SEED64:", SEED64);
            this.debugLog("=== END DEBUG Keys ===");

            console.log("Standard 20Byte key: " + "3132333435363738393031323334353637383930");
            console.log("Standard 32Byte key: " + "3132333435363738393031323334353637383930");
            console.log("                     " + "313233343536373839303132");
            console.log("Standard 64Byte key: 313233343536373839" + "3031323334353637383930");
            console.log("                     313233343536373839" + "3031323334353637383930");
            console.log("                     313233343536373839" + "3031323334353637383930");
            console.log("                     31323334");
            console.log();

            console.log("Plain challenge response");
            console.log("========================");
            console.log();

            ocraSuite = "OCRA-1:HOTP-SHA1-6:QN08";
            console.log(ocraSuite);
            console.log("=======================");
            seed = SEED;
            counter = "";
            question = "";
            password = "";
            sessionInformation = "";
            timeStamp = "";

            for (let i = 0; i < 10; i++) {
                question = "" + i + i + i + i + i + i + i + i;
                qHex = BigInt(question).toString(16).toUpperCase();
                this.debugLog("Test SHA1", i, "- Question:", question, "qHex:", qHex);
                ocra = await OCRA.generateOCRA(ocraSuite, seed, counter,
                    qHex, password, sessionInformation, timeStamp);
                console.log("Key: Standard 20Byte Q: " + question + " OCRA: " + ocra);
            }
            console.log();

            ocraSuite = "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1";
            console.log(ocraSuite);
            console.log("=================================");
            seed = SEED32;
            counter = "";
            question = "12345678";
            password = PASS1234;
            sessionInformation = "";
            timeStamp = "";

            for (let i = 0; i < 10; i++) {
                counter = "" + i;
                qHex = BigInt(question).toString(16).toUpperCase();
                this.debugLog("Test SHA256+C", i, "- Counter:", counter, "Question:", question, "qHex:", qHex);
                ocra = await OCRA.generateOCRA(ocraSuite, seed, counter,
                    qHex, password, sessionInformation, timeStamp);
                console.log("Key: Standard 32Byte C: " + counter + " Q: " + question + " PIN(1234): ");
                console.log(password + " OCRA: " + ocra);
            }
            console.log();

            ocraSuite = "OCRA-1:HOTP-SHA256-8:QN08-PSHA1";
            console.log(ocraSuite);
            console.log("===============================");
            seed = SEED32;
            counter = "";
            question = "";
            password = PASS1234;
            sessionInformation = "";
            timeStamp = "";

            for (let i = 0; i < STOP; i++) {
                question = "" + i + i + i + i + i + i + i + i;
                qHex = BigInt(question).toString(16).toUpperCase();
                this.debugLog("Test SHA256+Q", i, "- Question:", question, "qHex:", qHex);
                ocra = await OCRA.generateOCRA(ocraSuite, seed, counter,
                    qHex, password, sessionInformation, timeStamp);
                console.log("Key: Standard 32Byte Q: " + question + " PIN(1234): ");
                console.log(password + " OCRA: " + ocra);
            }
            console.log();

            ocraSuite = "OCRA-1:HOTP-SHA512-8:C-QN08";
            console.log(ocraSuite);
            console.log("===========================");
            seed = SEED64;
            counter = "";
            question = "";
            password = "";
            sessionInformation = "";
            timeStamp = "";

            this.debugLog("=== Starting SHA512 C+Q tests ===");
            this.debugLog("SEED64 used:", seed);
            this.debugLog("SEED64 length:", seed.length);

            for (let i = 0; i < 10; i++) {
                question = "" + i + i + i + i + i + i + i + i;
                qHex = BigInt(question).toString(16).toUpperCase();
                counter = "0000" + i;
                this.debugLog("Test SHA512+C", i, "- Counter:", counter, "Question:", question, "qHex:", qHex);
                ocra = await OCRA.generateOCRA(ocraSuite, seed, counter,
                    qHex, password, sessionInformation, timeStamp);
                console.log("Key: Standard 64Byte C: " + counter + " Q: " + question + " OCRA: " + ocra);
            }
            console.log();

            ocraSuite = "OCRA-1:HOTP-SHA512-8:QN08-T1M";
            console.log(ocraSuite);
            console.log("=============================");
            seed = SEED64;
            counter = "";
            question = "";
            password = "";
            sessionInformation = "";
            timeStamp = b.toString(16);

            this.debugLog("=== Starting SHA512 Q+T1M tests ===");
            this.debugLog("Timestamp used:", timeStamp);

            for (let i = 0; i < STOP; i++) {
                question = "" + i + i + i + i + i + i + i + i;
                counter = "";
                qHex = BigInt(question).toString(16).toUpperCase();
                this.debugLog("Test SHA512+T1M", i, "- Question:", question, "qHex:", qHex, "Timestamp:", timeStamp);
                ocra = await OCRA.generateOCRA(ocraSuite, seed, counter,
                    qHex, password, sessionInformation, timeStamp);
                console.log("Key: Standard 64Byte Q: " + question + " T: " + timeStamp.toUpperCase() + " OCRA: " + ocra);
            }
            console.log();
            console.log();

            console.log("Mutual Challenge Response");
            console.log("=========================");
            console.log();

            ocraSuite = "OCRA-1:HOTP-SHA256-8:QA08";
            console.log("OCRASuite (server computation) = " + ocraSuite);
            console.log("OCRASuite (client computation) = " + ocraSuite);
            console.log("===============================" + "===========================");
            seed = SEED32;
            counter = "";
            question = "";
            password = "";
            sessionInformation = "";
            timeStamp = "";

            for (let i = 0; i < STOP; i++) {
                question = "CLI2222" + i + "SRV1111" + i;
                qHex = this.asHex(new TextEncoder().encode(question));
                this.debugLog("Mutual test", i, "- Server Question:", question, "qHex:", qHex);
                ocra = await OCRA.generateOCRA(ocraSuite, seed, counter, qHex,
                    password, sessionInformation, timeStamp);
                console.log("(server)Key: Standard 32Byte Q: " + question + " OCRA: " + ocra);

                question = "SRV1111" + i + "CLI2222" + i;
                qHex = this.asHex(new TextEncoder().encode(question));
                this.debugLog("Mutual test", i, "- Client Question:", question, "qHex:", qHex);
                ocra = await OCRA.generateOCRA(ocraSuite, seed, counter, qHex,
                    password, sessionInformation, timeStamp);
                console.log("(client)Key: Standard 32Byte Q: " + question + " OCRA: " + ocra);
            }
            console.log();

            const ocraSuite1 = "OCRA-1:HOTP-SHA512-8:QA08";
            const ocraSuite2 = "OCRA-1:HOTP-SHA512-8:QA08-PSHA1";
            console.log("OCRASuite (server computation) = " + ocraSuite1);
            console.log("OCRASuite (client computation) = " + ocraSuite2);
            console.log("===============================" + "=================================");
            ocraSuite = "";
            seed = SEED64;
            counter = "";
            question = "";
            password = "";
            sessionInformation = "";
            timeStamp = "";

            for (let i = 0; i < STOP; i++) {
                ocraSuite = ocraSuite1;
                question = "CLI2222" + i + "SRV1111" + i;
                qHex = this.asHex(new TextEncoder().encode(question));
                password = "";
                this.debugLog("Mutual SHA512 test", i, "- Server Question:", question, "qHex:", qHex);
                ocra = await OCRA.generateOCRA(ocraSuite, seed, counter, qHex,
                    password, sessionInformation, timeStamp);
                console.log("(server)Key: Standard 64Byte Q: " + question + " OCRA: " + ocra);

                ocraSuite = ocraSuite2;
                question = "SRV1111" + i + "CLI2222" + i;
                qHex = this.asHex(new TextEncoder().encode(question));
                password = PASS1234;
                this.debugLog("Mutual SHA512 test", i, "- Client Question:", question, "qHex:", qHex, "Password:", password);
                ocra = await OCRA.generateOCRA(ocraSuite, seed, counter, qHex,
                    password, sessionInformation, timeStamp);
                console.log("(client)Key: Standard 64Byte Q: " + question);
                console.log("P: " + password.toUpperCase() + " OCRA: " + ocra);
            }
            console.log();
            console.log();

            console.log("Plain Signature");
            console.log("===============");
            console.log();

            ocraSuite = "OCRA-1:HOTP-SHA256-8:QA08";
            console.log(ocraSuite);
            console.log("=========================");
            seed = SEED32;
            counter = "";
            question = "";
            password = "";
            sessionInformation = "";
            timeStamp = "";

            for (let i = 0; i < STOP; i++) {
                question = "SIG1" + i + "000";
                qHex = this.asHex(new TextEncoder().encode(question));
                this.debugLog("Signature test", i, "- Question:", question, "qHex:", qHex);
                ocra = await OCRA.generateOCRA(ocraSuite, seed, counter, qHex,
                    password, sessionInformation, timeStamp);
                console.log("Key: Standard 32Byte Q(Signature challenge): " + question);
                console.log(" OCRA: " + ocra);
            }
            console.log();

            ocraSuite = "OCRA-1:HOTP-SHA512-8:QA10-T1M";
            console.log(ocraSuite);
            console.log("=============================");
            seed = SEED64;
            counter = "";
            question = "";
            password = "";
            sessionInformation = "";
            timeStamp = b.toString(16);

            for (let i = 0; i < STOP; i++) {
                question = "SIG1" + i + "00000";
                qHex = this.asHex(new TextEncoder().encode(question));
                this.debugLog("Signature SHA512+T1M test", i, "- Question:", question, "qHex:", qHex, "Timestamp:", timeStamp);
                ocra = await OCRA.generateOCRA(ocraSuite, seed, counter,
                    qHex, password, sessionInformation, timeStamp);
                console.log("Key: Standard 64Byte Q(Signature challenge): " + question);
                console.log(" T: " + timeStamp.toUpperCase() + " OCRA: " + ocra);
            }

        } catch (e) {
            console.log("Error : " + e);
        }
    }
}

/**
 * Test vectors extracted from RFC 6287 Appendix C
 * Exact values as specified in the RFC
 */
const RFC_TEST_VECTORS = {
    // Standard keys from RFC
    SEED: "3132333435363738393031323334353637383930",
    SEED32: "3132333435363738393031323334353637383930313233343536373839303132",
    SEED64: "3132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334",
    PASS1234: "7110eda4d09e062aa5e4a390b0a572ac0d2c0220",

    // One-Way Challenge Response test vectors
    oneWayChallengeResponse: [
        {
            suite: "OCRA-1:HOTP-SHA1-6:QN08",
            key: "3132333435363738393031323334353637383930",
            tests: [
                { Q: "00000000", expected: "237653" },
                { Q: "11111111", expected: "243178" },
                { Q: "22222222", expected: "653583" },
                { Q: "33333333", expected: "740991" },
                { Q: "44444444", expected: "608993" },
                { Q: "55555555", expected: "388898" },
                { Q: "66666666", expected: "816933" },
                { Q: "77777777", expected: "224598" },
                { Q: "88888888", expected: "750600" },
                { Q: "99999999", expected: "294470" }
            ]
        },
        {
            suite: "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1",
            key: "3132333435363738393031323334353637383930313233343536373839303132",
            tests: [
                { C: "0", Q: "12345678", expected: "65347737" },
                { C: "1", Q: "12345678", expected: "86775851" },
                { C: "2", Q: "12345678", expected: "78192410" },
                { C: "3", Q: "12345678", expected: "71565254" },
                { C: "4", Q: "12345678", expected: "10104329" },
                { C: "5", Q: "12345678", expected: "65983500" },
                { C: "6", Q: "12345678", expected: "70069104" },
                { C: "7", Q: "12345678", expected: "91771096" },
                { C: "8", Q: "12345678", expected: "75011558" },
                { C: "9", Q: "12345678", expected: "08522129" }
            ]
        },
        {
            suite: "OCRA-1:HOTP-SHA256-8:QN08-PSHA1",
            key: "3132333435363738393031323334353637383930313233343536373839303132",
            tests: [
                { Q: "00000000", expected: "83238735" },
                { Q: "11111111", expected: "01501458" },
                { Q: "22222222", expected: "17957585" },
                { Q: "33333333", expected: "86776967" },
                { Q: "44444444", expected: "86807031" }
            ]
        },
        {
            suite: "OCRA-1:HOTP-SHA512-8:C-QN08",
            key: "3132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334",
            tests: [
                { C: "00000", Q: "00000000", expected: "07016083" },
                { C: "00001", Q: "11111111", expected: "63947962" },
                { C: "00002", Q: "22222222", expected: "70123924" },
                { C: "00003", Q: "33333333", expected: "25341727" },
                { C: "00004", Q: "44444444", expected: "33203315" },
                { C: "00005", Q: "55555555", expected: "34205738" },
                { C: "00006", Q: "66666666", expected: "44343969" },
                { C: "00007", Q: "77777777", expected: "51946085" },
                { C: "00008", Q: "88888888", expected: "20403879" },
                { C: "00009", Q: "99999999", expected: "31409299" }
            ]
        },
        {
            suite: "OCRA-1:HOTP-SHA512-8:QN08-T1M",
            key: "3132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334",
            tests: [
                { Q: "00000000", T: "132d0b6", expected: "95209754" },
                { Q: "11111111", T: "132d0b6", expected: "55907591" },
                { Q: "22222222", T: "132d0b6", expected: "22048402" },
                { Q: "33333333", T: "132d0b6", expected: "24218844" },
                { Q: "44444444", T: "132d0b6", expected: "36209546" }
            ]
        }
    ],

    // Mutual Challenge-Response test vectors
    mutualChallengeResponse: [
        {
            serverSuite: "OCRA-1:HOTP-SHA256-8:QA08",
            clientSuite: "OCRA-1:HOTP-SHA256-8:QA08",
            key: "3132333435363738393031323334353637383930313233343536373839303132",
            tests: [
                { serverQ: "CLI22220SRV11110", clientQ: "SRV11110CLI22220", serverExpected: "28247970", clientExpected: "15510767" },
                { serverQ: "CLI22221SRV11111", clientQ: "SRV11111CLI22221", serverExpected: "01984843", clientExpected: "90175646" },
                { serverQ: "CLI22222SRV11112", clientQ: "SRV11112CLI22222", serverExpected: "65387857", clientExpected: "33777207" },
                { serverQ: "CLI22223SRV11113", clientQ: "SRV11113CLI22223", serverExpected: "03351211", clientExpected: "95285278" },
                { serverQ: "CLI22224SRV11114", clientQ: "SRV11114CLI22224", serverExpected: "83412541", clientExpected: "28934924" }
            ]
        },
        {
            serverSuite: "OCRA-1:HOTP-SHA512-8:QA08",
            clientSuite: "OCRA-1:HOTP-SHA512-8:QA08-PSHA1",
            key: "3132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334",
            tests: [
                { serverQ: "CLI22220SRV11110", clientQ: "SRV11110CLI22220", clientP: "1234", serverExpected: "79496648", clientExpected: "18806276" },
                { serverQ: "CLI22221SRV11111", clientQ: "SRV11111CLI22221", clientP: "1234", serverExpected: "76831980", clientExpected: "70020315" },
                { serverQ: "CLI22222SRV11112", clientQ: "SRV11112CLI22222", clientP: "1234", serverExpected: "12250499", clientExpected: "01600026" },
                { serverQ: "CLI22223SRV11113", clientQ: "SRV11113CLI22223", clientP: "1234", serverExpected: "90856481", clientExpected: "18951020" },
                { serverQ: "CLI22224SRV11114", clientQ: "SRV11114CLI22224", clientP: "1234", serverExpected: "12761449", clientExpected: "32528969" }
            ]
        }
    ],

    // Plain Signature test vectors
    plainSignature: [
        {
            suite: "OCRA-1:HOTP-SHA256-8:QA08",
            key: "3132333435363738393031323334353637383930313233343536373839303132",
            tests: [
                { Q: "SIG10000", expected: "53095496" },
                { Q: "SIG11000", expected: "04110475" },
                { Q: "SIG12000", expected: "31331128" },
                { Q: "SIG13000", expected: "76028668" },
                { Q: "SIG14000", expected: "46554205" }
            ]
        },
        {
            suite: "OCRA-1:HOTP-SHA512-8:QA10-T1M",
            key: "3132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334",
            tests: [
                { Q: "SIG1000000", T: "132d0b6", expected: "77537423" },
                { Q: "SIG1100000", T: "132d0b6", expected: "31970405" },
                { Q: "SIG1200000", T: "132d0b6", expected: "10235557" },
                { Q: "SIG1300000", T: "132d0b6", expected: "95213541" },
                { Q: "SIG1400000", T: "132d0b6", expected: "65360607" }
            ]
        }
    ]
};

// Export for use in module (if supported)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { TestOCRA, RFC_TEST_VECTORS };
}

// Export for use globally in browser
if (typeof window !== 'undefined') {
    window.TestOCRA = TestOCRA;
    window.RFC_TEST_VECTORS = RFC_TEST_VECTORS;
}