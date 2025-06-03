/**
 * Javascript Implementation based on Java version included (Appendix A) in the RFC 6287.
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
 * This an Javascript implementation of OCRA.
 * Visit www.openauthentication.org for more information.
 *
 * Based on Java reference implementation (RFC 6287 Appendix A)
 * @author Johan Rydell, PortWise (original Java)
 * @author Mathieu CARBONNEAUX (Javascript Port)
 */


class OCRA {

    constructor() {
        // Private constructor equivalent
        throw new Error("OCRA cannot be instantiated");
    }

    // Helper function for conditional debug
    static debugLog(...args) {
        if (typeof window !== 'undefined' && window.debugMode) {
            console.log(...args);
        }
    }

    /**
     * Detect available crypto libraries and return priority order
     */
    static detectCryptoLibraries() {
        const available = [];

        // Check Web Crypto API
        if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
            available.push('webcrypto');
        }

        // Check CryptoJS
        if (typeof CryptoJS !== 'undefined') {
            available.push('cryptojs');
        }

        // Check jsSHA
        if (typeof jsSHA !== 'undefined') {
            available.push('jssha');
        }

        return available;
    }

    /**
     * HMAC calculation using Web Crypto API
     */
    static async hmacWebCrypto(hashAlgo, keyBytes, text) {
        try {
            const cryptoKey = await window.crypto.subtle.importKey(
                'raw',
                keyBytes,
                { name: 'HMAC', hash: hashAlgo },
                false,
                ['sign']
            );

            const signature = await window.crypto.subtle.sign('HMAC', cryptoKey, text);
            return new Uint8Array(signature);
        } catch (e) {
            console.error("Web Crypto API HMAC Error:", e);
            throw e;
        }
    }

    /**
     * HMAC calculation using CryptoJS
     */
    static async hmacCryptoJS(crypto, keyBytes, text) {
        try {
            // Convert Uint8Array to CryptoJS WordArray
            const keyHex = Array.from(keyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
            const textHex = Array.from(text).map(b => b.toString(16).padStart(2, '0')).join('');

            const key = CryptoJS.enc.Hex.parse(keyHex);
            const message = CryptoJS.enc.Hex.parse(textHex);

            let hash;
            if (crypto === "HmacSHA1") {
                hash = CryptoJS.HmacSHA1(message, key);
            } else if (crypto === "HmacSHA256") {
                hash = CryptoJS.HmacSHA256(message, key);
            } else if (crypto === "HmacSHA512") {
                hash = CryptoJS.HmacSHA512(message, key);
            } else {
                throw new Error("Unsupported crypto algorithm for CryptoJS: " + crypto);
            }

            // Convert WordArray back to Uint8Array
            const hashHex = hash.toString(CryptoJS.enc.Hex);
            const result = new Uint8Array(hashHex.length / 2);
            for (let i = 0; i < hashHex.length; i += 2) {
                result[i / 2] = parseInt(hashHex.substr(i, 2), 16);
            }

            return result;
        } catch (e) {
            console.error("CryptoJS HMAC Error:", e);
            throw e;
        }
    }

    /**
     * HMAC calculation using jsSHA
     */
    static async hmacJsSHA(crypto, keyBytes, text) {
        try {
            let variant;
            if (crypto === "HmacSHA1") {
                variant = "SHA-1";
            } else if (crypto === "HmacSHA256") {
                variant = "SHA-256";
            } else if (crypto === "HmacSHA512") {
                variant = "SHA-512";
            } else {
                throw new Error("Unsupported crypto algorithm for jsSHA: " + crypto);
            }

            const shaObj = new jsSHA(variant, "UINT8ARRAY");
            shaObj.setHMACKey(keyBytes, "UINT8ARRAY");
            shaObj.update(text);

            const hash = shaObj.getHMAC("UINT8ARRAY");
            return new Uint8Array(hash);
        } catch (e) {
            console.error("jsSHA HMAC Error:", e);
            throw e;
        }
    }

    /**
     * Multi-crypto HMAC function with automatic fallback
     * Supports Web Crypto API, CryptoJS, and jsSHA
     *
     * @param crypto the crypto algorithm (HmacSHA1, HmacSHA256, HmacSHA512)
     * @param keyBytes the bytes to use for the HMAC key
     * @param text the message or text to be authenticated.
     */
    static async hmac_sha1(crypto, keyBytes, text) {
        const availableLibs = this.detectCryptoLibraries();

        if (availableLibs.length === 0) {
            throw new Error("No crypto library available! Please include Web Crypto API, CryptoJS, or jsSHA");
        }

        this.debugLog(`Available crypto libraries: ${availableLibs.join(', ')}`);


        // Debug for SHA512
        if (crypto === "HmacSHA512") {
            this.debugLog("DEBUG SHA512 - keyBytes length:", keyBytes.length);
            this.debugLog("DEBUG SHA512 - text length:", text.length);
            this.debugLog("DEBUG SHA512 - keyBytes:", Array.from(keyBytes.slice(0, 10)).map(b => b.toString(16).padStart(2, '0')).join(''));
            this.debugLog("DEBUG SHA512 - using library:", availableLibs[0]);
        }

        let result;
        let lastError;

        // Try each available library in priority order
        for (const lib of availableLibs) {
            try {
                if (lib === 'webcrypto') {
                    let hashAlgo;
                    if (crypto === "HmacSHA1") {
                        hashAlgo = "SHA-1";
                    } else if (crypto === "HmacSHA256") {
                        hashAlgo = "SHA-256";
                    } else if (crypto === "HmacSHA512") {
                        hashAlgo = "SHA-512";
                    } else {
                        throw new Error("Unsupported crypto algorithm: " + crypto);
                    }
                    this.debugLog(`Using ${lib} for ${crypto}`);
                    result = await this.hmacWebCrypto(hashAlgo, keyBytes, text);
                    break;
                } else if (lib === 'cryptojs') {
                    this.debugLog(`Using ${lib} for ${crypto}`);
                    result = await this.hmacCryptoJS(crypto, keyBytes, text);
                    break;
                } else if (lib === 'jssha') {
                    this.debugLog(`Using ${lib} for ${crypto}`);
                    result = await this.hmacJsSHA(crypto, keyBytes, text);
                    break;
                }
            } catch (e) {
                console.warn(`${lib} failed for ${crypto}:`, e.message);
                lastError = e;
                continue;
            }
        }

        if (!result) {
            throw new Error(`All crypto libraries failed. Last error: ${lastError?.message}`);
        }

        // Debug for SHA512
        if (crypto === "HmacSHA512") {
            this.debugLog("DEBUG SHA512 - HMAC result length:", result.length);
            this.debugLog("DEBUG SHA512 - HMAC result:", Array.from(result.slice(0, 10)).map(b => b.toString(16).padStart(2, '0')).join(''));
        }

        return result;
    }

    static DIGITS_POWER = [
        // 0    1     2      3       4        5         6          7           8
        1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000
    ];

    /**
     * This method converts HEX string to Byte[]
     *
     * @param hex the HEX string
     *
     * @return A byte array
     */
    static hexStr2Bytes(hex) {
        // Adding one byte to get the right conversion
        // values starting with "0" can be converted

        // Exact reproduction of Java: new BigInteger("10" + hex, 16).toByteArray()

        // Handle empty hex
        if (!hex) return new Uint8Array(0);

        // Debug for long keys
        if (hex.length > 80) {
            this.debugLog("DEBUG hexStr2Bytes - Long hex input length:", hex.length);
            this.debugLog("DEBUG hexStr2Bytes - Long hex start:", hex.substring(0, 20));
        }

        // Java BigInteger behavior: add "10" prefix then convert
        const prefixedHex = "10" + hex;

        // Convert to number representation
        let bigIntValue;
        try {
            bigIntValue = BigInt("0x" + prefixedHex);
        } catch (e) {
            console.error("BigInt conversion error for hex:", hex.substring(0, 20) + "...");
            throw e;
        }

        // Convert to hex string (toByteArray equivalent)
        let hexStr = bigIntValue.toString(16);

        // Ensure even length
        if (hexStr.length % 2 !== 0) {
            hexStr = "0" + hexStr;
        }

        // Convert to byte array
        const bArray = new Uint8Array(hexStr.length / 2);
        for (let i = 0; i < hexStr.length; i += 2) {
            bArray[i / 2] = parseInt(hexStr.substr(i, 2), 16);
        }

        // Copy all the REAL bytes, not the "first"
        // Java: System.arraycopy(bArray, 1, ret, 0, ret.length);
        if (bArray.length <= 1) {
            return new Uint8Array(0);
        }

        const ret = new Uint8Array(bArray.length - 1);
        for (let i = 0; i < ret.length; i++) {
            ret[i] = bArray[i + 1];
        }

        // Debug for long keys
        if (hex.length > 80) {
            this.debugLog("DEBUG hexStr2Bytes - Output length:", ret.length);
            this.debugLog("DEBUG hexStr2Bytes - Output start:", Array.from(ret.slice(0, 10)).map(b => b.toString(16).padStart(2, '0')).join(''));
        }

        return ret;
    }

    /**
     * This method converts String to HEX string
     *
     * @param str the string
     *
     * @return A HEX String
     */
    static stringToHex(str) {
        const strbuf = [];
        let i;
        for (i = 0; i < str.length; i++) {
            if ((buf[i] & 0xff) < 0x10)
                strbuf.push("0");
            strbuf.push((buf[i] & 0xff).toString(16));
        }
        return strbuf.join("");
    }

    /**
     * This method converts BigInt to HEX string
     *
     * @param bigIntValue the BigInt
     *
     * @return A HEX String
     */
    static bigIntToHex(bigIntValue) {
        return bigIntValue.toString(16).toUpperCase();
    }

    /**
     * This method generates an OCRA HOTP value for the given
     * set of parameters.
     *
     * @param ocraSuite the OCRA Suite
     * @param key the shared secret, HEX encoded
     * @param counter the counter that changes on a per use basis, HEX encoded
     * @param question the challenge question, HEX encoded
     * @param password a password that can be used, HEX encoded
     * @param sessionInformation Static information that identifies the current session, Hex encoded (fixed size depend on Ocra Suite information)
     * @param timeStamp a value that reflects a time (BigInt number of minutes converted to hexString, in ocra-tests)
     *
     * @return A numeric String in base 10 that includes truncationDigits digits
     */
    static async generateOCRA(ocraSuite, key, counter, question, password, sessionInformation, timeStamp) {
        let codeDigits = 0;
        let crypto = "";
        let result = null;
        const ocraSuiteLength = new TextEncoder().encode(ocraSuite).length;
        let counterLength = 0;
        let questionLength = 0;
        let passwordLength = 0;
        let sessionInformationLength = 0;
        let timeStampLength = 0;

        // The OCRASuites components
        const CryptoFunction = ocraSuite.split(":")[1];
        const DataInput = ocraSuite.split(":")[2];

        if (CryptoFunction.toLowerCase().indexOf("sha1") > 1)
            crypto = "HmacSHA1";
        if (CryptoFunction.toLowerCase().indexOf("sha256") > 1)
            crypto = "HmacSHA256";
        if (CryptoFunction.toLowerCase().indexOf("sha512") > 1)
            crypto = "HmacSHA512";

        // How many digits should we return
        codeDigits = parseInt(CryptoFunction.substring(
            CryptoFunction.lastIndexOf("-") + 1));

        // The size of the byte array message to be encrypted
        // Counter
        if (DataInput.toLowerCase().startsWith("c")) {
            // Fix the length of the HEX string
            while (counter.length < 16)
                counter = "0" + counter;
            counterLength = 8;
        }

        // Question - always 128 bytes
        if (DataInput.toLowerCase().startsWith("q") ||
            (DataInput.toLowerCase().indexOf("-q") >= 0)) {
            while (question.length < 256)
                question = question + "0";
            questionLength = 128;
        }

        // Password - sha1
        if (DataInput.toLowerCase().indexOf("psha1") > 1) {
            while (password.length < 40)
                password = "0" + password;
            passwordLength = 20;
        }

        // Password - sha256
        if (DataInput.toLowerCase().indexOf("psha256") > 1) {
            while (password.length < 64)
                password = "0" + password;
            passwordLength = 32;
        }

        // Password - sha512
        if (DataInput.toLowerCase().indexOf("psha512") > 1) {
            while (password.length < 128)
                password = "0" + password;
            passwordLength = 64;
        }

        // sessionInformation - s064
        if (DataInput.toLowerCase().indexOf("s064") > 1) {
            while (sessionInformation.length < 128)
                sessionInformation = "0" + sessionInformation;
            sessionInformationLength = 64;
        }

        // sessionInformation - s128
        if (DataInput.toLowerCase().indexOf("s128") > 1) {
            while (sessionInformation.length < 256)
                sessionInformation = "0" + sessionInformation;
            sessionInformationLength = 128;
        }

        // sessionInformation - s256
        if (DataInput.toLowerCase().indexOf("s256") > 1) {
            while (sessionInformation.length < 512)
                sessionInformation = "0" + sessionInformation;
            sessionInformationLength = 256;
        }

        // sessionInformation - s512
        if (DataInput.toLowerCase().indexOf("s512") > 1) {
            while (sessionInformation.length < 1024)
                sessionInformation = "0" + sessionInformation;
            sessionInformationLength = 512;
        }

        // TimeStamp
        if (DataInput.toLowerCase().startsWith("t") ||
            (DataInput.toLowerCase().indexOf("-t") > 1)) {
            while (timeStamp.length < 16)
                timeStamp = "0" + timeStamp;
            timeStampLength = 8;
        }

        // Remember to add "1" for the "00" byte delimiter
        const msg = new Uint8Array(ocraSuiteLength +
            counterLength +
            questionLength +
            passwordLength +
            sessionInformationLength +
            timeStampLength +
            1);

        // Put the bytes of "ocraSuite" parameters into the message
        let bArray = new TextEncoder().encode(ocraSuite);
        msg.set(bArray, 0);

        // Delimiter
        msg[bArray.length] = 0x00;

        // Put the bytes of "Counter" to the message
        // Input is HEX encoded
        if (counterLength > 0) {
            bArray = this.hexStr2Bytes(counter);
            msg.set(bArray, ocraSuiteLength + 1);
        }

        // Put the bytes of "question" to the message
        // Input is text encoded
        if (questionLength > 0) {
            bArray = this.hexStr2Bytes(question);
            msg.set(bArray, ocraSuiteLength + 1 + counterLength);
        }

        // Put the bytes of "password" to the message
        // Input is HEX encoded
        if (passwordLength > 0) {
            bArray = this.hexStr2Bytes(password);
            msg.set(bArray, ocraSuiteLength + 1 + counterLength + questionLength);
        }

        // Put the bytes of "sessionInformation" to the message
        // Input is text encoded
        if (sessionInformationLength > 0) {
            bArray = this.hexStr2Bytes(sessionInformation);
            msg.set(bArray, ocraSuiteLength + 1 + counterLength + questionLength + passwordLength);
        }

        // Put the bytes of "time" to the message
        // Input is text value of minutes
        if (timeStampLength > 0) {
            bArray = this.hexStr2Bytes(timeStamp);
            msg.set(bArray, ocraSuiteLength + 1 + counterLength + questionLength + passwordLength + sessionInformationLength);
        }

        // Specific debug for SHA512
        const isDebugSHA512 = ocraSuite.includes("SHA512");
        if (isDebugSHA512) {
            this.debugLog("=== DEBUG SHA512 generateOCRA ===");
            this.debugLog("OCRASuite:", ocraSuite);
            this.debugLog("Key length:", key.length);
            this.debugLog("Counter:", counter);
            this.debugLog("Question:", question);
            this.debugLog("Password:", password);
            this.debugLog("SessionInfo:", sessionInformation);
            this.debugLog("TimeStamp:", timeStamp);
            this.debugLog("Crypto:", crypto);
            this.debugLog("CodeDigits:", codeDigits);
        }

        bArray = this.hexStr2Bytes(key);
        const hash = await this.hmac_sha1(crypto, bArray, msg);

        if (isDebugSHA512) {
            this.debugLog("Message length:", msg.length);
            this.debugLog("Message (first 20 bytes):", Array.from(msg.slice(0, 20)).map(b => b.toString(16).padStart(2, '0')).join(''));
            this.debugLog("Hash length:", hash.length);
            this.debugLog("Hash (first 20 bytes):", Array.from(hash.slice(0, 20)).map(b => b.toString(16).padStart(2, '0')).join(''));
        }

        // put selected bytes into result int
        const offset = hash[hash.length - 1] & 0xf;
        const binary =
            ((hash[offset] & 0x7f) << 24) |
            ((hash[offset + 1] & 0xff) << 16) |
            ((hash[offset + 2] & 0xff) << 8) |
            (hash[offset + 3] & 0xff);

        const otp = binary % this.DIGITS_POWER[codeDigits];

        if (isDebugSHA512) {
            this.debugLog("Offset:", offset);
            this.debugLog("Binary:", binary);
            this.debugLog("OTP before padding:", otp);
            this.debugLog("DIGITS_POWER[" + codeDigits + "]:", this.DIGITS_POWER[codeDigits]);
        }

        result = otp.toString();
        while (result.length < codeDigits) {
            result = "0" + result;
        }

        if (isDebugSHA512) {
            this.debugLog("Final result:", result);
            this.debugLog("=== END DEBUG SHA512 ===");
        }

        return result;
    }

    /**
     * Get information about available crypto libraries
     */
    static getCryptoInfo() {
        const available = this.detectCryptoLibraries();
        const info = {
            available: available,
            primary: available[0] || 'none',
            all: []
        };

        if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
            info.all.push({ name: 'Web Crypto API', status: 'available', native: true });
        } else {
            info.all.push({ name: 'Web Crypto API', status: 'not available', native: true });
        }

        if (typeof CryptoJS !== 'undefined') {
            info.all.push({ name: 'CryptoJS', status: 'available', version: CryptoJS.lib?.Base?.toString?.() || 'unknown' });
        } else {
            info.all.push({ name: 'CryptoJS', status: 'not available' });
        }

        if (typeof jsSHA !== 'undefined') {
            info.all.push({ name: 'jsSHA', status: 'available', version: 'unknown' });
        } else {
            info.all.push({ name: 'jsSHA', status: 'not available' });
        }

        return info;
    }
}

// Export for use in module (if supported)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = OCRA;
}

// Export for use globally in browser
if (typeof window !== 'undefined') {
    window.OCRA = OCRA;
}