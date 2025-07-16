# OCRA (RFC 6287) JavaScript Implementation

An implementation of the OATH Challenge-Response Algorithm (OCRA) as specified in [RFC 6287](https://tools.ietf.org/html/rfc6287).

# RFC 6287 Compliance

This implementation fully complies with RFC 6287 and passes all official test vectors:

- All hash algorithms (SHA1, SHA256, SHA512)
- All data input formats (C, Q, P, S, T)
- All question formats (N, A, H)

# Features

- Developped to works only in browsers 
  - Chrome 49+
  - Firefox 45+
  - Safari 10.1+
  - Opera 36+
  - Edge 13+
- Work with : CryptoJS; jsSHA and Browser Web Crypto API

# RFC Conformance Test

Running RFC conformance Test Vectors [her](https://zenprojects.github.io/OCRAjs/test.html)

# Quick Start

### Browser Usage

```html
<!-- Include a crypto library -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.2.0/crypto-js.min.js"></script>

<!-- Include OCRA -->
<script src="ocra.js"></script>

<script>
async function generateCode() {
  const code = await OCRA.generate(
    "OCRA-1:HOTP-SHA1-6:QN08",  // Suite
    "12345678901234567890",      // Secret key
    "12345678"                   // Challenge
  );
  console.log("OCRA Code:", code);
}
</script>
```

# API Reference

## OCRA.generate(suite, key, challenge, [counter], [password], [sessionInfo], [timestamp])

Generates an OCRA code according to the specified suite.

### Parameters

| Parameter     | Type                         | Required | Description                                                                                                                                                                          |
|---------------|------------------------------|----------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `suite`       | `string`                     | ✅        | OCRA suite specification (e.g., "OCRA-1:HOTP-SHA1-6:QN08")                                                                                                                           |
| `key`         | `Hex Encoded string`         | ✅        | Secret key (HEX encoded)                                                                                                                                                             |
| `challenge`   | `Hex Encoded string`         | ✅        | Challenge/question string (HEX encoded, type to encode depend on suite QNxx/QAxx/QHxx, QN = BigInt hexx String encoded, QA = String Hex Encoded, QH = Raw Hex String, max 128 bytes) |
| `counter`     | `Big Int Hex Encoded String` | ❌        | Counter value (for suites with 'C')        (BigInt HEX encoded, max 16 bytes)                                                                                                        |
| `password`    | `Hex Encoded string`         | ❌        | Password (for suites with 'P')  (HEX encoded, max 20 bytes)                                                                                                                          |
| `sessionInfo` | `Hex Encoded string`         | ❌        | Session information (for suites with 'S')     (HEX encoded, max bytes depend on the Ocra Suite : 64, 128, 512)                                                                       |
| `timestamp`   | `Big Int Hex Encoded`        | ❌        | Timestamp (for suites with 'T')            (BigInt Hex Encoded, the signification of the depend on the Time Step Granularity of the Ocra Suite)                                      | 

### Returns

- `Promise<string>` - The generated OCRA code

## Ocra Suite Format Structure

An OCRASuite value follows this general format:

```
<Algorithm>:<CryptoFunction>:<DataInput>
```

The OCRASuite is composed of three main components separated by colons (`:`):

1. **Algorithm** - Specifies the OCRA version
2. **CryptoFunction** - Defines the cryptographic function used
3. **DataInput** - Describes the input parameters for computation

## Component Specifications

### 1. Algorithm Component

**Format:** `OCRA-v`

- **Description:** Indicates the version of OCRA being used
- **Values:** `OCRA-1` (RFC 6287 specifies version 1)
- **Example:** `OCRA-1`

### 2. CryptoFunction Component

**Format:** `HOTP-H-t`

- **Description:** Specifies the HMAC-based function and truncation parameters
- **Components:**
  - `HOTP` - Fixed prefix indicating HOTP-based computation
  - `H` - Hash function (SHA1, SHA256, SHA512)
  - `t` - Truncation length in decimal digits (0, 4-10)

**Supported Values:**

| Function Name    | HMAC Function | Truncation Size |
|------------------|---------------|-----------------|
| HOTP-SHA1-t      | HMAC-SHA1     | 0, 4-10        |
| HOTP-SHA256-t    | HMAC-SHA256   | 0, 4-10        |
| HOTP-SHA512-t    | HMAC-SHA512   | 0, 4-10        |

**Common Examples:**
- `HOTP-SHA1-6` (default) - SHA1 with 6-digit truncation
- `HOTP-SHA256-8` - SHA256 with 8-digit truncation
- `HOTP-SHA512-4` - SHA512 with 4-digit truncation
- `HOTP-SHA1-0` - SHA1 with no truncation (full HMAC)

### 3. DataInput Component

**Format:** `[C][|QFxx][|PH][|Snnn][|TG]`

The DataInput component specifies which input parameters are used in the computation. Components are separated by hyphens (`-`) and include:

#### Counter (C) - Optional
- **Symbol:** `C`
- **Description:** 8-byte counter value synchronized between parties
- **Usage:** Incremented on each computation request
- **Example:** `C`

#### Challenge Question (Q) - Mandatory for most modes
- **Format:** `QFxx`
- **Description:** Challenge question with specified format and maximum length
- **Components:**
  - `Q` - Fixed prefix for challenge
  - `F` - Format specifier
  - `xx` - Maximum length (04-64)

**Format Specifiers:**

| Format (F) | Type         | Length Range |
|------------|--------------|--------------|
| A          | Alphanumeric | 04-64        |
| N          | Numeric      | 04-64        |
| H          | Hexadecimal  | 04-64        |

**Default:** `QN08` (Numeric, up to 8 digits)

**Examples:**
- `QN08` - Numeric challenge, max 8 digits
- `QA10` - Alphanumeric challenge, max 10 characters
- `QH16` - Hexadecimal challenge, max 16 nibbles

#### PIN/Password (P) - Optional
- **Format:** `PH`
- **Description:** Hashed version of PIN/password
- **Components:**
  - `P` - Fixed prefix for password
  - `H` - Hash function (SHA1, SHA256, SHA512)

**Supported Hash Functions:**
- `PSHA1` - SHA1 hash of PIN/password (default)
- `PSHA256` - SHA256 hash of PIN/password
- `PSHA512` - SHA512 hash of PIN/password

#### Session Information (S) - Optional
- **Format:** `Snnn`
- **Description:** UTF-8 encoded session data
- **Components:**
  - `S` - Fixed prefix for session
  - `nnn` - Length in bytes

**Common Lengths:**
- `S064` - 64 bytes (default)
- `S128` - 128 bytes
- `S256` - 256 bytes
- `S512` - 512 bytes

#### Timestamp (T) - Optional
- **Format:** `TG`
- **Description:** Time-based parameter
- **Components:**
  - `T` - Fixed prefix for timestamp
  - `G` - Time-step granularity

**Time-Step Granularity:**

| Granularity (G) | Description           | Examples |
|-----------------|-----------------------|----------|
| [1-59]S         | Seconds              | 20S      |
| [1-59]M         | Minutes              | 5M       |
| [0-48]H         | Hours                | 24H      |

**Default:** `T1M` (1-minute time steps)

## Usage Patterns

### Challenge-Response Computation
**Format:** `[C]|QFxx|[PH|Snnn|TG]`

**Examples:**
- `QN08` - Simple numeric challenge
- `C-QN08-PSHA1` - Counter + numeric challenge + PIN
- `QA10-T1M` - Alphanumeric challenge + timestamp

### Plain Signature Computation
**Format:** `[C]|QFxx|[PH|TG]`

**Examples:**
- `QA08` - Alphanumeric signature challenge
- `QH8-S512` - Hex challenge + session info

## OCRA Suite Examples

### Basic Challenge-Response
```
OCRA-1:HOTP-SHA1-6:QN08
```
- Version 1 OCRA
- SHA1 with 6-digit truncation
- Numeric challenge up to 8 digits

### Advanced Authentication
```
OCRA-1:HOTP-SHA512-8:C-QN08-PSHA1
```
- Version 1 OCRA
- SHA512 with 8-digit truncation
- Counter + numeric challenge + SHA1-hashed PIN

### Timestamped Challenge
```
OCRA-1:HOTP-SHA256-6:QA10-T1M
```
- Version 1 OCRA
- SHA256 with 6-digit truncation
- Alphanumeric challenge + 1-minute timestamps

### Session-Based Signature
```
OCRA-1:HOTP-SHA1-4:QH8-S512
```
- Version 1 OCRA
- SHA1 with 4-digit truncation
- Hex challenge + 512-byte session data

## Notes

1. **Key Agreement:** Client and server must agree on OCRASuite values during provisioning or negotiation
2. **Mutual Authentication:** Requires two OCRASuite values (one for server, one for client computation)
3. **Default Values:** When optional parameters are omitted, defaults apply (QN08, PSHA1, S064, T1M)
4. **Padding:** Challenge/questions less than 128 bytes are padded with zeros to the right
5. **Encoding:** Session information uses UTF-8 encoding
6. **Epoch Time:** Timestamps based on Unix epoch (January 1, 1970, midnight UTC)

## Examples

### Basic OCRA Generation

```javascript
const suite = "OCRA-1:HOTP-SHA1-6:QN08";
const key = "12345678901234567890";
const challenge = "12345678";

const code = await OCRA.generate(suite, key, challenge);
console.log(code); // e.g., "123456"
```

### Using Hex Keys

```javascript
const key = "3132333435363738393031323334353637383930";  // hex encoded seed key

const code = await OCRA.generate(
  "OCRA-1:HOTP-SHA1-6:QN08", 
  key,
  ORCA.bigIntToHex("00000000") // QN = numeric challenge
);
```

### Counter-Based OCRA

```javascript
const code = await OCRA.generate(
  "OCRA-1:HOTP-SHA1-6:C-QN08",
  key,
  ORCA.bigIntToHex("12345678"), // QN = numeric challenge
  ORCA.bigIntToHex("123")  // counter
);
```

### Password-Protected OCRA

```javascript
const code = await OCRA.generate(
  "OCRA-1:HOTP-SHA256-8:QN08-PSHA1",
  key, 
  ORCA.bigIntToHex("12345678"), // QN = numeric challenge
  undefined,                    // no counter
  OCRA.stringToHex("1234")      // PSHA1 = SHA1 password
);
```

### Time-Based OCRA

```javascript
const timestampMinutes = Math.floor(Date.now() / 60000); // Actual nulber of minute from epoch because set T1M in ocra suite

const code = await OCRA.generate(
  "OCRA-1:HOTP-SHA512-8:QN08-T1M",
  key,
  ORCA.bigIntToHex("12345678"),  // QN = numeric challenge
  undefined, // no counter
  undefined, // no password
  undefined, // no session
  ORCA.bigIntToHex(timestampMinutes)
);
```


# Crypto Library Support

The implementation automatically detects and uses available crypto libraries in this order:

1. **WebCrypto API** (default)
2. **CryptoJS** (alternative)
3. **jsSHA** (alternative)

Automatique detection : 
```javascript
const cryptoInfo = OCRA.getCryptoInfo();
console.log('Libraries available:', cryptoInfo.available);
console.log('Primary library:', cryptoInfo.primary);
```

### CryptoJS Setup

```html
<!-- Browser -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.2.0/crypto-js.min.js"></script>
```

### jsSHA Setup

```html
<!-- Browser -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/jsSHA/3.3.1/sha.js"></script>
```

## Error Handling

```javascript
try {
  const code = await OCRA.generate(suite, key, challenge);
  console.log("Success:", code);
} catch (error) {
  console.error("OCRA Error:", error.message);
}
```

### Common Errors

- `Invalid OCRA suite format` - Malformed suite string
- `Invalid crypto function` - Unsupported hash algorithm
- `Crypto library not supported` - No compatible crypto library found
- `Algorithm X not supported with Y` - Library doesn't support the algorithm

# License

**GNU Lesser General Public License v3.0 or later (LGPL-3.0-or-later)**

This library is free software; you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.




