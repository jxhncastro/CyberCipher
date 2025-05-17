const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto'); 
const app = express();
const port = 3000;

app.use(express.static('public'));
app.use(bodyParser.json());

// For AES
const AES_HMAC_KEY = crypto.randomBytes(32); // A separate, secret key for HMAC. 
const AES_FIXED_IV = Buffer.from('000102030405060708090A0B0C0D0E0F', 'hex'); // Fixed IV for demonstration ONLY if random IV is disabled

// For Vigenere
const VIGENERE_PERMUTATION_BLOCK_SIZE = 5; 

function vigenereEncrypt(text, keyword, autoKeyEnabled, permutationEnabled) {
    keyword = keyword.toUpperCase().replace(/[^A-Z]/g, '');
    if (!keyword) return { error: "Vigenere key must contain alphabetic characters." };

    let encryptedText = '';
    let keyStream = keyword;
    let keyIndex = 0;

    for (let i = 0; i < text.length; i++) {
        const char = text[i];

        if (char.match(/[A-Za-z]/)) {
            const isUpper = char === char.toUpperCase();
            const base = isUpper ? 65 : 97;

            const ptCharCode = char.charCodeAt(0) - base;
            const keyCharCode = keyStream[keyIndex].charCodeAt(0) - 65;
            const encryptedChar = String.fromCharCode(((ptCharCode + keyCharCode) % 26) + base);

            encryptedText += encryptedChar;
            keyIndex++;

            if (autoKeyEnabled) {
                keyStream += char.toUpperCase(); // always add uppercase for key stream
            }
        } else {
            encryptedText += char; // Non-alpha stays the same
        }
    }

    if (permutationEnabled) {
        encryptedText = applyVigenerePermutation(encryptedText, VIGENERE_PERMUTATION_BLOCK_SIZE, 'encrypt');
    }

    return { encryptedText };
}

function vigenereDecrypt(text, keyword, autoKeyEnabled, permutationEnabled) {
    if (permutationEnabled) {
        text = applyVigenerePermutation(text, VIGENERE_PERMUTATION_BLOCK_SIZE, 'decrypt');
    }

    keyword = keyword.toUpperCase().replace(/[^A-Z]/g, '');
    if (!keyword) return { error: "Vigenere key must contain alphabetic characters." };

    let decryptedText = '';
    let keyStream = keyword;
    let keyIndex = 0;

    for (let i = 0; i < text.length; i++) {
        const char = text[i];

        if (char.match(/[A-Za-z]/)) {
            const isUpper = char === char.toUpperCase();
            const base = isUpper ? 65 : 97;

            const ctCharCode = char.charCodeAt(0) - base;
            const keyCharCode = keyStream[keyIndex].charCodeAt(0) - 65;
            const decryptedCharCode = (ctCharCode - keyCharCode + 26) % 26;
            const decryptedChar = String.fromCharCode(decryptedCharCode + base);

            decryptedText += decryptedChar;
            keyIndex++;

            if (autoKeyEnabled) {
                keyStream += decryptedChar.toUpperCase(); // append decrypted character for autokey
            }
        } else {
            decryptedText += char; // Non-alpha stays the same
        }
    }

    return { decryptedText };
}

// Simple Block Permutation for Vigenere
function applyVigenerePermutation(text, blockSize, mode) {
    let blocks = [];
    for (let i = 0; i < text.length; i += blockSize) {
        blocks.push(text.substring(i, i + blockSize));
    }

    if (mode === 'encrypt') {
        // Simple reversal within each block for encryption
        return blocks.map(block => block.split('').reverse().join('')).join('');
    } else if (mode === 'decrypt') {
        // Simple reversal within each block for decryption
        return blocks.map(block => block.split('').reverse().join('')).join('');
    }
    return text; // Should not happen
}


function caesarCipher(text, key, encrypt) {
    key = key % 26; // Normalize key to 0-25
    let result = '';

    for (let i = 0; i < text.length; i++) {
        let char = text[i];
        let offset = encrypt ? key : -key;

        if (char >= 'A' && char <= 'Z') {
            result += String.fromCharCode(((char.charCodeAt(0) - 65 + offset + 26) % 26) + 65);
        } else if (char >= 'a' && char <= 'z') {
            result += String.fromCharCode(((char.charCodeAt(0) - 97 + offset + 26) % 26) + 97);
        } else {
            result += char; // Non-alphabetical characters are unchanged
        }
    }

    return result;
}

// Mirror Shift Cipher
function mirrorShiftCipher(text, key, encrypt) {
    let processedText = encrypt ? text.split('').reverse().join('') : text;
    let result = '';
    for (let i = 0; i < processedText.length; i++) {
        let charCode = processedText.charCodeAt(i);
        let shift = key + (i % 5);
        if (encrypt) {
            result += String.fromCharCode(charCode + shift);
        } else {
            result += String.fromCharCode(charCode - shift);
        }
    }
    return encrypt ? result : result.split('').reverse().join('');
}

// Dynamic Shift Cipher
function dynamicShiftCipher(text, key, salt, encrypt) {
    const combinedKey = key + (salt ? salt.split('').reduce((sum, char) => sum + char.charCodeAt(0), 0) : 0);
    const blockSize = (combinedKey % 10) + 1;

    if (encrypt) {
        let shiftedText = '';
        for (let i = 0; i < text.length; i++) {
            let charCode = text.charCodeAt(i);
            let dynamicShift = (combinedKey + i) % 256;
            shiftedText += String.fromCharCode(charCode + dynamicShift);
        }
        // Block manipulation
        let blocks = [];
        for (let i = 0; i < shiftedText.length; i += blockSize) {
            blocks.push(shiftedText.substring(i, i + blockSize).split('').reverse().join(''));
        }
        return blocks.reverse().join('');
    } else {
        // Reverse block manipulation first
        let blocks = [];
        for (let i = 0; i < text.length; i += blockSize) {
            blocks.push(text.substring(i, i + blockSize));
        }
        let reversedBlocksText = blocks.reverse().map(block => block.split('').reverse().join('')).join('');

        let result = '';
        for (let i = 0; i < reversedBlocksText.length; i++) {
            let charCode = reversedBlocksText.charCodeAt(i);
            let dynamicShift = (combinedKey + i) % 256;
            result += String.fromCharCode(charCode - dynamicShift);
        }
        return result;
    }
}


// --- AES Encryption/Decryption (crypto module) ---
function aesEncrypt(text, aesKeyHex, enableRandomIV, enableHMAC) {
    let key;
    if (aesKeyHex) {
        key = Buffer.from(aesKeyHex, 'hex');
        if (key.length !== 32) { // AES-256 requires a 32-byte key
            return { error: "AES Key must be 64 characters (32 bytes) in hexadecimal." };
        }
    } else {
        key = crypto.randomBytes(32); // Generate a random 256-bit key
    }

    const iv = enableRandomIV ? crypto.randomBytes(16) : AES_FIXED_IV; // 128-bit IV for AES-CBC

    try {
        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        let result = {
            encryptedText: iv.toString('hex') + encrypted, // Prepend IV to ciphertext
            key: key.toString('hex') // Return the generated key (if not provided)
        };

        if (enableHMAC) {
            const hmac = crypto.createHmac('sha256', AES_HMAC_KEY); // HMAC key
            hmac.update(Buffer.from(encrypted, 'hex')); // HMAC on the ciphertext
            result.hmac = hmac.digest('hex');
            result.encryptedText += `:${result.hmac}`; // Append HMAC to ciphertext
        }

        return result;

    } catch (err) {
        console.error("AES Encryption Error:", err);
        return { error: "AES encryption failed. Check key format or other parameters." };
    }
}

function aesDecrypt(ciphertextWithIVandHMAC, aesKeyHex, enableRandomIV, enableHMAC) {
    let key;
    if (aesKeyHex) {
        key = Buffer.from(aesKeyHex, 'hex');
        if (key.length !== 32) {
            return { error: "AES Key must be 64 characters (32 bytes) in hexadecimal." };
        }
    } else {
        return { error: "Decryption requires the original AES Key." };
    }

    let hmacProvided = '';
    let ciphertextWithIV = ciphertextWithIVandHMAC;

    if (enableHMAC) {
        const parts = ciphertextWithIVandHMAC.split(':');
        if (parts.length !== 2) {
            return { error: "Invalid ciphertext format for HMAC. Expected 'ciphertext:hmac'." };
        }
        ciphertextWithIV = parts[0];
        hmacProvided = parts[1];

        const hmac = crypto.createHmac('sha256', AES_HMAC_KEY);
        hmac.update(Buffer.from(ciphertextWithIV.substring(32), 'hex')); // HMAC on just the ciphertext part (after IV)
        const hmacCalculated = hmac.digest('hex');

        if (hmacCalculated !== hmacProvided) {
            return { error: "HMAC mismatch. Data may have been tampered with or key is incorrect." };
        }
    }

    if (ciphertextWithIV.length < 32) { // 16 bytes for IV * 2 hex chars/byte = 32 hex chars
        return { error: "Invalid ciphertext length. Missing IV." };
    }

    const iv = enableRandomIV ? Buffer.from(ciphertextWithIV.substring(0, 32), 'hex') : AES_FIXED_IV;
    const ciphertext = ciphertextWithIV.substring(32);

    try {
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
        let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return { decryptedText: decrypted };
    } catch (err) {
        console.error("AES Decryption Error:", err);
        return { error: "AES decryption failed. Check key, IV, or ciphertext format." };
    }
}


// --- ROUTES ---

app.post('/encrypt', (req, res) => {
    const { type, text, key, vigenereKey, salt, useAESKey, aesKey, enableAESRandomIV, enableAESHMAC, enableVigenereAutoKey, enableVigenerePermutation } = req.body;

    let result = {};
    switch (type) {
        case 'Caesar':
            if (isNaN(key)) return res.status(400).json({ error: "Caesar key must be a number." });
            result.encryptedText = caesarCipher(text, key, true);
            break;
        case 'ReverseCipher':
            if (isNaN(key)) return res.status(400).json({ error: "Mirror Shift key must be a number." });
            result.encryptedText = mirrorShiftCipher(text, key, true);
            break;
        case 'DynamicShift':
            if (isNaN(key)) return res.status(400).json({ error: "Dynamic Shift key must be a number." });
            result.encryptedText = dynamicShiftCipher(text, key, salt, true);
            break;
        case 'Vigenere':
            if (!vigenereKey) return res.status(400).json({ error: "Vigenère key is required." });
            const vigenereResult = vigenereEncrypt(text, vigenereKey, enableVigenereAutoKey, enableVigenerePermutation);
            if (vigenereResult.error) return res.status(400).json(vigenereResult);
            result.encryptedText = vigenereResult.encryptedText;
            break;
        case 'AES':
            const aesEncryptResult = aesEncrypt(text, useAESKey ? aesKey : null, enableAESRandomIV, enableAESHMAC);
            if (aesEncryptResult.error) return res.status(400).json(aesEncryptResult);
            result.encryptedText = aesEncryptResult.encryptedText;
            break;
        default:
            return res.status(400).json({ error: 'Invalid encryption type.' });
    }
    res.json(result);
});

app.post('/decrypt', (req, res) => {
    const { type, text, key, vigenereKey, salt, useAESKey, aesKey, enableAESRandomIV, enableAESHMAC, enableVigenereAutoKey, enableVigenerePermutation } = req.body;

    let result = {};
    switch (type) {
        case 'Caesar':
            if (isNaN(key)) return res.status(400).json({ error: "Caesar key must be a number." });
            result.decryptedText = caesarCipher(text, key, false);
            break;
        case 'ReverseCipher':
            if (isNaN(key)) return res.status(400).json({ error: "Mirror Shift key must be a number." });
            result.decryptedText = mirrorShiftCipher(text, key, false);
            break;
        case 'DynamicShift':
            if (isNaN(key)) return res.status(400).json({ error: "Dynamic Shift key must be a number." });
            result.decryptedText = dynamicShiftCipher(text, key, salt, false);
            break;
        case 'Vigenere':
            if (!vigenereKey) return res.status(400).json({ error: "Vigenère key is required." });
            const vigenereResult = vigenereDecrypt(text, vigenereKey, enableVigenereAutoKey, enableVigenerePermutation);
            if (vigenereResult.error) return res.status(400).json(vigenereResult);
            result.decryptedText = vigenereResult.decryptedText;
            break;
        case 'AES':
            const aesDecryptResult = aesDecrypt(text, useAESKey ? aesKey : null, enableAESRandomIV, enableAESHMAC);
            if (aesDecryptResult.error) return res.status(400).json(aesDecryptResult);
            result.decryptedText = aesDecryptResult.decryptedText;
            break;
        default:
            return res.status(400).json({ error: 'Invalid decryption type.' });
    }
    res.json(result);
});

app.post('/encrypt-file', (req, res) => {
    const {
        type,
        text,
        key,
        vigenereKey,
        salt,
        useAESKey,
        aesKey,
        enableAESRandomIV,
        enableAESHMAC,
        enableVigenereAutoKey,
        enableVigenerePermutation,
        enableCaesarShuffle,
        enableCaesarSymbolSub
    } = req.body;

    if (!text) return res.status(400).json({ error: "File content is required." });

    let result = {};
    switch (type) {
        case 'Caesar':
            if (isNaN(key)) return res.status(400).json({ error: "Caesar key must be a number." });
            result.encryptedText = caesarCipher(text, key, true, enableCaesarShuffle, enableCaesarSymbolSub);
            break;
        case 'ReverseCipher':
            if (isNaN(key)) return res.status(400).json({ error: "Mirror Shift key must be a number." });
            result.encryptedText = mirrorShiftCipher(text, key, true);
            break;
        case 'DynamicShift':
            if (isNaN(key)) return res.status(400).json({ error: "Dynamic Shift key must be a number." });
            result.encryptedText = dynamicShiftCipher(text, key, salt, true);
            break;
        case 'Vigenere':
            if (!vigenereKey) return res.status(400).json({ error: "Vigenère key is required." });
            const vigenereResult = vigenereEncrypt(text, vigenereKey, enableVigenereAutoKey, enableVigenerePermutation);
            if (vigenereResult.error) return res.status(400).json(vigenereResult);
            result.encryptedText = vigenereResult.encryptedText;
            break;
        case 'AES':
            const aesEncryptResult = aesEncrypt(text, useAESKey ? aesKey : null, enableAESRandomIV, enableAESHMAC);
            if (aesEncryptResult.error) return res.status(400).json(aesEncryptResult);
            result.encryptedText = aesEncryptResult.encryptedText;
            break;
        default:
            return res.status(400).json({ error: 'Invalid encryption type.' });
    }
    res.json(result);
});

// File Decryption
app.post('/decrypt-file', (req, res) => {
    const {
        type,
        text,
        key,
        vigenereKey,
        salt,
        useAESKey,
        aesKey,
        enableAESRandomIV,
        enableAESHMAC,
        enableVigenereAutoKey,
        enableVigenerePermutation,
        enableCaesarShuffle,
        enableCaesarSymbolSub
    } = req.body;

    if (!text) return res.status(400).json({ error: "File content is required." });

    let result = {};
    switch (type) {
        case 'Caesar':
            if (isNaN(key)) return res.status(400).json({ error: "Caesar key must be a number." });
            result.decryptedText = caesarCipher(text, key, false, enableCaesarShuffle, enableCaesarSymbolSub);
            break;
        case 'ReverseCipher':
            if (isNaN(key)) return res.status(400).json({ error: "Mirror Shift key must be a number." });
            result.decryptedText = mirrorShiftCipher(text, key, false);
            break;
        case 'DynamicShift':
            if (isNaN(key)) return res.status(400).json({ error: "Dynamic Shift key must be a number." });
            result.decryptedText = dynamicShiftCipher(text, key, salt, false);
            break;
        case 'Vigenere':
            if (!vigenereKey) return res.status(400).json({ error: "Vigenère key is required." });
            const vigenereResult = vigenereDecrypt(text, vigenereKey, enableVigenereAutoKey, enableVigenerePermutation);
            if (vigenereResult.error) return res.status(400).json(vigenereResult);
            result.decryptedText = vigenereResult.decryptedText;
            break;
        case 'AES':
            const aesDecryptResult = aesDecrypt(text, useAESKey ? aesKey : null, enableAESRandomIV, enableAESHMAC);
            if (aesDecryptResult.error) return res.status(400).json(aesDecryptResult);
            result.decryptedText = aesDecryptResult.decryptedText;
            break;
        default:
            return res.status(400).json({ error: 'Invalid decryption type.' });
    }
    res.json(result);
});
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});