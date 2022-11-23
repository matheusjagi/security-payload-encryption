require('dotenv/config');
const express = require('express');
const crypto = require("crypto");

const app = express();
app.use(express.json());
app.use(express.urlencoded());

const outputEncoding = 'hex',
    inputEncoding = 'utf8',
    algorithm = 'aes-256-gcm', 
    oaepHashingAlgorithm = 'SHA256',
    ivLength = 16,
    sessionKeyLength = 32;

app.post('/encrypt', function (req, res) {
    res.status(200).send(encryptAES(req.body.payload));
});

function encryptAES(info) {
    const iv = crypto.randomBytes(ivLength).toString(outputEncoding).slice(0, 16);
    const sessionKey = crypto.randomBytes(sessionKeyLength).toString(outputEncoding).slice(0, 32);

    const cipher = crypto.createCipheriv(algorithm, sessionKey, iv);

    let encryptedInfo = cipher.update(info, inputEncoding, outputEncoding) + cipher.final(outputEncoding);
    const tag = cipher.getAuthTag();

    return {
        "iv": iv,
        "encryptedKey": encryptRSA(sessionKey),
        "encryptedValue": encryptedInfo,
        "tag": tag,
        "oaepHashingAlgorithm": oaepHashingAlgorithm
    };
}

function encryptRSA(info) {
    return crypto.publicEncrypt({
            key: process.env.PUBLIC_KEY,
            padding: crypto.constants.RSA_PKCS1_PADDING
        },
        Buffer.from(info)
    ).toString('base64');
}

app.listen(3000, function () {
    console.log('Microsserviço iniciado na porta 3000');
});