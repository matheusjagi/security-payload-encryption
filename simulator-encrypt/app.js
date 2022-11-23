require('dotenv/config');
const express = require('express');
const crypto = require("crypto");

const app = express();
app.use(express.json());
app.use(express.urlencoded());

const outputEncoding = 'base64',
    inputEncoding = 'utf8',
    algorithm = 'aes-256-gcm', 
    ivLength = 16,
    sessionKeyLength = 32;

app.post('/encrypt', function (req, res) {
    res.status(200).send(encryptAES(req.body.payload));
});

function encryptAES(info) {
    const iv = Buffer.from(crypto.randomBytes(ivLength), 'utf8');
    const sessionKey = Buffer.from(crypto.randomBytes(sessionKeyLength), 'utf8');

    const cipher = crypto.createCipheriv(algorithm, sessionKey, iv);

    let encryptedInfo = Buffer.concat([cipher.update(info, inputEncoding), cipher.final()]);
    let tag = cipher.getAuthTag();

    return {
        "iv": iv.toString(outputEncoding),
        "encryptedKey": encryptRSA(sessionKey),
        "encryptedKey": sessionKey.toString(outputEncoding),
        "encryptedValue": Buffer.concat([encryptedInfo, tag]).toString(outputEncoding)
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