const express = require('express')
const createError = require('http-errors')
const morgan = require('morgan')
require('dotenv').config()
const JWT = require('jsonwebtoken')
const fs = require('fs')
const { generateKeyPairSync } = require('crypto')


const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(morgan('dev'));
app.use(express.static('public'))

const PORT = 8005;
const KEY_EXPIRATION_SECONDS = 3600; 
const SECRET_KEY = 'your_secret_key';
var { public, private } = {}

const keyPairs = {};
function generateRSAKeyPair() {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    public = publicKey;
    private = privateKey
    return {
      publicKey,
      privateKey,
      kid: new Date().toISOString(),
      expiry: Date.now() + KEY_EXPIRATION_SECONDS * 1000,
    };
  }

keyPairs['initial'] = generateRSAKeyPair();


  app.get('/jwks', (req, res) => {
    console.log('From GET call');
    const validKeys = Object.values(keyPairs).filter(key => key.expiry > Date.now());
  
    const jwks = {
      keys: validKeys.map(key => ({
        kty: 'RSA',
        kid: key.kid,
        use: 'sig',
        nbf: Math.floor(key.expiry / 1000) - KEY_EXPIRATION_SECONDS,
        exp: Math.floor(key.expiry / 1000),
        alg: 'RS256',
        e: 'AQAB',
        n: key.publicKey.split('-----')[2].replace(/\r?\n|\r/g, ''),
      })),
    };
  
    res.json(jwks);
  });
  

app.get('/login',(req,res,next)=>{
    const secret = private
    const token = JWT.sign({}, secret, {expiresIn: '20min', algorithm: 'RS256'})
    res.send({ token })
})

app.listen(PORT, ()=>{
    console.log(`Server is Running in PORT ${PORT}`);
})