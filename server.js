const express = require('express');
const jwt = require('jsonwebtoken');
const jose = require('node-jose');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');

const app = express();
const port = 8080;

const DB_FILE = path.join(process.cwd(), 'totally_not_my_privateKeys.db');

// ensure DB file exists 
let db;
let ready = false;
let readyPromise;

function openDatabase() {
  return new Promise((resolve, reject) => {
    db = new sqlite3.Database(DB_FILE, sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
      if (err) return reject(err);
      // create table if not exists
      db.run(
        `CREATE TABLE IF NOT EXISTS keys(
          kid INTEGER PRIMARY KEY AUTOINCREMENT,
          key BLOB NOT NULL,
          exp INTEGER NOT NULL
        )`,
        (err) => {
          if (err) return reject(err);
          resolve();
        }
      );
    });
  });
}

// save private key PEM and expiry using parameterized query
function saveKey(pem, exp) {
  return new Promise((resolve, reject) => {
    const sql = `INSERT INTO keys(key, exp) VALUES(?, ?)`;
    db.run(sql, [pem, exp], function (err) {
      if (err) return reject(err);
      resolve(this.lastID);
    });
  });
}

// read keys: expiredFlag=true -> expired keys, else non-expired
function getKeys(expiredFlag) {
  return new Promise((resolve, reject) => {
    const now = Math.floor(Date.now() / 1000);
    let sql;
    let params;
    if (expiredFlag) {
      sql = `SELECT kid, key, exp FROM keys WHERE exp <= ?`;
      params = [now];
    } else {
      sql = `SELECT kid, key, exp FROM keys WHERE exp > ?`;
      params = [now];
    }
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

// read all non-expired keys for JWKS
function getValidKeys() {
  return getKeys(false);
}

// read one key (expired or not)
function getOneKey(expiredFlag) {
  return new Promise((resolve, reject) => {
    const now = Math.floor(Date.now() / 1000);
    let sql;
    let params;
    if (expiredFlag) {
      sql = `SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY kid LIMIT 1`;
      params = [now];
    } else {
      sql = `SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid LIMIT 1`;
      params = [now];
    }
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}

app.use((req, res, next) => {
  if (ready) return next();
  readyPromise.then(() => next()).catch(next);
});

// enforce POST on /auth
app.all('/auth', (req, res, next) => {
  if (req.method !== 'POST') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

// ensure only GET requests are allowed for /jwks
app.all('/.well-known/jwks.json', (req, res, next) => {
  if (req.method !== 'GET') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

// GET JWKS: read all valid (non-expired) keys and return their public JWKs
app.get('/.well-known/jwks.json', async (req, res) => {
  try {
    const rows = await getValidKeys();
    // rows[].key contains PEM private key; convert to node-jose Key objects to extract public JWK
    const jwks = [];
    for (const row of rows) {
      const key = await jose.JWK.asKey(row.key, 'pem');
      // ensure the public JWK uses the DB `kid` so tokens signed with that kid are verifiable
      try {
        key.kid = row.kid.toString();
      } catch (e) {
        // if setting directly fails, fall back silently
      }
      const publicJwk = key.toJSON();
      // ensure kid present in output
      publicJwk.kid = row.kid.toString();
      jwks.push(publicJwk);
    }
    res.setHeader('Content-Type', 'application/json');
    res.json({ keys: jwks });
  } catch (err) {
    console.error('Error building JWKS:', err);
    res.status(500).send('Internal Server Error');
  }
});

// POST /auth: return a JWT signed with either an expired or valid private key from DB
app.post('/auth', async (req, res) => {
  try {
    const wantsExpired = req.query.expired === 'true';
    const row = await getOneKey(wantsExpired);
    if (!row) {
      return res.status(500).send('No matching key in DB');
    }
    // row.key is PEM private key
    const privatePem = row.key;
    const kid = row.kid.toString();
    const now = Math.floor(Date.now() / 1000);
    // JWT payloads include username from a fake auth
    let payload;
    if (wantsExpired) {
      // make the token expired: issued in the past and expired in the past
      payload = {
        user: 'userABC',
        iat: now - 3600,
        exp: now - 10
      };
    } else {
      payload = {
        user: 'userABC',
        iat: now,
        exp: now + 3600
      };
    }
    const options = {
      algorithm: 'RS256',
      header: {
        typ: 'JWT',
        alg: 'RS256',
        kid: kid
      }
    };
    const signed = jwt.sign(payload, privatePem, options);
    res.send(signed);
  } catch (err) {
    console.error('Error signing JWT:', err);
    res.status(500).send('Internal Server Error');
  }
});

// generate keys and persist to DB ensuring at least one expired and one valid key
async function ensureKeysInDb() {
  // ensure at least one valid and one expired key exist
  return new Promise((resolve, reject) => {
    const now = Math.floor(Date.now() / 1000);
    db.get('SELECT COUNT(*) AS total FROM keys', async (err, rowTotal) => {
      if (err) return reject(err);
      try {
        // count valid and expired separately
        db.get('SELECT COUNT(*) AS validCnt FROM keys WHERE exp > ?', [now], async (err, validRow) => {
          if (err) return reject(err);
          db.get('SELECT COUNT(*) AS expiredCnt FROM keys WHERE exp <= ?', [now], async (err, expiredRow) => {
            if (err) return reject(err);

            const validCnt = validRow ? validRow.validCnt : 0;
            const expiredCnt = expiredRow ? expiredRow.expiredCnt : 0;

            // insert a valid key if none
            if (validCnt === 0) {
              const validKey = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
              const validPem = validKey.toPEM(true);
              const validExp = now + 3600; // 1 hour
              await saveKey(validPem, validExp);
            }

            // insert an expired key if none
            if (expiredCnt === 0) {
              const expiredKey = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
              const expiredPem = expiredKey.toPEM(true);
              const expiredExp = now - 10; // already expired
              await saveKey(expiredPem, expiredExp);
            }

            resolve();
          });
        });
      } catch (e) {
        reject(e);
      }
    });
  });
}

// open DB ensure keys exist then listen when run directly
readyPromise = openDatabase()
  .then(() => ensureKeysInDb())
  .then(() => {
    ready = true;
    if (require.main === module) {
      app.listen(port, () => {
        console.log(`Server started on http://localhost:${port}`);
      });
    }
  })
  .catch((err) => {
    console.error('Failed to start server:', err);
    process.exit(1);
  });

// delay handling until DB/keys are ready to prevent race conditions during tests
app.use((req, res, next) => {
  if (ready) return next();
  readyPromise.then(() => next()).catch(next);
});

// export for tests
module.exports = app;
