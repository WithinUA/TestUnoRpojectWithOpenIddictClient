// --------------- RAM storage ---------------
const KeyStore = (function () {
    const _keys = {};

    return {
        setKey: function (name, jwkJsonString) {
            _keys[name] = jwkJsonString;
        },
        getKey: async function (name) {
            if (!_keys[name]) {
                await decryptAndSaveToKeyStore();
            }
            return _keys[name];
        },
        clearKey: function (name) {
            _keys[name] = null;
        },
        clearAll: function () {
            for (const k in _keys) _keys[k] = null;
        }
    };
})();

// --------------------- IndexedDB ---------------------
function openDatabase() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open("cryptoKeysDB", 2);

        request.onupgradeneeded = function (event) {
            const db = event.target.result;

            if (!db.objectStoreNames.contains("keys")) {
                db.createObjectStore("keys");
            }
            if (!db.objectStoreNames.contains("device")) {
                db.createObjectStore("device");
            }
        };

        request.onsuccess = function (event) {
            resolve(event.target.result);
        };

        request.onerror = function (event) {
            reject(event.target.error);
        };
    });
}

async function loadKeys(db) {
    return new Promise((resolve, reject) => {
        const transaction = db.transaction(["keys"], "readonly");
        const store = transaction.objectStore("keys");

        const request = store.get("myEncryptedKeys");

        request.onsuccess = function (event) {
            const result = event.target.result;
            if (result) {
                console.log("Keys are succesfully got from IndexedDB");
                resolve(result);
            } else {
                console.warn("Keys did not found");
                resolve(null);
            }
        };

        request.onerror = function (event) {
            console.error("Reading keys error:", event.target.error);
            reject(event.target.error);
        };
    });
}

async function loadDeviceId(db) {
    return new Promise((resolve, reject) => {
        const transaction = db.transaction(["device"], "readonly");
        const store = transaction.objectStore("device");

        const request = store.get("deviceId");

        request.onsuccess = function (event) {
            const result = event.target.result;
            if (result) {
                console.log("deviceId was found IndexedDB");
                resolve(result);
            } else {
                console.warn("deviceId was not found");
                resolve(null);
            }
        };

        request.onerror = function (event) {
            console.error("Reading deviceId error:", event.target.error);
            reject(event.target.error);
        };
    });
}

async function saveDeviceId(db, deviceId) {
    return new Promise((resolve, reject) => {
        const transaction = db.transaction(["device"], "readwrite");
        const store = transaction.objectStore("device");

        const request = store.put(deviceId, "deviceId");

        request.onsuccess = function () {
            console.log("deviceId saved in IndexedDB");
            resolve();
        };

        request.onerror = function (event) {
            console.error("Save deviceId error:", event.target.error);
            reject(event.target.error);
        };
    });
}

async function saveKeys(db, keysToStore) {
    return new Promise((resolve, reject) => {
        const transaction = db.transaction(["keys"], "readwrite");
        const store = transaction.objectStore("keys");

        const request = store.put(keysToStore, "myEncryptedKeys");

        request.onsuccess = function () {
            console.log("Keys was succesfully created in IndexedDB");
            resolve();
        };

        request.onerror = function (event) {
            console.error("Save keys error:", event.target.error);
            reject(event.target.error);
        };
    });
}

async function decryptAndSaveToKeyStore() {
    const db = await openDatabase();
    const existingKeys = await loadKeys(db);

    if (existingKeys) {
        const deviceId = await loadDeviceId(db);
        const deviceIdBytes = new TextEncoder().encode(deviceId);

        const baseKey = await window.crypto.subtle.importKey(
            "raw",
            deviceIdBytes,
            "PBKDF2",
            false,
            ["deriveKey"]
        );

        const aesKey = await window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: Uint8Array.from(existingKeys.salt),
                iterations: 100000,
                hash: "SHA-256"
            },
            baseKey,
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );

        async function decryptText(cipherText, aesKey, iv) {
            const decrypted = await window.crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: iv
                },
                aesKey,
                cipherText
            );

            const decoded = new TextDecoder().decode(decrypted);
            return decoded;
        }

        const decryptedCryptoKeyString = await decryptText(
            existingKeys.cryptoKey,
            aesKey,
            Uint8Array.from(existingKeys.iv)
        );

        const decryptedSignKeyString = await decryptText(
            existingKeys.signInKey,
            aesKey,
            Uint8Array.from(existingKeys.iv)
        );

        KeyStore.setKey("Ecierge encryption key", decryptedCryptoKeyString);
        KeyStore.setKey("Ecierge signing key", decryptedSignKeyString);

        console.log("Keys decrypted and stored in RAM (KeyStore)");
    } else {
        console.warn("No keys found in IndexedDB");
    }
}
// --------------------- Logic  ---------------------
(async () => {
    const db = await openDatabase();

    const existingKeys = await loadKeys(db);

    if (!existingKeys) {
        console.log("Generating keys");

        let deviceId = await loadDeviceId(db);

        if (!deviceId) {
            deviceId = crypto.randomUUID();
            await saveDeviceId(db, deviceId);
            console.log("New deviceId created:", deviceId);
        }

        const deviceIdBytes = new TextEncoder().encode(deviceId);
        const salt = window.crypto.getRandomValues(new Uint8Array(16));

        const cryptoKeyPair = await window.crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256"
            },
            true,
            ["encrypt", "decrypt"]
        );

        const signingKeyPair = await window.crypto.subtle.generateKey(
            {
                name: "RSASSA-PKCS1-v1_5",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256"
            },
            true,
            ["sign", "verify"]
        );

        const exportedCryptoPrivateKey = await window.crypto.subtle.exportKey(
            "jwk",
            cryptoKeyPair.privateKey
        );
        const exportedSignInPrivateKey = await window.crypto.subtle.exportKey(
            "jwk",
            signingKeyPair.privateKey
        );
        console.log(exportedCryptoPrivateKey)
        console.log(exportedSignInPrivateKey)

        const exportedCryptoPrivateKeyString = JSON.stringify(exportedCryptoPrivateKey);
        const exportedSignInPrivateKeyString = JSON.stringify(exportedSignInPrivateKey);

        KeyStore.setKey("Ecierge encryption key", exportedCryptoPrivateKeyString);
        KeyStore.setKey("Ecierge signing key", exportedSignInPrivateKeyString);

        const baseKey = await window.crypto.subtle.importKey(
            "raw",
            deviceIdBytes,
            "PBKDF2",
            false,
            ["deriveKey"]
        );

        const aesKey = await window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: 100000,
                hash: "SHA-256"
            },
            baseKey,
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );

        const iv = window.crypto.getRandomValues(new Uint8Array(12));

        async function encryptText(plainText, aesKey, iv) {
            const encoded = new TextEncoder().encode(plainText);
            const ciphertext = await window.crypto.subtle.encrypt(
                { name: "AES-GCM", iv: iv },
                aesKey,
                encoded
            );
            return ciphertext;
        }

        const encryptedCryptoKey = await encryptText(exportedCryptoPrivateKeyString, aesKey, iv);
        const encryptedSignInKey = await encryptText(exportedSignInPrivateKeyString, aesKey, iv);

        const keysToStore = {
            cryptoKey: encryptedCryptoKey,
            signInKey: encryptedSignInKey,
            iv: Array.from(iv),
            salt: Array.from(salt)
        };

        await saveKeys(db, keysToStore);
        console.log("Keys saved successfully");

    } else {
        console.log("Keys already exist.");
        await decryptAndSaveToKeyStore();
    }
})();



