import { FastCryptoAPI, doInitialize } from 'improved-vaultage-client/src/crypto-impl/FastCryptoAPI';
import { LegacyCryptoAPI } from 'improved-vaultage-client/src/crypto-impl/LegacyCryptoAPI';
import { Crypto } from '../src/Crypto';
import { ConsoleLog } from 'improved-vaultage-client/src/vaultage';

function generateString(len: number) {
    return Math.random().toString(36).substr(2, 2 + len);
}

const DIFFICULTY = 1;

const REMOTE_SALT = '0123456789';
const LOCAL_SALT = 'deadbeef';
const OFFLINE_SALT = 'my-offline-salt123';

const EXPECTED_LOCAL_KEY = '93ff3db4b46bf6e63885f0d37efcac689970947c49cd9a04e66cace32b258b0e';
const EXPECTED_REMOTE_KEY = '8aefc63391ce6eb2e706bf92d0af026189adfe02d2bc757ca5511112c8bdb2a8';
const EXPECTED_OFFLINE_KEY = '8a895f56fe4d16e2b88480e500ae6c195c2a7318c72aebf0642fb0a24bdbde6f';

const EXPECTED_FINGERPRINT = '26cf88bef1397343f38ebdef0452bef1a744a3fbefd3248f1095e73b3dec6e46';

const ADDITIONAL_DATA = 'blah blah';

function createFastCrypto() {
    const instance = new FastCryptoAPI(ConsoleLog.INSTANCE);
    doInitialize(instance, ConsoleLog.INSTANCE);
    return instance;
}

describe('Crypto.ts', () => {
    let crypto: Crypto;

    beforeEach(() => {
        crypto = new Crypto({
            LOCAL_KEY_SALT: LOCAL_SALT,
            REMOTE_KEY_SALT: REMOTE_SALT
        },
        ConsoleLog.INSTANCE);
        crypto.PBKDF2_DIFFICULTY = DIFFICULTY;
    });

    describe('the key derivation function', () => {
        const masterKey = 'ucantseeme';
        it('gives a consistent local key - Crypto', async () => {
            const localKey = crypto.deriveLocalKey(masterKey);
            expect(await localKey).toEqual(EXPECTED_LOCAL_KEY);
        });
        it('gives a consistent remote key - Crypto', async () => {
            const remoteKey = crypto.deriveRemoteKey(masterKey);
            expect(await remoteKey).toEqual(EXPECTED_REMOTE_KEY);
        });
        it('gives a consistent offline key - Crypto', async () => {
            const offlineKey = Crypto.deriveOfflineKey(masterKey, OFFLINE_SALT, ConsoleLog.INSTANCE);
            expect(await offlineKey).toEqual(EXPECTED_OFFLINE_KEY);
        });
        it('gives a consistent local key - Legacy', async () => {
            const localKey = new LegacyCryptoAPI().deriveKey(masterKey, LOCAL_SALT, DIFFICULTY, true);
            expect(await localKey).toEqual(EXPECTED_LOCAL_KEY);
        });
        it('gives a consistent remote key - Legacy', async () => {
            const remoteKey = new LegacyCryptoAPI().deriveKey(masterKey, REMOTE_SALT, DIFFICULTY, true);
            expect(await remoteKey).toEqual(EXPECTED_REMOTE_KEY);
        });
        it('gives a consistent local key - Fast', async () => {
            const localKey = createFastCrypto().deriveKey(masterKey, LOCAL_SALT, DIFFICULTY, true);
            expect(await localKey).toEqual(EXPECTED_LOCAL_KEY);
        });
        it('gives a consistent remote key - Fast', async () => {
            const remoteKey = createFastCrypto().deriveKey(masterKey, REMOTE_SALT, DIFFICULTY, true);
            expect(await remoteKey).toEqual(EXPECTED_REMOTE_KEY);
        });
    });

    describe('the encryption/decryption pair', () => {
        for (let i = 0; i < 10; i++) {
            const localKey = generateString(20);
            const plaintext = generateString(2000);
            const fast = createFastCrypto();
            const legacy = new LegacyCryptoAPI();

            it('work together', async () => {
                const cipher = await crypto.encrypt(localKey, plaintext);
                const decoded = await crypto.decrypt(localKey, cipher);
                expect(plaintext).toEqual(decoded);
            });

            it('is not the identity function', async () => {
                const cipher = await crypto.encrypt(localKey, plaintext);
                expect(plaintext).not.toEqual(cipher);
            });

            it('works with legacy and fast together.', async () => {
                const cipher1 = await fast.encrypt(plaintext, localKey);
                console.log(cipher1);
                expect(plaintext).not.toEqual(cipher1);
                const plain1 = await legacy.decrypt(localKey, cipher1);
                console.log(plain1);
                expect(plaintext).toEqual(plain1);
                const cipher2 = await legacy.encrypt(plain1, localKey, {
                    mode: 'gcm',
                    ts: 128,
                    ks: 192
                });
                console.log(cipher2);
                expect(plaintext).not.toEqual(cipher2);
                expect(cipher1).not.toEqual(cipher2);
                const plain2 = await fast.decrypt(localKey, cipher2);
                console.log(plain2);
                expect(plaintext).toEqual(plain2);
            });

            it('works with legacy and fast together with adata.', async () => {
                console.log(ADDITIONAL_DATA);
                const cipher1 = await fast.encrypt(plaintext, localKey, {
                    adata: ADDITIONAL_DATA
                });
                console.log(cipher1);
                expect(plaintext).not.toEqual(cipher1);
                const plain1 = await legacy.decrypt(localKey, cipher1);
                console.log(plain1);
                expect(plaintext).toEqual(plain1);
                const cipher2 = await legacy.encrypt(plain1, localKey, {
                    mode: 'gcm',
                    ts: 128,
                    ks: 192,
                    adata: ADDITIONAL_DATA
                });
                console.log(cipher2);
                expect(plaintext).not.toEqual(cipher2);
                expect(cipher1).not.toEqual(cipher2);
                const plain2 = await fast.decrypt(localKey, cipher2);
                console.log(plain2);
                expect(plaintext).toEqual(plain2);
                expect(plain1).toEqual(plain2);
            });
        }
    });

    describe('the key derivation works with encryption and decryption', () => {
        for (let i = 0; i < 10; i++) {
            it('work together', async () => {
                const masterKey = generateString(20);
                const localKey = crypto.deriveLocalKey(masterKey);
                const plaintext = generateString(2000);
                const cipher = await crypto.encrypt(await localKey, plaintext);
                const decoded = await crypto.decrypt(await localKey, cipher);
                expect(plaintext).toEqual(decoded);
            });
        }
    });

    describe('the fingerprint function', () => {
        for (let i = 0; i < 10; i++) {
            const database = generateString(2000);
            const masterKey = generateString(20);
            it('works on a random database', async () => {
                const localKey = crypto.deriveLocalKey(masterKey);
                const fingerprint = await crypto.getFingerprint(await localKey, database);
                expect(fingerprint).not.toEqual(database);
            });
            it('is deterministic', async () => {
                const localKey = crypto.deriveLocalKey(masterKey);
                const fingerprint = await crypto.getFingerprint(await localKey, database);
                const fingerprint2 = await crypto.getFingerprint(await localKey, database);
                expect(fingerprint).toEqual(fingerprint2);
            });
            it('REALLY is deterministic', async () => {
                const myDatabase = '{}';
                const myMasterKey = 'DETERMINISTIC!';
                const localKey = await crypto.deriveLocalKey(myMasterKey);
                const fingerprint = await crypto.getFingerprint(myDatabase, localKey);
                const fingerprint2 = await crypto.getFingerprint(myDatabase, localKey);
                const legacyFingerprint = await new LegacyCryptoAPI().deriveKey(myDatabase,
                    localKey,
                    crypto.PBKDF2_DIFFICULTY,
                    false);
                const fastFingerprint = await createFastCrypto().deriveKey(myDatabase, localKey, crypto.PBKDF2_DIFFICULTY, false);
                expect(legacyFingerprint).toEqual(EXPECTED_FINGERPRINT);
                expect(fastFingerprint).toEqual(EXPECTED_FINGERPRINT);
                expect(fingerprint).toEqual(EXPECTED_FINGERPRINT);
                expect(fingerprint2).toEqual(EXPECTED_FINGERPRINT);
                expect(fingerprint2).toEqual(fingerprint);
            });
            it('depends on the local key', async () => {
                const localKey = crypto.deriveLocalKey(masterKey);
                const localKey2 = crypto.deriveLocalKey(masterKey + '2');
                const fingerprint = await crypto.getFingerprint(await localKey, database);
                const fingerprint2 = await crypto.getFingerprint(await localKey2, database);
                expect(fingerprint).not.toEqual(fingerprint2);
            });
        }
    });
});
