import { FastCryptoAPI } from './crypto-impl/FastCryptoAPI';
import { LegacyCryptoAPI } from './crypto-impl/LegacyCryptoAPI';
import { ISaltsConfig } from './interface';
import { ERROR_CODE, VaultageError } from './VaultageError';

// tslint:disable-next-line:no-var-requires
const sjcl = require('../lib/sjcl') as any;

// pedro-arruda-moreira: offline mode support
const OFFLINE_PBKDF2_DIFFICULTY: number = 1048576;
/**
 * Handles the crypto stuff
 */
export class Crypto {

    // pedro-arruda-moreira: offline mode support
    /**
     * Returns the offline key for a given offline salt and master password.
     *
     * @param masterPassword Plaintext of the master password
     * @param offlineSalt the offline salt
     */
    public static async deriveOfflineKey(masterPassword: string, offlineSalt: string): Promise<string> {
        return Crypto.tryDeriveWithBestApi(masterPassword, offlineSalt, OFFLINE_PBKDF2_DIFFICULTY);
    }

    private static tryDeriveWithBestApi(password: string, salt: string, difficulty: number) {
        try {
            return new FastCryptoAPI().deriveKey(password, salt, difficulty);
        } catch (e) {
            return new LegacyCryptoAPI().deriveKey(password, salt, difficulty);
        }
    }

    public PBKDF2_DIFFICULTY: number = 32768;

    constructor(
        private _salts: ISaltsConfig) {
    }

    /**
     * Returns the local key for a given LOCAL_KEY_SALT and master password.
     *
     * @param masterPassword Plaintext of the master password
     */
    public deriveLocalKey(masterPassword: string): Promise<string> {
        return Crypto.tryDeriveWithBestApi(masterPassword, this._salts.LOCAL_KEY_SALT, this.PBKDF2_DIFFICULTY);
    }

    /**
     * Returns the remote key for a given REMOTE_KEY_SALT and master password.
     *
     * @param masterPassword Plaintext of the master password
     */
    public deriveRemoteKey(masterPassword: string): Promise<string> {
        return Crypto.tryDeriveWithBestApi(masterPassword, this._salts.REMOTE_KEY_SALT, this.PBKDF2_DIFFICULTY);
    }

    /**
     * Performs the symetric encryption of a plaintext.
     *
     * Used to encrypt the vault's serialized data.
     *
     * @param localKey Local encryption key
     * @param plain The plaintext to encrypt
     */
    public encrypt(localKey: string, plain: string): string {
        return sjcl.encrypt(localKey, plain);
    }

    /**
     * Performs the symetric decryption of a plaintext.
     *
     * Used to decrypt the vault's serialized data.
     *
     * @param localKey Local encryption key
     * @param cipher The ciphertext to encrypt
     */
    public decrypt(localKey: string, cipher: string): string {
        try {
            return sjcl.decrypt(localKey, cipher);
        } catch (e) {
            throw new VaultageError(ERROR_CODE.CANNOT_DECRYPT, 'An error occurred while decrypting the cipher', e);
        }
    }

    /**
     * Computes the fingerprint of a plaintext.
     *
     * Used to prove to our past-self that we have access to the local key and the latest
     * vault's plaintext and challenge our future-self to do the same.
     *
     * @param plain the serialized vault's plaintext
     * @param localKey the local key
     */
    public getFingerprint(plain: string, localKey: string): string {
        // We want to achieve two results:
        // 1. Ensure that we don't push old content over some newer content
        // 2. Prevent unauthorized pushes even if the remote key was compromized
        //
        // For 1, we need to fingerprint the plaintext of the DB as well as the local key.
        // Without the local key we could not detect when the local key changed and
        // might overwrite a DB that was re-encrypted with a new local password.
        //
        // The localKey is already derived from the username, some per-deployment salt and
        // the master password so using it as a salt here should be enough to show that we know
        // all of the above information.
        return sjcl.codec.hex.fromBits(sjcl.misc.pbkdf2(plain, localKey, this.PBKDF2_DIFFICULTY));
    }
}
