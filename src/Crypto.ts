import { CryptoOperation, getCryptoAPI, ICryptoParams, param2String, string2Param } from './crypto-impl/CryptoAPI';
import { ILog } from './ILog';
import { ISaltsConfig } from './interface';
import { ERROR_CODE, VaultageError } from './VaultageError';

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
    public static async deriveOfflineKey(masterPassword: string, offlineSalt: string, log: ILog): Promise<string> {
        return Crypto.tryDeriveWithBestApi(masterPassword, offlineSalt, OFFLINE_PBKDF2_DIFFICULTY, undefined, log);
    }

    private static async tryDeriveWithBestApi(password: string, salt: string, difficulty: number, useSha512: boolean = true, log: ILog) {
        return (await getCryptoAPI(CryptoOperation.DERIVE, log)).deriveKey(password, salt, difficulty, useSha512);
    }

    public PBKDF2_DIFFICULTY: number = 32768;

    constructor(
        private _salts: ISaltsConfig,
        private _log: ILog,
        private _sjclConfig?: ICryptoParams) {
    }

    /**
     * Returns the local key for a given LOCAL_KEY_SALT and master password.
     *
     * @param masterPassword Plaintext of the master password
     */
    public deriveLocalKey(masterPassword: string): Promise<string> {
        return Crypto.tryDeriveWithBestApi(masterPassword, this._salts.LOCAL_KEY_SALT, this.PBKDF2_DIFFICULTY, undefined, this._log);
    }

    /**
     * Returns the remote key for a given REMOTE_KEY_SALT and master password.
     *
     * @param masterPassword Plaintext of the master password
     */
    public deriveRemoteKey(masterPassword: string): Promise<string> {
        return Crypto.tryDeriveWithBestApi(masterPassword, this._salts.REMOTE_KEY_SALT, this.PBKDF2_DIFFICULTY, undefined, this._log);
    }

    /**
     * Performs the symetric encryption of a plaintext.
     *
     * Used to encrypt the vault's serialized data.
     *
     * @param localKey Local encryption key
     * @param plain The plaintext to encrypt
     */
    public async encrypt(localKey: string, plain: string): Promise<string> {
        const p = await (await getCryptoAPI(CryptoOperation.ENCRYPT, this._log, this._sjclConfig)).encrypt(
            plain,
            localKey,
            this._sjclConfig
        );
        return param2String(p);
    }

    /**
     * Performs the symetric decryption of a plaintext.
     *
     * Used to decrypt the vault's serialized data.
     *
     * @param localKey Local encryption key
     * @param cipher The ciphertext to encrypt
     */
    public async decrypt(localKey: string, cipher: string): Promise<string> {
        try {
            const param = string2Param(cipher);
            return (await getCryptoAPI(CryptoOperation.DECRYPT, this._log, param)).decrypt(localKey, param);
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
    public getFingerprint(plain: string, localKey: string): Promise<string> {
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
        return Crypto.tryDeriveWithBestApi(plain, localKey, this.PBKDF2_DIFFICULTY, false, this._log);
    }
}
