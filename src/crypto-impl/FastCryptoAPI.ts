import { ILog } from '../ILog';
import { arrayBufferToBase64String, base64StringToArrayBuffer } from '../utils';
import { AESMode, AuthenticationDataHashSize, CipherType, ICryptoAPI, ICryptoParams, KeySize, Version } from './CryptoAPI';

type RequireFunction = (name: string) => any;

const AES_MODE: AESMode = 'gcm';
const ALGORITHM = 'AES-GCM';
const TAG_LENGTH: AuthenticationDataHashSize = 128;
const VERSION: Version = 1;
const AES_KEY_SIZE: KeySize = 256;
const MINIMAL_IV_SIZE = 12;
const CIPHER_TYPE: CipherType = 'aes';

const REQUIRE: RequireFunction = (() => {
    try {
        // tslint:disable-next-line
        return eval('require');
    } catch (e) {
        return (name) => {
            throw new Error(`require function not found! (tried to load module ${name})`);
        };
    }
})();

function createEncoder(): TextEncoder {
    try {
        return new window.TextEncoder();
    } catch (e) {
        return new (REQUIRE('util').TextEncoder)() as TextEncoder;
    }
}

function createDecoder(): TextDecoder {
    try {
        return new window.TextDecoder();
    } catch (e) {
        return new (REQUIRE('util').TextDecoder)() as TextDecoder;
    }
}

function getCrypto(): SubtleCrypto {
    try {
        return crypto.subtle;
    } catch (e) {
        return REQUIRE('crypto').webcrypto.subtle as SubtleCrypto;
    }
}

function randomValues(buff: Uint8Array): Uint8Array {
    try {
        return crypto.getRandomValues(buff);
    } catch (e) {
        return (REQUIRE('crypto').webcrypto.getRandomValues(buff)) as Uint8Array;
    }
}

function toHexString(bytes: Uint8Array) {
    return Buffer.from(bytes).toString('hex');
}

/**
 * Outside class for unit tests.
 * @param instance
 * @returns
 */
export function doInitialize(instance: FastCryptoAPI, log: ILog) {
    try {
        instance.cryptoInstance = getCrypto();
        instance.encoderInstance = createEncoder();
        instance.decoderInstance = createDecoder();
        randomValues(new Uint8Array(1));
        return instance.cryptoInstance != null && instance.encoderInstance != null && instance.decoderInstance != null;
    } catch (e) {
        log.error(() => 'Error during init.', e);
        return false;
    }
}

export class FastCryptoAPI implements ICryptoAPI {

    public cryptoInstance?: SubtleCrypto = undefined;

    public encoderInstance?: TextEncoder = undefined;

    public decoderInstance?: TextDecoder = undefined;

    constructor(
        private _log: ILog
    ) { }

    public async deriveKey(password: string, salt: string, difficulty: number, useSha512: boolean): Promise<string> {
        return toHexString(await this.pbkdf2(password, salt, 'SHA-256', difficulty, 32, useSha512));
    }

    public canDerive(): Promise<boolean> {
        return Promise.resolve(this.initialize());
    }

    public async encrypt(plain: string, key: string, params?: ICryptoParams): Promise<ICryptoParams> {
        const encoder = this.encoderInstance as TextEncoder;
        const crypto = this.cryptoInstance as SubtleCrypto;
        let iterations: number;
        if (params && params!!.iter) {
            iterations = params!!.iter!!;
        } else {
            iterations = 32768;
        }
        let salt: ArrayBuffer;
        if (params && params!!.salt) {
            salt = base64StringToArrayBuffer(params!!.salt!!);
        } else {
            salt = randomValues(new Uint8Array(8));
        }
        let adata: ArrayBuffer | undefined;
        if (params && params!!.adata) {
            adata = encoder.encode(params!!.adata!!);
        } else {
            adata = undefined;
        }
        const keyArray = await this.pbkdf2(key, salt, 'SHA-256', iterations, AES_KEY_SIZE / 8, false);
        const importedKey = await crypto.importKey('raw', keyArray, {
            name: ALGORITHM
        } as AesKeyAlgorithm, false, ['encrypt']);
        let ivArray: ArrayBuffer;
        if (params && params!!.iv) {
            ivArray = base64StringToArrayBuffer(params!!.iv!!);
        } else {
            ivArray = randomValues(new Uint8Array(MINIMAL_IV_SIZE));
        }
        const aesParams: AesGcmParams = {
            name: ALGORITHM,
            iv: ivArray,
            tagLength: TAG_LENGTH
        };
        if (adata !== undefined) {
            aesParams.additionalData = adata;
        }
        const cryptoResult = await crypto.encrypt(
            aesParams,
            importedKey,
            encoder.encode(plain)
        );
        const result = {} as ICryptoParams;
        result.ct = arrayBufferToBase64String(cryptoResult);
        result.iv = arrayBufferToBase64String(ivArray);
        result.salt = arrayBufferToBase64String(salt);
        result.v = VERSION;
        result.iter = iterations;
        result.ks = AES_KEY_SIZE;
        result.mode = AES_MODE;
        result.ts = TAG_LENGTH;
        result.cipher = CIPHER_TYPE;
        if (adata) {
            result.adata = arrayBufferToBase64String(adata);
        } else {
            result.adata = '';
        }
        return Promise.resolve(result);
    }

    public description(): string {
        return 'FAST';
    }

    public canEncrypt(params?: ICryptoParams): Promise<boolean> {
        return Promise.resolve(this.canEncryptOrDecrypt(params));
    }

    public async decrypt(key: string, params: ICryptoParams): Promise<string> {
        if (!params.ct) {
            throw new Error('cipher text not specified!');
        }
        if (!params.ts) {
            throw new Error('tag length not specified!');
        }
        const crypto = this.cryptoInstance as SubtleCrypto;
        let iterations: number;
        if (params.iter) {
            iterations = params.iter!!;
        } else {
            throw new Error('iterations not specified!');
        }
        let keyLen: number;
        if (params.ks) {
            keyLen = params.ks!!;
        } else {
            throw new Error('key size not specified!');
        }
        let salt: ArrayBuffer;
        if (params.salt) {
            salt = base64StringToArrayBuffer(params.salt!!);
        } else {
            throw new Error('salt not specified!');
        }
        let adata: ArrayBuffer | undefined;
        if (params.adata) {
            adata = base64StringToArrayBuffer(params!!.adata!!);
        } else {
            adata = undefined;
        }
        const keyArray = await this.pbkdf2(key, salt, 'SHA-256', iterations, keyLen / 8, false);
        const importedKey = await crypto.importKey('raw', keyArray, {
            name: ALGORITHM
        } as AesKeyAlgorithm, false, ['decrypt']);
        let ivArray: ArrayBuffer;
        if (params.iv) {
            ivArray = base64StringToArrayBuffer(params!!.iv!!);
        } else {
            throw new Error('IV not specified!');
        }
        const aesParams: AesGcmParams = {
            name: ALGORITHM,
            iv: ivArray,
            tagLength: params.ts!!
        };
        if (adata !== undefined) {
            aesParams.additionalData = adata;
        }
        const cryptoResult = await crypto.decrypt(
            aesParams,
            importedKey,
            base64StringToArrayBuffer(params.ct!!)
        );
        return this.decoderInstance!!.decode(cryptoResult);
    }

    public canDecrypt(params: ICryptoParams): Promise<boolean> {
        return Promise.resolve(this.canEncryptOrDecrypt(params));
    }


    private initialize(): boolean {
        return doInitialize(this, this._log);
    }

    private canEncryptOrDecrypt(params?: ICryptoParams): boolean {
        let able = true;
        if (params !== undefined) {
            if (params.mode !== undefined && params.mode !== AES_MODE) {
                this._log.error(() => 'failed on mode');
                able = false;
            }
            if (params.iv !== undefined && base64StringToArrayBuffer(params.iv).byteLength < MINIMAL_IV_SIZE) {
                this._log.error(() => 'failed on IV');
                able = false;
            }
        }
        return able && this.initialize();
    }

    /**
     * @param {string} strPassword The clear text password
     * @param {string} salt        The salt
     * @param {string} hash        The Hash model, e.g. ["SHA-256" | "SHA-512"]
     * @param {int} iterations     Number of iterations
     * @param {int} len            The output length in bytes, e.g. 16
     * @param {int} useSha512      Use additional SHA-512 before pbkdf2.
     */
    private async pbkdf2(strPassword: string, salt: string | ArrayBuffer, hash: string,
                         iterations: number, len: number, useSha512: boolean): Promise<Uint8Array> {
        const encoder = this.encoderInstance as TextEncoder;
        const crypto = this.cryptoInstance as SubtleCrypto;

        let dataArray: Uint8Array = encoder.encode(strPassword);
        if (useSha512) {
            dataArray = new Uint8Array(await crypto.digest('SHA-512', dataArray));
        }
        let saltBuffer: ArrayBuffer;
        if (typeof (salt) === 'string') {
            saltBuffer = encoder.encode(salt);
        } else {
            saltBuffer = salt;
        }


        const importedKey = await crypto.importKey('raw', dataArray, 'PBKDF2', false, ['deriveBits']);
        const derivedKey = await crypto.deriveBits(
            {
                name: 'PBKDF2',
                hash: hash,
                salt: saltBuffer,
                iterations: iterations
            },
            importedKey,
            len * 8
        );  // Bytes to bits

        return new Uint8Array(derivedKey);
    }
}
