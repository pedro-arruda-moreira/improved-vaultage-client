import { arrayBufferToBase64String, base64StringToArrayBuffer } from '../utils';
import { ICryptoAPI, ISJCLParams } from './CryptoAPI';

const ALGORITHM = 'AES-GCM';
const TAG_LENGTH = 128;
const VERSION = 1;
const AES_KEY_SIZE = 256;

function createEncoder(): TextEncoder {
    try {
        return new window.TextEncoder();
    } catch (e) {
        // tslint:disable-next-line
        return new (eval('require(\'util\')').TextEncoder)() as TextEncoder;
    }
}

function createDecoder(): TextDecoder {
    try {
        return new window.TextDecoder();
    } catch (e) {
        // tslint:disable-next-line
        return new (eval('require(\'util\')').TextDecoder)() as TextDecoder;
    }
}

function getCrypto(): SubtleCrypto {
    try {
        return crypto.subtle;
    } catch (e) {
        // tslint:disable-next-line
        return (eval('require(\'crypto\')').webcrypto.subtle) as SubtleCrypto;
    }
}

function randomValues(buff: Uint8Array): Uint8Array {
    try {
        return crypto.getRandomValues(buff);
    } catch (e) {
        // tslint:disable-next-line
        return (eval('require(\'crypto\')').webcrypto.getRandomValues(buff)) as Uint8Array;
    }
}

function toHexString(bytes: Uint8Array) {
    return bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
}

/**
 * Outside class for unit tests.
 * @param instance
 * @returns
 */
export function doInitialize(instance: FastCryptoAPI) {
    try {
        instance.cryptoInstance = getCrypto();
        instance.encoderInstance = createEncoder();
        instance.decoderInstance = createDecoder();
        randomValues(new Uint8Array(1));
        return instance.cryptoInstance != null && instance.encoderInstance != null && instance.decoderInstance != null;
    } catch (e) {
        console.error(e);
        return false;
    }
}

export class FastCryptoAPI implements ICryptoAPI {

    public cryptoInstance?: SubtleCrypto = undefined;

    public encoderInstance?: TextEncoder = undefined;

    public decoderInstance?: TextDecoder = undefined;

    public async deriveKey(password: string, salt: string, difficulty: number, useSha512: boolean): Promise<string> {
        return toHexString(await this.pbkdf2(password, salt, 'SHA-256', difficulty, 32, useSha512));
    }

    public canDerive(): Promise<boolean> {
        return Promise.resolve(this.initialize());
    }

    public async encrypt(plain: string, key: string, params?: ISJCLParams): Promise<ISJCLParams> {
        const encoder = this.encoderInstance as TextEncoder;
        const crypto = this.cryptoInstance as SubtleCrypto;
        let iterations: number;
        if (params && params!!.iter) {
            iterations = params!!.iter!!;
        } else {
            iterations = 10000;
        }
        let salt: ArrayBuffer;
        if (params && params!!.salt) {
            salt = base64StringToArrayBuffer(params!!.salt!!);
        } else {
            salt = randomValues(new Uint8Array(8));
        }
        const keyArray = await this.pbkdf2(key, salt, 'SHA-256', iterations, AES_KEY_SIZE / 8, false);
        const importedKey = await crypto.importKey('raw', keyArray, {
            name: ALGORITHM
        } as AesKeyAlgorithm, false, ['encrypt']);
        let ivArray: ArrayBuffer;
        if (params && params!!.iv) {
            ivArray = base64StringToArrayBuffer(params!!.iv!!);
        } else {
            ivArray = randomValues(new Uint8Array(12));
        }
        const cryptoResult = await crypto.encrypt(
            {
                name: ALGORITHM,
                iv: ivArray,
                tagLength: TAG_LENGTH
            },
            importedKey,
            encoder.encode(plain)
        );
        const result = {} as ISJCLParams;
        result.ct = arrayBufferToBase64String(cryptoResult);
        result.iv = arrayBufferToBase64String(ivArray);
        result.salt = arrayBufferToBase64String(salt);
        result.v = VERSION;
        result.iter = iterations;
        result.ks = AES_KEY_SIZE;
        result.mode = 'gcm';
        result.ts = TAG_LENGTH;
        result.cipher = 'aes';
        result.adata = '';
        return Promise.resolve(result);
    }

    public description(): string {
        return 'FAST';
    }

    public canEncrypt(params?: ISJCLParams): Promise<boolean> {
        return Promise.resolve(this.canEncryptOrDecrypt(params));
    }

    public async decrypt(key: string, params: ISJCLParams): Promise<string> {
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
            keyLen = AES_KEY_SIZE;
        }
        let salt: ArrayBuffer;
        if (params.salt) {
            salt = base64StringToArrayBuffer(params.salt!!);
        } else {
            throw new Error('salt not specified!');
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
        const cryptoResult = await crypto.decrypt(
            {
                name: ALGORITHM,
                iv: ivArray,
                tagLength: params.ts!!
            },
            importedKey,
            base64StringToArrayBuffer(params.ct!!)
        );
        return this.decoderInstance!!.decode(cryptoResult);
    }

    public canDecrypt(params: ISJCLParams): Promise<boolean> {
        return Promise.resolve(this.canEncryptOrDecrypt(params));
    }


    private initialize(): boolean {
        return doInitialize(this);
    }

    private canEncryptOrDecrypt(params?: ISJCLParams): boolean {
        let able = this.initialize();
        if (params === undefined) {
            return able;
        }
        if (params.mode !== undefined && params.mode !== 'gcm') {
            able = false;
        }
        if (params.adata !== undefined && params.adata !== '') {
            able = false;
        }
        if (params.iv !== undefined && base64StringToArrayBuffer(params.iv).byteLength !== 12) {
            able = false;
        }
        if (params.ts !== undefined && params.ts !== 128) {
            able = false;
        }
        return able;
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
