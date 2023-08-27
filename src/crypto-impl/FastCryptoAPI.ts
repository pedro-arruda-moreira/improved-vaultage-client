import { arrayBufferToBase64String, base64StringToArrayBuffer } from '../utils';
import { ICryptoAPI, ISJCLParams } from './CryptoAPI';

function createEncoder(): TextEncoder {
    try {
        return new window.TextEncoder();
    } catch (e) {
        // tslint:disable-next-line
        return new (eval('require(\'util\')').TextEncoder)() as TextEncoder;
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
        return (eval('require(\'crypto\')').getRandomValues(buff)) as Uint8Array;
    }
}

function toHexString(bytes: Uint8Array) {
    return bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
}

export class FastCryptoAPI implements ICryptoAPI {

    private cryptoInstance?: SubtleCrypto = undefined;

    private encoderInstance?: TextEncoder = undefined;

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
        const keyArray: Uint8Array = await this.pbkdf2(key, salt, 'SHA-256', iterations, 32, false);
        const importedKey = await crypto.importKey('raw', keyArray, {
            name: 'AES'
        } as AesKeyAlgorithm, false, ['encrypt']);
        let ivArray: ArrayBuffer;
        if (params && params!!.iv) {
            ivArray = base64StringToArrayBuffer(params!!.iv!!);
        } else {
            ivArray = randomValues(new Uint8Array(12));
        }
        const cryptoResult = await crypto.encrypt(
            {
                name: 'AES-GCM',
                iv: ivArray
            },
            importedKey,
            encoder.encode(plain)
        );
        const paramsCopy = {} as ISJCLParams;
        paramsCopy.ct = arrayBufferToBase64String(cryptoResult);
        paramsCopy.iv = arrayBufferToBase64String(ivArray);
        paramsCopy.salt = arrayBufferToBase64String(salt);
        paramsCopy.v = 1;
        paramsCopy.iter = iterations;
        paramsCopy.ks = 256;
        paramsCopy.mode = 'gcm';
        paramsCopy.ts = 64;
        paramsCopy.cipher = 'aes';
        paramsCopy.adata = '';
        return Promise.resolve(paramsCopy);
    }

    public canEncrypt(params?: ISJCLParams): Promise<boolean> {
        return Promise.resolve(this.canEncryptOrDecrypt(params));
    }

    public async decrypt(_: string, __: ISJCLParams): Promise<string> {
        throw new Error('bla');
    }

    public canDecrypt(params: ISJCLParams): Promise<boolean> {
        return Promise.resolve(this.canEncryptOrDecrypt(params));
    }


    private initialize(): boolean {
        try {
            this.cryptoInstance = getCrypto();
            this.encoderInstance = createEncoder();
            randomValues(new Uint8Array(1));
            return this.cryptoInstance != null && this.encoderInstance != null;
        } catch (e) {
            return false;
        }
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
        if (params.ts !== undefined && params.ts !== 64) {
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
