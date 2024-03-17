import { ILog } from '../ILog';
import { FastCryptoAPI } from './FastCryptoAPI';
import { LegacyCryptoAPI } from './LegacyCryptoAPI';

export type AESMode = 'ccm' | 'gcm' | 'ocb2';

export type AuthenticationDataHashSize = 64 | 96 | 128;

export type KeySize = 128 | 192 | 256;

export type Version = 1;

export type CipherType = 'aes';


/**
 * Params for SJCL.
 */
export interface ICryptoParams {
    /**
     * Cipher type (must be always 'aes')
     */
    cipher?: CipherType;

    /**
     * Version (must be always 1)
     */
    v?: Version;

    /**
     * Additional data
     */
    adata?: string;

    /**
     * Number of iterations
     */
    iter?: number;

    /**
     * AES mode
     */
    mode?: AESMode;

    /**
     * Authentication data (Tag) hash size
     */
    ts?: AuthenticationDataHashSize;

    /**
     * key size
     */
    ks?: KeySize;

    /**
     * Initialization Vector
     */
    iv?: string;

    /**
     * Salt
     */
    salt?: string;

    /**
     * cipher Text
     */
    ct?: string;
}

export enum CryptoOperation {
    DERIVE,
    ENCRYPT,
    DECRYPT
}

export interface ICryptoAPI {
    deriveKey(password: string, salt: string, difficulty: number, useSha512: boolean): Promise<string>;
    canDerive(): Promise<boolean>;

    encrypt(plain: string, key: string, params?: ICryptoParams): Promise<ICryptoParams>;
    canEncrypt(params?: ICryptoParams): Promise<boolean>;

    decrypt(key: string, cipher: ICryptoParams): Promise<string>;
    canDecrypt(params: ICryptoParams): Promise<boolean>;

    description(): string;
}


export async function getCryptoAPI(op: CryptoOperation, log: ILog, params?: ICryptoParams): Promise<ICryptoAPI> {
    const availableApis = [
        new FastCryptoAPI(log),
        new LegacyCryptoAPI()
    ] as ICryptoAPI[];
    for (const api of availableApis) {
        if (op === CryptoOperation.DERIVE) {
            if (await api.canDerive()) {
                return api;
            }
        } else if (op === CryptoOperation.ENCRYPT) {
            if (await api.canEncrypt(params)) {
                return api;
            }
        } else {
            if (await api.canDecrypt(params!!)) {
                return api;
            }
        }
        log.error(() => `ICryptoAPI '${api.description()}' is not capable of ${op === 1 ? 'ENCRYPT' : (op === 0 ? 'DERIVE' : 'DECRYPT')} with params ${param2String(params)}`);
    }
    throw new Error('unable to find a ICryptoAPI');
}

export function param2String(param?: ICryptoParams): string {
    return JSON.stringify(param);
}

export function string2Param(str: string): ICryptoParams {
    return JSON.parse(str) as ICryptoParams;
}
