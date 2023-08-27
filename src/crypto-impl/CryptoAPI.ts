import { FastCryptoAPI } from './FastCryptoAPI';
import { LegacyCryptoAPI } from './LegacyCryptoAPI';

export type SJCL_AESMode = 'ccm' | 'gcm' | 'ocb2';

export type SJCL_AuthenticationDataHashSize = 64 | 96 | 128;

export type SJCL_KeySize = 128 | 192 | 256;


/**
 * Params for SJCL.
 */
export interface ISJCLParams {
    /**
     * Cipher type (must be always 'aes')
     */
    cipher?: string;

    /**
     * Version (must be always 1)
     */
    v?: number;

    /**
     * Authentication data
     */
    adata?: string;

    /**
     * Number of iterations
     */
    iter?: number;

    /**
     * AES mode
     */
    mode?: SJCL_AESMode;

    /**
     * Authentication data hash size
     */
    ts?: SJCL_AuthenticationDataHashSize;

    /**
     * key size
     */
    ks?: SJCL_KeySize;

    /**
     * Initialization Vector
     */
    iv?: string;

    /**
     * Salt
     */
    salt?: string;

    /**
     * Cypher Text
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

    encrypt(plain: string, key: string, params?: ISJCLParams): Promise<ISJCLParams>;
    canEncrypt(params?: ISJCLParams): Promise<boolean>;

    decrypt(key: string, cypher: ISJCLParams): Promise<string>;
    canDecrypt(params: ISJCLParams): Promise<boolean>;
}


export async function getCryptoAPI(op: CryptoOperation, params?: ISJCLParams): Promise<ICryptoAPI> {
    const availableApis = [
        new FastCryptoAPI(),
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
    }
    throw new Error('unable to find a ICryptoAPI');
}

export function param2String(param: ISJCLParams): string {
    return JSON.stringify(param);
}

export function string2Param(str: string): ISJCLParams {
    return JSON.parse(str) as ISJCLParams;
}
