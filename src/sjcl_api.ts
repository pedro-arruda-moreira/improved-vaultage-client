
// tslint:disable-next-line:no-var-requires
const sjcl = require('../lib/sjcl') as any;

export type SJCL_AESMode = 'ccm' | 'gcm' | 'ocb2';

export type SJCL_AuthenticationDataHashSize = 64 | 96 | 128;

export type SJCL_KeySize = 128 | 192 | 256;

/**
 * Params for SJCL.
 */
export interface ISJCLParams {
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
     * Initialization Vector
     */
    salt?: string;
}

export function sjcl_encrypt(key: string, plain: string, params?: ISJCLParams): string {
    if (params) {
        const returningParams: ISJCLParams = {};
        const retVal = sjcl.encrypt(key, plain, params, returningParams);
        for (const field in params) {
            if (params[field] !== returningParams[field]) {
                throw new Error(`field ${field} does not match!`);
            }
        }
        return retVal;
    }
    return sjcl.encrypt(key, plain);
}

export function sjcl_decrypt(key: string, cipher: string): string {
    return sjcl.decrypt(key, cipher);
}

export function sjcl_sha512(password: string): number[] {
    return sjcl.hash.sha512.hash(password);
}

export function sjcl_pbkdf2(key: string | number[], salt: string, difficulty: number): number[] {
    return sjcl.misc.pbkdf2(key, salt, difficulty);
}

export function sjcl_hex_from_bits(bits: number[]): string {
    return sjcl.codec.hex.fromBits(bits);
}
