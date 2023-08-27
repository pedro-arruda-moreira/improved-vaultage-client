import { ICryptoAPI, ISJCLParams, param2String, string2Param } from './CryptoAPI';


// tslint:disable-next-line:no-var-requires
const sjcl = require('../../lib/sjcl') as any;


function sjcl_encrypt(key: string, plain: string, params?: ISJCLParams): string {
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

function sjcl_decrypt(key: string, cipher: string): string {
    return sjcl.decrypt(key, cipher);
}

function sjcl_sha512(password: string): number[] {
    return sjcl.hash.sha512.hash(password);
}

function sjcl_pbkdf2(key: string | number[], salt: string, difficulty: number): number[] {
    return sjcl.misc.pbkdf2(key, salt, difficulty);
}

function sjcl_hex_from_bits(bits: number[]): string {
    return sjcl.codec.hex.fromBits(bits);
}


export class LegacyCryptoAPI implements ICryptoAPI {
    public deriveKey(password: string, salt: string, difficulty: number, useSha512: boolean): Promise<string> {
        const key = (useSha512 ? sjcl_sha512(password) : password);
        return Promise.resolve(sjcl_hex_from_bits(sjcl_pbkdf2(key, salt, difficulty)));
    }

    public canDerive(): Promise<boolean> {
        return Promise.resolve(true);
    }

    public encrypt(plain: string, key: string, params?: ISJCLParams): Promise<ISJCLParams> {
        const result = sjcl_encrypt(key, plain, params);
        return Promise.resolve(string2Param(result));
    }

    public canEncrypt(_: ISJCLParams): Promise<boolean> {
        return Promise.resolve(true);
    }

    public decrypt(key: string, cipher: ISJCLParams): Promise<string> {
        return Promise.resolve(sjcl_decrypt(key, param2String(cipher)));
    }

    public canDecrypt(_: ISJCLParams): Promise<boolean> {
        return Promise.resolve(true);
    }

    public description(): string {
        return 'LEGACY';
    }

}
