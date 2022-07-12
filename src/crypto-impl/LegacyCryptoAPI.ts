import { ICryptoAPI } from './CryptoAPI';

// tslint:disable-next-line:no-var-requires
const sjcl = require('../../lib/sjcl') as any;
export class LegacyCryptoAPI implements ICryptoAPI {
    public deriveKey(password: string, salt: string, difficulty: number, useSha512: boolean): Promise<string> {
        const key = (useSha512 ? sjcl.hash.sha512.hash(password) : password);
        return Promise.resolve(sjcl.codec.hex.fromBits(sjcl.misc.pbkdf2(key, salt, difficulty)));
    }

}
