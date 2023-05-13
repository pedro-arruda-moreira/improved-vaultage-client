import { ICryptoAPI } from './CryptoAPI';
import { sjcl_sha512, sjcl_hex_from_bits, sjcl_pbkdf2 } from '../sjcl_api';

export class LegacyCryptoAPI implements ICryptoAPI {
    public deriveKey(password: string, salt: string, difficulty: number, useSha512: boolean): Promise<string> {
        const key = (useSha512 ? sjcl_sha512(password) : password);
        return Promise.resolve(sjcl_hex_from_bits(sjcl_pbkdf2(key, salt, difficulty)));
    }

}
