import { ICryptoAPI } from './CryptoAPI';

function createEncoder(): TextEncoder {
    try {
        return new window.TextEncoder();
    } catch (e) {
        // tslint:disable-next-line:no-var-requires
        return new (require('util').TextEncoder)() as TextEncoder;
    }
}

function getCrypto(): SubtleCrypto {
    try {
        return crypto.subtle;
    } catch (e) {
        // tslint:disable-next-line:no-var-requires
        return (require('crypto').webcrypto.subtle) as SubtleCrypto;
    }
}

function toHexString(bytes: Uint8Array) {
  return bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
}

/**
 * @param {string} strPassword The clear text password
 * @param {Uint8Array} salt    The salt
 * @param {string} hash        The Hash model, e.g. ["SHA-256" | "SHA-512"]
 * @param {int} iterations     Number of iterations
 * @param {int} len            The output length in bytes, e.g. 16
 */
async function pbkdf2(strPassword: string, salt: Uint8Array, hash: string, iterations: number, len: number): Promise<Uint8Array> {
    const password = createEncoder().encode(strPassword);

    const ik = await getCrypto().importKey('raw', password,
        'PBKDF2',
        false, ['deriveBits']
    );
    const dk = await getCrypto().deriveBits(
        {
            name: 'PBKDF2',
            hash: hash,
            salt: salt,
            iterations: iterations
        },
        ik,
        len * 8
    );  // Bytes to bits

    return new Uint8Array(dk);
}


export class FastCryptoAPI implements ICryptoAPI {
    public async deriveKey(password: string, salt: string, difficulty: number): Promise<string> {
        return toHexString(await pbkdf2(password, createEncoder().encode(salt), 'SHA-512', difficulty, 32));
    }
}
