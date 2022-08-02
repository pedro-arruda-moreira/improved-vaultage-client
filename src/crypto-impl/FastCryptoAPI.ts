import { ICryptoAPI } from './CryptoAPI';

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

function toHexString(bytes: Uint8Array) {
  return bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
}

/**
 * @param {string} strPassword The clear text password
 * @param {string} salt    The salt
 * @param {string} hash        The Hash model, e.g. ["SHA-256" | "SHA-512"]
 * @param {int} iterations     Number of iterations
 * @param {int} len            The output length in bytes, e.g. 16
 */
async function pbkdf2(strPassword: string, salt: string, hash: string,
                      iterations: number, len: number, useSha512: boolean): Promise<Uint8Array> {
    const encoder = createEncoder();
    const crypto = getCrypto();

    let dataArray: Uint8Array = encoder.encode(strPassword);
    if (useSha512) {
        dataArray = new Uint8Array(await crypto.digest('SHA-512', dataArray));
    }


    const importedKey = await crypto.importKey('raw', dataArray, 'PBKDF2', false, ['deriveBits']);
    const derivedKey = await crypto.deriveBits(
        {
            name: 'PBKDF2',
            hash: hash,
            salt: encoder.encode(salt),
            iterations: iterations
        },
        importedKey,
        len * 8
    );  // Bytes to bits

    return new Uint8Array(derivedKey);
}


export class FastCryptoAPI implements ICryptoAPI {
    public async deriveKey(password: string, salt: string, difficulty: number, useSha512: boolean): Promise<string> {
        return toHexString(await pbkdf2(password, salt, 'SHA-256', difficulty, 32, useSha512));
    }
}
