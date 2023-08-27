
// Utility functions

export function deepCopy<T>(source: T): T {
    // Probably one of the most inefficient way to perform a deep copy but at least it guarantees isolation,
    // is short and easy to understand, and works as long as we dont mess with non-primitive types
    return JSON.parse(JSON.stringify(source));
}


/** As seen on https://gist.github.com/jonleighton/958841, but modified for typescript.
 *
 * Converts an ArrayBuffer directly to base64, without any intermediate 'convert to string then
 * use window.btoa' step. According to my tests, this appears to be a faster approach:
 * http://jsperf.com/encoding-xhr-image-data/5
 *
 *
 * MIT LICENSE
 * Copyright 2011 Jon Leighton
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and
 * to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
function base64ArrayBuffer(arrayBuffer: ArrayBuffer): string {
    let base64 = '';
    const encodings = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

    const bytes = new Uint8Array(arrayBuffer);
    const byteLength = bytes.byteLength;
    const byteRemainder = byteLength % 3;
    const mainLength = byteLength - byteRemainder;

    let a: number;
    let b: number;
    let c: number;
    let d: number;
    let chunk: number;

    // Main loop deals with bytes in chunks of 3
    for (let i = 0; i < mainLength; i = i + 3) {
        // Combine the three bytes into a single integer
        // tslint:disable-next-line
        chunk = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];

        // Use bitmasks to extract 6-bit segments from the triplet
        // tslint:disable-next-line
        a = (chunk & 16515072) >> 18; // 16515072 = (2^6 - 1) << 18
        // tslint:disable-next-line
        b = (chunk & 258048) >> 12; // 258048   = (2^6 - 1) << 12
        // tslint:disable-next-line
        c = (chunk & 4032) >> 6; // 4032     = (2^6 - 1) << 6
        // tslint:disable-next-line
        d = chunk & 63;               // 63       = 2^6 - 1

        // Convert the raw binary segments to the appropriate ASCII encoding
        base64 += encodings[a] + encodings[b] + encodings[c] + encodings[d];
    }

    // Deal with the remaining bytes and padding
    if (byteRemainder === 1) {
        chunk = bytes[mainLength];
        // tslint:disable-next-line
        a = (chunk & 252) >> 2; // 252 = (2^6 - 1) << 2

        // Set the 4 least significant bits to zero
        // tslint:disable-next-line
        b = (chunk & 3) << 4; // 3   = 2^2 - 1

        base64 += encodings[a] + encodings[b] + '==';
    } else if (byteRemainder === 2) {
        // tslint:disable-next-line
        chunk = (bytes[mainLength] << 8) | bytes[mainLength + 1];
        // tslint:disable-next-line
        a = (chunk & 64512) >> 10; // 64512 = (2^6 - 1) << 10
        // tslint:disable-next-line
        b = (chunk & 1008) >> 4; // 1008  = (2^6 - 1) << 4

        // Set the 2 least significant bits to zero
        // tslint:disable-next-line
        c = (chunk & 15) << 2; // 15    = 2^4 - 1

        base64 += encodings[a] + encodings[b] + encodings[c] + '=';
    }

    return base64;
}
export { base64ArrayBuffer as arrayBufferToBase64String };

/**
 * As seen on https://stackoverflow.com/questions/21797299/convert-base64-string-to-arraybuffer, but modified for typescript.
 * @param base64 string in base64
 * @returns array buffer
 */
function base64ToArrayBuffer(base64: string) {
    const binaryString = fromBase64(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}
export { base64ToArrayBuffer as base64StringToArrayBuffer };

export const toBase64: (text: string) => string = (text) => {
    try {
        return btoa(text);
    } catch (e) {
        return Buffer.from(text).toString('base64');
    }
};

export const fromBase64: (text: string) => string = (b64) => {
    try {
        return atob(b64);
    } catch (e) {
        return Buffer.from(b64, 'base64').toString();
    }
};
