
// Utility functions

export function deepCopy<T>(source: T): T {
    // Probably one of the most inefficient way to perform a deep copy but at least it guarantees isolation,
    // is short and easy to understand, and works as long as we dont mess with non-primitive types
    return JSON.parse(JSON.stringify(source));
}

export function arrayBufferToBase64String(arrayBuffer: ArrayBufferLike): string {
    return Buffer.from(arrayBuffer).toString('base64');
}

export function base64StringToArrayBuffer(base64: string): ArrayBufferLike {
    return Buffer.from(base64, 'base64');
}

export const toBase64String: (text: string) => string = (text) => {
    if (typeof btoa !== 'undefined') {
        return btoa(text);
    } else {
        return Buffer.from(text).toString('base64');
    }
};

export const fromBase64String: (text: string) => string = (b64) => {
    if (typeof atob !== 'undefined') {
        return atob(b64);
    } else {
        return Buffer.from(b64, 'base64').toString();
    }
};
