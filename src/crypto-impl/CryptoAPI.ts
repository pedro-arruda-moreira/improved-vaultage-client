import { FastCryptoAPI } from "./FastCryptoAPI";
import { LegacyCryptoAPI } from "./LegacyCryptoAPI";

export enum CryptoOperation {
    DERIVE,
    ENCRYPT,
    DECRYPT
}

export interface ICryptoAPI {
    deriveKey(password: string, salt: string, difficulty: number, useSha512: boolean): Promise<string>;
    canDerive(): Promise<Boolean>;
}


export async function getCryptoAPI(op: CryptoOperation): Promise<ICryptoAPI> {
    const availableApis = [
        new FastCryptoAPI(),
        new LegacyCryptoAPI()
    ];
    let chosen: ICryptoAPI | null = null;
    availableApis.forEach(async api => {
        if(chosen != null) {
            return;
        }
        if (op == CryptoOperation.DERIVE) {
            if (await api.canDerive()) {
                chosen = api;
            }
        }
    });
    if (chosen == null) {
        throw new Error('unable to find a ICryptoAPI');
    }
    return chosen;
}
