export interface ICryptoAPI {
    deriveKey(password: string, salt: string, difficulty: number, useSha512: boolean): Promise<string>;
}
