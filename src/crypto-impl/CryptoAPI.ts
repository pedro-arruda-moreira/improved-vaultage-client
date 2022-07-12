export interface ICryptoAPI {
    deriveKey(password: string, salt: string, difficulty: number): Promise<string>;
}
