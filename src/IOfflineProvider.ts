export const OFFLINE_URL: string = 'offline://';

export interface IOfflineProvider {
    isRunningOffline(): Promise<boolean>;
    getOfflineCipher(): Promise<string>;
    offlineSalt(): Promise<string>;
    saveOfflineCipher(cipher: string): Promise<void>;
}
