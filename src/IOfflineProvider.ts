export const OFFLINE_URL: string = 'offline://';

export interface IOfflineProvider {
    isRunningOffline(): Promise<boolean>;
    offlineCipher(): Promise<string>;
    offlineSalt(): Promise<string>;
    saveOfflineCipher(): Promise<void>;
}
