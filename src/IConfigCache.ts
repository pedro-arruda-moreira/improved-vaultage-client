import { IVaultageConfig } from 'vaultage-protocol';

export interface IConfigCache {

    saveConfig(url: string, config: IVaultageConfig): void;

    loadConfig(url: string): IVaultageConfig | null;

}
