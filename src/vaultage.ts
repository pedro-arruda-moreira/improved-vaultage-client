import { Crypto } from './Crypto';
import { HttpApi } from './HTTPApi';
import { HttpRequestFunction, HttpService } from './HTTPService';
import { IConfigCache } from './IConfigCache';
import { IHttpParams, ISaltsConfig } from './interface';
import { IVaultageConfig } from 'vaultage-protocol';
import { ICredentials, Vault } from './Vault';
import { IOfflineProvider, OFFLINE_URL } from './IOfflineProvider';
import { ISJCLParams } from './sjcl_api';

export { sjcl_encrypt, sjcl_decrypt, ISJCLParams } from './sjcl_api';
export { IOfflineProvider };
export { IConfigCache };
export { Passwords } from './Passwords';
export { Vault };
export { VaultageError, ERROR_CODE } from './VaultageError';
export * from './interface';

// tslint:disable-next-line:no-var-requires
const pkg = require('../package.json');

// pedro-arruda-moreira: config cache
class NoOPSaltsCache implements IConfigCache {

    public static INSTANCE = new NoOPSaltsCache();
    public saveConfig(_: string, __: IVaultageConfig): void {
        return;
    }

    public loadConfig(_: string): IVaultageConfig | null {
        return null;
    }
}

// pedro-arruda-moreira: offline mode support
export class NoOPOfflineProvider implements IOfflineProvider {
    public static INSTANCE = new NoOPOfflineProvider();
    public saveOfflineCipher(_: string): Promise<void> {
        return Promise.resolve();
    }
    public isRunningOffline(): Promise<boolean> {
        return Promise.resolve(false);
    }
    public getOfflineCipher(): Promise<string> {
        throw new Error('Method not implemented.');
    }
    public offlineSalt(): Promise<string> {
        throw new Error('Method not implemented.');
    }
}

// pedro-arruda-moreira: fixed docs.
/**
 * Attempts to pull the cipher and decode it. Saves credentials on success.
 * @param serverURL URL to the vaultage server.
 * @param username The username used to locate the cipher on the server
 * @param masterPassword Plaintext of the master password
 * @param httpParams HTTP Parameters (optional)
 * @param configCache Configuration cache (optional)
 * @param offlineProvider Offline provider (optional)
 * @see IHttpParams
 */
export async function login(
        serverURL: string,
        username: string,
        masterPassword: string,
        // pedro-arruda-moreira: config cache
        httpParams?: IHttpParams,
        configCache: IConfigCache = NoOPSaltsCache.INSTANCE,
        // pedro-arruda-moreira: offline mode support
        offlineProvider: IOfflineProvider = NoOPOfflineProvider.INSTANCE,
        sjclParams?: ISJCLParams): Promise<Vault> {

    const creds = {
        serverURL: serverURL.replace(/\/$/, ''), // Removes trailing slash
        username: username,
        localKey: 'null',
        remoteKey: 'null'
    } as ICredentials;

    // pedro-arruda-moreira: offline mode support
    const offlineEnabled = offlineProvider !== NoOPOfflineProvider.INSTANCE;
    const offline = await offlineProvider.isRunningOffline();
    let obtainedConfig: IVaultageConfig | null = null;
    if (offline) {
        creds.serverURL = OFFLINE_URL;
        obtainedConfig = {
            version: 1,
            demo: false,
            salts: {
                local_key_salt: await offlineProvider.offlineSalt(),
                remote_key_salt: ''
            }
        };
    } else {

        // pedro-arruda-moreira: config cache
        obtainedConfig = configCache.loadConfig(creds.serverURL);
        if (!obtainedConfig) {
            obtainedConfig = await HttpApi.pullConfig(creds.serverURL, httpParams);
            if (!obtainedConfig.demo) {
                configCache.saveConfig(creds.serverURL, obtainedConfig);
            }
        }
    }

    const config = obtainedConfig;

    const salts: ISaltsConfig = {
        LOCAL_KEY_SALT: config.salts.local_key_salt,
        REMOTE_KEY_SALT: config.salts.remote_key_salt,
    };

    const crypto = new Crypto(salts, sjclParams);

    if (offline) {
        creds.localKey = await Crypto.deriveOfflineKey(masterPassword, await offlineProvider.offlineSalt());
    } else {
        // possible optimization: compute the local key while the request is in the air
        const localKey = crypto.deriveLocalKey(masterPassword);
        creds.localKey = await localKey;

        const remoteKey = crypto.deriveRemoteKey(masterPassword);
        creds.remoteKey = await remoteKey;

        if (offlineEnabled) {
            creds.offlineKey = Crypto.deriveOfflineKey(masterPassword, await offlineProvider.offlineSalt());
        }
    }

    let cipherText: string | null = null;
    if (offline) {
        cipherText = await offlineProvider.getOfflineCipher();
    } else {
        cipherText = await HttpApi.pullCipher(creds, httpParams);
    }

    const cipher = cipherText;
    return await Vault.build(creds, crypto, cipher, offlineProvider, httpParams, config.demo);
}

export function _mockHttpRequests(fn: HttpRequestFunction): void {
    HttpService.mock(fn);
}

/**
 * Returns the current version of the vaultage-client package
 */
export function version(): string {
    return pkg.version;
}
