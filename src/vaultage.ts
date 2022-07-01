import { Crypto } from './Crypto';
import { HttpApi } from './HTTPApi';
import { HttpRequestFunction, HttpService } from './HTTPService';
import { IConfigCache } from './IConfigCache';
import { IHttpParams, ISaltsConfig } from './interface';
import { IVaultageConfig } from 'vaultage-protocol';
import { ICredentials, Vault } from './Vault';
import { IOfflineProvider } from './IOfflineProvider';

export { IConfigCache } from './IConfigCache';
export { Passwords } from './Passwords';
export { Vault } from './Vault';
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
class NoOPOfflineProvider implements IOfflineProvider {
    public static INSTANCE = new NoOPOfflineProvider();
    public saveOfflineCipher(): Promise<void> {
        throw new Error('Method not implemented.');
    }
    public isRunningOffline(): Promise<boolean> {
        return Promise.resolve(false);
    }
    public offlineCipher(): Promise<string> {
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
        offlineProvider: IOfflineProvider = NoOPOfflineProvider.INSTANCE): Promise<Vault> {

    const creds = {
        serverURL: serverURL.replace(/\/$/, ''), // Removes trailing slash
        username: username,
        localKey: 'null',
        remoteKey: 'null'
    } as ICredentials;

    const offline = await offlineProvider.isRunningOffline();
    let obtainedConfig: IVaultageConfig | null = null;
    if (offline) {
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

    const crypto = new Crypto(salts);

    if (offline) {
        creds.localKey = Crypto.deriveOfflineKey(masterPassword, await offlineProvider.offlineSalt());
    } else {
        // possible optimization: compute the local key while the request is in the air
        const localKey = crypto.deriveLocalKey(masterPassword);
        creds.localKey = localKey;

        const remoteKey = crypto.deriveRemoteKey(masterPassword);
        creds.remoteKey = remoteKey;
    }

    let cipherText: string | null = null;
    if (offline) {
        cipherText = await offlineProvider.offlineCipher();
    } else {
        cipherText = await HttpApi.pullCipher(creds, httpParams);
    }

    const cipher = cipherText;
    return new Vault(creds, crypto, cipher, httpParams, config.demo);
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
