import { Crypto } from './Crypto';
import { HttpApi } from './HTTPApi';
import { HttpRequestFunction, HttpService } from './HTTPService';
import { IConfigCache } from './IConfigCache';
import { IHttpParams, ISaltsConfig } from './interface';
import { IVaultageConfig } from 'vaultage-protocol';
import { ICredentials, Vault } from './Vault';
import { IOfflineProvider, OFFLINE_URL } from './IOfflineProvider';
import { CryptoOperation, ICryptoParams, getCryptoAPI, param2String, string2Param } from './crypto-impl/CryptoAPI';
import { ILog } from './ILog';

export { ICryptoParams };
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
 * Login Options
 * @param serverURL URL to the vaultage server.
 * @param username The username used to locate the cipher on the server
 * @param masterPassword Plaintext of the master password
 * @param httpParams HTTP Parameters (optional)
 * @param configCache Configuration cache (optional)
 * @param offlineProvider Offline provider (optional)
 * @param cryptoParams Crypto params (optional)
 * @see IHttpParams
 */
export interface ILoginOptions {
    serverURL: string;
    username: string;
    masterPassword: string;
    // pedro-arruda-moreira: config cache
    httpParams?: IHttpParams;
    configCache?: IConfigCache;
    // pedro-arruda-moreira: offline mode support
    offlineProvider?: IOfflineProvider;
    cryptoParams?: ICryptoParams;
    log?: ILog;
    /**
     * used only for debugging and unit tests.
     */
    disableParallel?: boolean;
}

const RESOLVED_PROMISE = Promise.resolve();

export class ConsoleLog implements ILog {
    public static INSTANCE = new ConsoleLog();
    public info(msg: () => string): Promise<void> {
        console.log(msg());
        return RESOLVED_PROMISE;
    }
    public error(msg: () => string, error?: Error): Promise<void> {
        console.log(msg());
        if (error) {
            console.error(error);
        }
        return RESOLVED_PROMISE;
    }
}

export class NoOPLog implements ILog {
    public static INSTANCE = new NoOPLog();
    public info(_: () => string): Promise<void> {
        return RESOLVED_PROMISE;
    }
    public error(_: () => string, __: Error): Promise<void> {
        return RESOLVED_PROMISE;
    }

}

/**
 * Attempts to pull the cipher and decode it. Saves credentials on success.
 * @param options login options.
 * @returns the vault.
 */
export async function login(options: ILoginOptions): Promise<Vault> {

    const masterPassword = options.masterPassword;
    const httpParams = options.httpParams;
    const offlineProvider: IOfflineProvider = options.offlineProvider || NoOPOfflineProvider.INSTANCE;
    const configCache: IConfigCache = options.configCache || NoOPSaltsCache.INSTANCE;
    const log: ILog = options.log || NoOPLog.INSTANCE;
    const disableParallel = options.disableParallel || false;

    const creds = {
        serverURL: options.serverURL.replace(/\/$/, ''), // Removes trailing slash
        username: options.username,
        localKey: 'null',
        remoteKey: 'null'
    } as ICredentials;

    // pedro-arruda-moreira: offline mode support
    const offlineEnabled = offlineProvider !== NoOPOfflineProvider.INSTANCE;
    const offline = await offlineProvider.isRunningOffline();
    let config: IVaultageConfig;
    if (offline) {
        creds.serverURL = OFFLINE_URL;
        config = {
            version: 1,
            demo: false,
            salts: {
                local_key_salt: await offlineProvider.offlineSalt(),
                remote_key_salt: ''
            }
        };
    } else {

        // pedro-arruda-moreira: config cache
        const maybeCachedConfig = configCache.loadConfig(creds.serverURL);
        if (!maybeCachedConfig) {
            config = await HttpApi.pullConfig(creds.serverURL, httpParams);
            if (!config.demo) {
                configCache.saveConfig(creds.serverURL, config);
            }
        } else {
            config = maybeCachedConfig;
        }
    }

    const salts: ISaltsConfig = {
        LOCAL_KEY_SALT: config.salts.local_key_salt,
        REMOTE_KEY_SALT: config.salts.remote_key_salt,
    };

    const crypto = new Crypto(salts, log, options.cryptoParams);
    let localKey: Promise<string>;
    if (offline) {
        localKey = Crypto.deriveOfflineKey(masterPassword, await offlineProvider.offlineSalt(), log);
    } else {
        localKey = crypto.deriveLocalKey(masterPassword);

        const remoteKey = crypto.deriveRemoteKey(masterPassword);
        creds.remoteKey = await remoteKey;

        if (offlineEnabled) {
            creds.offlineKey = Crypto.deriveOfflineKey(masterPassword, await offlineProvider.offlineSalt(), log);
        }
    }
    if (disableParallel) {
        await localKey;
    }

    let cipherText: Promise<string>;
    if (offline) {
        cipherText = offlineProvider.getOfflineCipher();
    } else {
        cipherText = HttpApi.pullCipher(creds, httpParams);
    }

    creds.localKey = await localKey;
    const ct = await cipherText;
    return await Vault.build(creds, crypto, ct, offlineProvider, log, httpParams, config.demo);
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

export async function encrypt(key: string, plain: string, log: ILog, params?: ICryptoParams) {
    const p = await (await getCryptoAPI(CryptoOperation.ENCRYPT, log, params)).encrypt(plain, key, params);
    return param2String(p);
}

export async function decrypt(key: string, cipher: string, log: ILog) {
    const params = string2Param(cipher);
    return (await getCryptoAPI(CryptoOperation.DECRYPT, log, params)).decrypt(key, params);
}
