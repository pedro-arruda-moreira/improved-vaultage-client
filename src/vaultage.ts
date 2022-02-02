import { Crypto } from './Crypto';
import { HttpApi } from './HTTPApi';
import { HttpRequestFunction, HttpService } from './HTTPService';
import { IConfigCache } from './IConfigCache';
import { IHttpParams, ISaltsConfig } from './interface';
import { IVaultageConfig } from 'vaultage-protocol';
import { Vault } from './Vault';

export { IConfigCache } from './IConfigCache';
export { Passwords } from './Passwords';
export { Vault } from './Vault';
export { VaultageError, ERROR_CODE } from './VaultageError';
export * from './interface';

// tslint:disable-next-line:no-var-requires
const pkg = require('../package.json');

//pedro-arruda-moreira: config cache
class NoOPSaltsCache implements IConfigCache {

    public static INSTANCE = new NoOPSaltsCache();
    public saveConfig(_: string, __: IVaultageConfig): void {
        return;
    }

    public loadConfig(_: string): IVaultageConfig | null {
        return null;
    }
}

/**
 * Attempts to pull the cipher and decode it. Saves credentials on success.
 * @param serverURL URL to the vaultage server.
 * @param username The username used to locate the cipher on the server
 * @param masterPassword Plaintext of the master password
 * @param cb Callback invoked on completion. err is null if no error occured.
 */
export async function login(
        serverURL: string,
        username: string,
        masterPassword: string,
        //pedro-arruda-moreira: config cache
        httpParams?: IHttpParams,
        configCache: IConfigCache = NoOPSaltsCache.INSTANCE): Promise<Vault> {

    const creds = {
        serverURL: serverURL.replace(/\/$/, ''), // Removes trailing slash
        username: username,
        localKey: 'null',
        remoteKey: 'null'
    };

    //pedro-arruda-moreira: config cache
    let obtainedConfig = configCache.loadConfig(creds.serverURL);
    if (!obtainedConfig) {
        obtainedConfig = await HttpApi.pullConfig(creds.serverURL, httpParams);
        configCache.saveConfig(creds.serverURL, obtainedConfig);
    }

    const config = obtainedConfig;

    const salts: ISaltsConfig = {
        LOCAL_KEY_SALT: config.salts.local_key_salt,
        REMOTE_KEY_SALT: config.salts.remote_key_salt,
    };

    const crypto = new Crypto(salts);

    const remoteKey = crypto.deriveRemoteKey(masterPassword);
    // possible optimization: compute the local key while the request is in the air
    const localKey = crypto.deriveLocalKey(masterPassword);

    creds.localKey = localKey;
    creds.remoteKey = remoteKey;

    const cipher = await HttpApi.pullCipher(creds, httpParams);
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
