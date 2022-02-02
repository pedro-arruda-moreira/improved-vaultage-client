import { IErrorPushPullResponse, IVaultageConfig } from 'vaultage-protocol';

import { HttpService, IHttpResponse } from '../src/HTTPService';
import { IConfigCache } from '../src/IConfigCache';
import { Vault } from '../src/Vault';
import { login } from '../src/vaultage';
import { ERROR_CODE } from '../src/VaultageError';

function response<T>(data: T): IHttpResponse<T> {
    return {
        data
    };
}

const config: IVaultageConfig = {
    salts: { local_key_salt: 'deadbeef', remote_key_salt: '0123456789'},
    version: 1,
    demo: false,
};

let obtainedConfig: IVaultageConfig | null = null;

class TestConfigCache implements IConfigCache {
    public static INSTANCE = new TestConfigCache();
    public saveConfig(_: string, cfg: IVaultageConfig): void {
        obtainedConfig = cfg;
    }

    public loadConfig(_: string): IVaultageConfig | null {
        console.log(JSON.stringify(obtainedConfig));
        return obtainedConfig;
    }
}

describe('login', () => {
    let mockAPI: jest.Mock;

    beforeEach(() => {
        mockAPI = jest.fn();
        HttpService.mock(mockAPI);
        obtainedConfig = null;
    });

    it('detects an unreachable remote', async () => {
        mockAPI.mockImplementationOnce((_parameters) => {
            // bad luck, server unreachable
            return Promise.reject('404 error');
        });

        await expect(login('url', 'username', 'passwd')).rejects.toEqual('404 error');

        expect(mockAPI).toHaveBeenCalledTimes(1);
        expect(mockAPI).toHaveBeenCalledWith({
            url: 'url/config'
        });
    });

    it('detects a login error', async () => {

        mockAPI.mockImplementationOnce((_parameters) => {
            return Promise.resolve(response<IVaultageConfig>(config));
        });
        mockAPI.mockImplementationOnce((_parameters) => {
            // bad luck, server reachable but wrong credentials
            return Promise.resolve(response<IErrorPushPullResponse>({
                error: true,
                code: 'EAUTH',
                description: 'Authentication error'
            }));
        });

        await expect(login('url', 'username', 'passwd')).rejects.toHaveProperty('code', ERROR_CODE.BAD_CREDENTIALS);

        expect(mockAPI).toHaveBeenCalledWith({
            url: 'url/config'
        });
        expect(mockAPI).toHaveBeenCalledWith({
            url: 'url/username/483c29af947d335ed2851c62f1daa12227126b00035387f66f2d1492036d4dcb/vaultage_api'
        });
    });

    it('creates a vault on success', async () => {

        mockAPI.mockImplementationOnce((_parameters) => {
            return Promise.resolve(response<IVaultageConfig>(config));
        });
        mockAPI.mockImplementationOnce((_parameters) => {
            return Promise.resolve(response({}));
        });

        const vault = await login('url', 'username', 'passwd');

        expect(mockAPI).toHaveBeenCalledWith({
            url: 'url/config'
        });
        expect(mockAPI).toHaveBeenCalledWith({
            url: 'url/username/483c29af947d335ed2851c62f1daa12227126b00035387f66f2d1492036d4dcb/vaultage_api'
        });

        expect(vault).toBeInstanceOf(Vault);
    });

    //pedro-arruda-moreira: config cache
    it('creates a vault on success using config cache', async () => {

        mockAPI.mockImplementationOnce((_parameters) => {
            return Promise.resolve(response<IVaultageConfig>(config));
        });
        mockAPI.mockImplementationOnce((_parameters) => {
            return Promise.resolve(response({}));
        }).mockImplementationOnce((_parameters) => {
            return Promise.resolve(response({}));
        });

        const vault = await login('url', 'username', 'passwd', undefined, TestConfigCache.INSTANCE);
        const vault2 = await login('url', 'username', 'passwd', undefined, TestConfigCache.INSTANCE);

        expect(mockAPI).toHaveBeenNthCalledWith(1,
            {
                url: 'url/config'
            }
        );
        expect(mockAPI).toHaveBeenNthCalledWith(2,
            {
                url: 'url/username/483c29af947d335ed2851c62f1daa12227126b00035387f66f2d1492036d4dcb/vaultage_api'
            }
        );
        expect(mockAPI).toHaveBeenNthCalledWith(3,
            {
                url: 'url/username/483c29af947d335ed2851c62f1daa12227126b00035387f66f2d1492036d4dcb/vaultage_api'
            }
        );

        expect(vault).toBeInstanceOf(Vault);
        expect(vault2).toBeInstanceOf(Vault);
        expect(obtainedConfig).toBe(config);
    });

    it('Uses basic auth params', async () => {
        mockAPI.mockImplementationOnce((_parameters) => {
            return Promise.resolve(response<IVaultageConfig>(config));
        });
        mockAPI.mockImplementationOnce((_parameters) => {
            return Promise.resolve(response({}));
        });

        const vault = await login('url', 'username', 'passwd', {
            auth: {
                username: 'Jean',
                password: 'j0hn'
            }
        });

        expect(mockAPI).toHaveBeenCalledWith({
            url: 'url/config',
            auth: {
                username: 'Jean',
                password: 'j0hn'
            }
        });
        expect(mockAPI).toHaveBeenCalledWith({
            url: 'url/username/483c29af947d335ed2851c62f1daa12227126b00035387f66f2d1492036d4dcb/vaultage_api',
            auth: {
                username: 'Jean',
                password: 'j0hn'
            }
        });

        expect(vault).toBeInstanceOf(Vault);
    });
});
