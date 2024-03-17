import { IOfflineProvider, OFFLINE_URL } from 'improved-vaultage-client/src/IOfflineProvider';
import { deepCopy } from 'improved-vaultage-client/src/utils';
import { ConsoleLog, NoOPOfflineProvider } from 'improved-vaultage-client/src/vaultage';
import { Crypto } from '../src/Crypto';
import { HttpService, IHttpResponse } from '../src/HTTPService';
import { ICredentials, Vault } from '../src/Vault';

const creds: ICredentials = {
    localKey: 'the_local_key',
    remoteKey: 'the_remote_key',
    serverURL: 'http://url',
    username: 'john cena'
};

const crypto = new Crypto(
    {
        LOCAL_KEY_SALT: 'deadbeef',
        REMOTE_KEY_SALT: '0123456789',
    },
    ConsoleLog.INSTANCE);

function response<T>(data: T): IHttpResponse<T> {
    return {
        data
    };
}

let offlineCipher = '';
const offlineSalt = 'the_offline_salt';

class MockOfflineProvider implements IOfflineProvider {
    public isRunningOffline(): Promise<boolean> {
        return Promise.resolve(false);
    }
    public getOfflineCipher(): Promise<string> {
        return Promise.resolve(offlineCipher);
    }
    public offlineSalt(): Promise<string> {
        return Promise.resolve(offlineSalt);
    }
    public saveOfflineCipher(cipher: string): Promise<void> {
        offlineCipher = cipher;
        return Promise.resolve();
    }
}

let mockAPI: jest.Mock;

describe('Vault.ts can', () => {

    beforeEach(() => {
        mockAPI = jest.fn();
        HttpService.mock(mockAPI);
    });

    it('create an empty vault', async () => {
        const vault = await Vault.build(creds, crypto, undefined, NoOPOfflineProvider.INSTANCE, ConsoleLog.INSTANCE);
        expect(vault.getAllEntries().length).toBe(0);
    });

    it('can create an offline vault', async () => {
        const offlineCreds = deepCopy(creds);
        offlineCreds.serverURL = OFFLINE_URL;
        offlineCreds.offlineKey = Promise.resolve('the_offline_key');
        const vault = await Vault.build(offlineCreds, crypto, undefined, NoOPOfflineProvider.INSTANCE, ConsoleLog.INSTANCE);
        expect(vault.getAllEntries().length).toBe(0);
        expect(vault.offline).toBe(true);
        expect(vault.serverURL).toBe(OFFLINE_URL);
        // try to pull vault, must fail
        try {
            await vault.pull();
            fail('did not fail!');
        } catch (e) {
            console.log('ok');
        }
        // try to save vault, must fail
        try {
            await vault.save();
            fail('did not fail!');
        } catch (e) {
            console.log('ok');
        }
        // try to update one entry, must fail
        try {
            vault.updateEntry('1', {
                title: 'Hello',
                login: 'Bob',
                password: 'zephyr',
                itemUrl: 'http://example.com',
                secureNoteText: ''
            });
            fail('did not fail!');
        } catch (e) {
            console.log('ok');
        }
        // try to remove one entry, must fail
        try {
            vault.removeEntry('1');
            fail('did not fail!');
        } catch (e) {
            console.log('ok');
        }
        // try to add one entry, must fail
        try {
            vault.addEntry({
                title: 'Hello',
                login: 'Bob',
                password: 'zephyr',
                itemUrl: 'http://example.com',
                secureNoteText: ''
            });
            fail('did not fail!');
        } catch (e) {
            console.log('ok');
        }
        // try to change master password, must fail
        try {
            await vault.updateMasterPassword('nopenope');
            fail('did not fail!');
        } catch (e) {
            console.log('ok');
        }
    });

    it('can create a Vault with a mock API, which interacts with a fake server and saves the vault for offline use', async () => {
        const offlineCreds = deepCopy(creds);
        offlineCreds.offlineKey = Promise.resolve('the_offline_key');
        const vault = await Vault.build(offlineCreds, crypto, undefined, new MockOfflineProvider(), ConsoleLog.INSTANCE);
        expect(vault.offline).toBe(false);

        // add one entry
        vault.addEntry({
            title: 'Hello',
            login: 'Bob',
            password: 'zephyr',
            itemUrl: 'http://example.com',
            secureNoteText: ''
        });

        expect(vault.getAllEntries().length).toBe(1);
        expect(mockAPI).not.toHaveBeenCalled();

        mockAPI.mockImplementationOnce((_parameters) => {
            // encrypted with master password 'passwd'. DB contains a single object Object:
            // {id: 0, title: 'Hello', url: 'http://example.com', login: 'Bob', password: 'zephyr',
            // created: 'Sat, 28 Oct 2017 12:41:50 GMT', updated: 'Sat, 28 Oct 2017 12:41:50 GMT'}
            return Promise.resolve(response({
                error: false,
                // tslint:disable-next-line:max-line-length
                data: '{"iv":"32CPCDg5TZfwMxTAkoxNnA==","v":1,"iter":10000,;"ks";:128,;"ts";:64,;"mode";:"ccm",;"adata";:"",;"cipher";:"aes",;"salt";:"2xgYuLeaI70=",;"ct";:"VP8hRnz0h71X0AycacRmDZVy6eCjglxTMGm\/MgFxDv3YiaSHMaIxfX2Krx6IDmHZGs1KLCmZWpgqW+NxUAdo6iIhTE7yQ2+JPY4iyvtEdvCJpMY9hGPxLACFC7i7JWLkNOSgeIOj9lO5SJBVtE5DASXfW68GZjTM0rc6PevuWQyAwwTwlnoLxQivodU0hH0w6LeUDXbpPtZGbP2vmiNuFs9haj1VRhrnHFUwRUTY\/mSE1JtClMvhjwjyfTYQdXjGA2qr9XBMiQWNFkA=";}'
            }));
        });

        // save the current vault
        await vault.save();

        expect(mockAPI).toHaveBeenCalledTimes(1);
        expect(mockAPI).toHaveBeenCalledWith(expect.objectContaining({
            url: 'http://url/john%20cena/the_remote_key/vaultage_api',
            method: 'POST',
        }));

        const entry = vault.getEntry('0');
        expect(entry.title).toEqual('Hello');
        expect(entry.itemUrl).toEqual('http://example.com');
        expect(entry.login).toEqual('Bob');
        expect(entry.password).toEqual('zephyr');
        expect(entry.secureNoteText).toEqual('');
        expect(offlineCipher).not.toBe('');
    });

    it('can create a Vault with a mock API, which interacts with a fake server', async () => {
        const vault = await Vault.build(creds, crypto, undefined, NoOPOfflineProvider.INSTANCE, ConsoleLog.INSTANCE);

        // add one entry
        vault.addEntry({
            title: 'Hello',
            login: 'Bob',
            password: 'zephyr',
            itemUrl: 'http://example.com',
            secureNoteText: ''
        });

        expect(vault.getAllEntries().length).toBe(1);
        expect(mockAPI).not.toHaveBeenCalled();

        mockAPI.mockImplementationOnce((_parameters) => {
            // encrypted with master password 'passwd'. DB contains a single object Object:
            // {id: 0, title: 'Hello', url: 'http://example.com', login: 'Bob', password: 'zephyr',
            // created: 'Sat, 28 Oct 2017 12:41:50 GMT', updated: 'Sat, 28 Oct 2017 12:41:50 GMT'}
            return Promise.resolve(response({
                error: false,
                // tslint:disable-next-line:max-line-length
                data: '{"iv":"32CPCDg5TZfwMxTAkoxNnA==","v":1,"iter":10000,;"ks";:128,;"ts";:64,;"mode";:"ccm",;"adata";:"",;"cipher";:"aes",;"salt";:"2xgYuLeaI70=",;"ct";:"VP8hRnz0h71X0AycacRmDZVy6eCjglxTMGm\/MgFxDv3YiaSHMaIxfX2Krx6IDmHZGs1KLCmZWpgqW+NxUAdo6iIhTE7yQ2+JPY4iyvtEdvCJpMY9hGPxLACFC7i7JWLkNOSgeIOj9lO5SJBVtE5DASXfW68GZjTM0rc6PevuWQyAwwTwlnoLxQivodU0hH0w6LeUDXbpPtZGbP2vmiNuFs9haj1VRhrnHFUwRUTY\/mSE1JtClMvhjwjyfTYQdXjGA2qr9XBMiQWNFkA=";}'
            }));
        });

        // save the current vault
        await vault.save();

        expect(mockAPI).toHaveBeenCalledTimes(1);
        expect(mockAPI).toHaveBeenCalledWith(expect.objectContaining({
            url: 'http://url/john%20cena/the_remote_key/vaultage_api',
            method: 'POST',
        }));

        const entry = vault.getEntry('0');
        expect(entry.title).toEqual('Hello');
        expect(entry.itemUrl).toEqual('http://example.com');
        expect(entry.login).toEqual('Bob');
        expect(entry.password).toEqual('zephyr');
        expect(entry.secureNoteText).toEqual('');
    });

    it('can create a Vault with a mock API, and play with entries', async () => {
        const vault = await Vault.build(creds, crypto, undefined, NoOPOfflineProvider.INSTANCE, ConsoleLog.INSTANCE);

        // add one entry
        vault.addEntry({
            title: 'github',
            login: 'json',
            password: 'zephyr',
            itemUrl: 'http://github.com',
            secureNoteText: ''
        });

        expect(vault.getAllEntries().length).toBe(1);

        // add one entry
        vault.addEntry({
            title: 'gitlab',
            login: 'jasongit',
            password: 'jackson',
            itemUrl: 'http://lab.git.com',
            secureNoteText: ''
        });

        // pedro-arruda-moreira: add one entry with secure note
        vault.addEntry({
            title: 'my bank',
            login: 'superher0',
            password: 'ldfksdjfolfj08028&(*&*',
            itemUrl: 'https://mybank.com',
            secureNoteText: `credit card pin:
1234`
        });

        const allEntries = vault.getAllEntries();

        expect(allEntries.length).toBe(3);
        expect(allEntries[2].title).toEqual('my bank');
        expect(allEntries[2].secureNoteText).toEqual(`credit card pin:
1234`);
        expect(allEntries[2].password).toEqual('ldfksdjfolfj08028&(*&*');

        const entries2 = vault.getWeakPasswords();
        expect(entries2.length).toEqual(2);

        vault.updateEntry('0', {
            password: 'N1N$a23489zasdél123',
        });

        const entries = vault.findEntries('git');
        expect(entries.length).toEqual(2);
        expect(entries[0].title).toEqual('gitlab');
        expect(entries[1].title).toEqual('github');

        const entries3 = vault.getWeakPasswords();
        expect(entries3.length).toEqual(1);
        expect(entries3[0].title).toEqual('gitlab');
    });
});
