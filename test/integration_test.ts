import { IOfflineProvider } from 'improved-vaultage-client/src/IOfflineProvider';
import * as util from 'util';
import * as vaultage from '../src/vaultage';
// pedro-arruda-moreira: secure notes
import { IVaultDBEntryAttrsImproved, Vault } from '../src/vaultage';

let offline = false;
let offlineCipher = '';
const offlineSalt = '6c667df5395c49ee20617060627c24dd579dc59fee54d620e7211b3334e5e934';

class SimpleOfflineProvider implements IOfflineProvider {
    public isRunningOffline(): Promise<boolean> {
        return Promise.resolve(offline);
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

async function runIntegrationTest() {
    const start = new Date().getTime();
    const serverUrl = 'http://localhost:3000/';
    const username = 'john';
    const masterpwd = '1234';
    console.log('starting integration test.');

    // create vault
    let vault = await vaultage.login({
        serverURL: serverUrl,
        username,
        masterPassword: masterpwd,
        log: vaultage.ConsoleLog.INSTANCE
    });

    if (vault.offline) {
        fail(vault, 'Vault is in offline mode.');
    }

    if (vault.getNbEntries() !== 0) {
        throw new Error('This integration test is meant to be run on a clean computer. Your DB is not empty. Aborting.');
    }

    console.log('Authentication and pull OK ! Creating entry...');

    // adds an entry
    // pedro-arruda-moreira: secure notes
    const newEntry: IVaultDBEntryAttrsImproved = {
        title: 'MyTitle',
        login: 'Username',
        password: 'Password',
        // pedro-arruda-moreira: secure notes
        itemUrl: 'http://url',
        secureNoteText: ''
    };

    vault.addEntry(newEntry);

    console.log('Pushing the db...');

    await vault.save();

    // log out and pull again
    console.log('Logging back in...');

    vault = await vaultage.login({
        serverURL: serverUrl,
        username,
        masterPassword: masterpwd,
        log: vaultage.ConsoleLog.INSTANCE
    });

    if (vault.offline) {
        fail(vault, 'Vault is in offline mode.');
    }
    if (vault.getNbEntries() !== 1) {
        fail(vault, 'Could not get back the entry we just created.');
    }

    const e = vault.getEntry('0');

    if (e.title !== newEntry.title) {
        fail(vault, 'The fetched entry has a different title than the created entry.');
    }
    if (e.login !== newEntry.login) {
        fail(vault, 'The fetched entry has a different login than the created entry.');
    }
    if (e.password !== newEntry.password) {
        fail(vault, 'The fetched entry has a different password than the created entry.');
    }
    // pedro-arruda-moreira: secure notes
    if (e.itemUrl !== newEntry.itemUrl) {
        fail(vault, 'The fetched entry has a different url than the created entry.');
    }
    // pedro-arruda-moreira: secure notes
    if (e.secureNoteText !== newEntry.secureNoteText) {
        fail(vault, 'The fetched entry has a different secure note than the created entry.');
    }

    console.log('Entry correctly fetched ! Trying to edit it...');

    // edit our entry
    // pedro-arruda-moreira: secure notes
    const newEntry2: IVaultDBEntryAttrsImproved = {
        title: 'MyTitle2',
        login: 'Username2',
        password: 'Password2',
        // pedro-arruda-moreira: secure notes
        itemUrl: 'http://url2',
        secureNoteText: 'my secure note'
    };

    vault.updateEntry('0', newEntry2);

    console.log('Saving it...');

    // manually save
    await vault.save();

    console.log('Manually pulling the db...');

    // try to manually pull the db
    await vault.pull();

    if (vault.getNbEntries() !== 1) {
        fail(vault, 'Could not get back the entry we just edited.');
    }

    const e2 = vault.getEntry('0');

    if (e2.title !== newEntry2.title) {
        fail(vault, 'The fetched entry has a different title than the created entry.');
    }
    if (e2.login !== newEntry2.login) {
        fail(vault, 'The fetched entry has a different login than the created entry.');
    }
    if (e2.password !== newEntry2.password) {
        fail(vault, 'The fetched entry has a different password than the created entry.');
    }
    // pedro-arruda-moreira: secure notes
    if (e2.itemUrl !== newEntry2.itemUrl) {
        fail(vault, 'The fetched entry has a different url than the created entry.');
    }
    // pedro-arruda-moreira: secure notes
    if (e2.secureNoteText !== newEntry2.secureNoteText) {
        fail(vault, 'The fetched entry has a different secure note than the created entry.');
    }

    console.log('Entry correctly edited ! Now trying to change the master password...');

    const newMasterPassword = 'masterpwd2';

    await vault.updateMasterPassword(newMasterPassword);

    // log out and pull again
    console.log('Logging out...');
    console.log('now testing SJCL params.');

    vault = await vaultage.login({
        serverURL: serverUrl,
        username,
        masterPassword: newMasterPassword,
        offlineProvider: new SimpleOfflineProvider(),
        cryptoParams: {
            iter: 48000,
            mode: 'ocb2',
            ks: 192
        },
        log: vaultage.ConsoleLog.INSTANCE
    });

    if (vault.offline) {
        fail(vault, 'Vault is in offline mode.');
    }
    // check if the vault content is as expected

    if (vault.getNbEntries() !== 1) {
        fail(vault, 'Could not get back the entry.');
    }

    const e3 = vault.getEntry('0');

    if (e3.title !== newEntry2.title) {
        fail(vault, 'The fetched entry has a different title than the created entry.');
    }
    if (e3.login !== newEntry2.login) {
        fail(vault, 'The fetched entry has a different login than the created entry.');
    }
    if (e3.password !== newEntry2.password) {
        fail(vault, 'The fetched entry has a different password than the created entry.');
    }
    // pedro-arruda-moreira: secure notes
    if (e3.itemUrl !== newEntry2.itemUrl) {
        fail(vault, 'The fetched entry has a different url than the created entry.');
    }
    // pedro-arruda-moreira: secure notes
    if (e3.secureNoteText !== newEntry2.secureNoteText) {
        fail(vault, 'The fetched entry has a different secure note than the created entry.');
    }

    console.log('Trying to delete the entry...');

    vault.removeEntry('0');

    if (vault.getNbEntries() !== 0) {
        fail(vault, 'Could not delete the entry.');
    }

    console.log('adding another entry to test offline mode.');

    vault.addEntry(newEntry);
    await vault.save();
    offline = true;

    vault = await vaultage.login({
        serverURL: serverUrl,
        username,
        masterPassword: newMasterPassword,
        offlineProvider: new SimpleOfflineProvider(),
        log: vaultage.ConsoleLog.INSTANCE
    });

    if (!vault.offline) {
        fail(vault, 'Vault is not in offline mode.');
    }

    if (vault.getNbEntries() !== 1) {
        fail(vault, 'Could not get back the entry in offline mode.');
    }

    const e4 = vault.getEntry('0');

    if (e4.title !== newEntry.title) {
        fail(vault, 'The fetched entry has a different title than the created entry.');
    }
    if (e4.login !== newEntry.login) {
        fail(vault, 'The fetched entry has a different login than the created entry.');
    }
    if (e4.password !== newEntry.password) {
        fail(vault, 'The fetched entry has a different password than the created entry.');
    }
    // pedro-arruda-moreira: secure notes
    if (e4.itemUrl !== newEntry.itemUrl) {
        fail(vault, 'The fetched entry has a different url than the created entry.');
    }
    // pedro-arruda-moreira: secure notes
    if (e4.secureNoteText !== newEntry.secureNoteText) {
        fail(vault, 'The fetched entry has a different secure note than the created entry.');
    }

    console.log(`offline vault: ${offlineCipher}`);
    if (offlineCipher === '') {
        fail(vault, 'The offlineCipher is empty.');
    }

    console.log(`Everything went well ! Test OK. (test duration: ${new Date().getTime() - start} ms)`);
}

runIntegrationTest().catch((e) => {
    if (e.message === 'Error: Invalid credentials') {
        console.log('Error: Invalid credentials. This integration test is meant to be ' +
        'run against an *empty* db - please (backup and) delete ~/.vaultage and retry.');
        process.exit(1);
    }
    console.log('Error:', e);
    process.exit(1);
});


function fail(vault: Vault, reason: string) {
    console.log(`=== FAILURE: ${reason} ===`);
    console.log('Dumping vault state:');
    console.log(util.inspect(vault, { showHidden: false, depth: null}));
    throw new Error('Assertion failure');
}
