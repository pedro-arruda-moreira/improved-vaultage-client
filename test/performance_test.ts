import * as util from 'util';
import * as vaultage from '../src/vaultage';
// pedro-arruda-moreira: secure notes
import { IVaultDBEntryAttrsImproved, Vault } from '../src/vaultage';


let totalTime = 0;
const runs = 20;

async function runPerfTest() {
    for (let __ = 0; __ < runs; __++) {
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

        if (vault.getNbEntries() !== 25) {
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
            for (let _ = 0; _ < 25; _++) {
                vault.addEntry(newEntry);
            }

            console.log('Pushing the db...');

            await vault.save();
        }

        // log out and pull again
        console.log('Logging back in multiple times (and measuring total time)...');
        const start = new Date().getTime();

        for (let _ = 0; _ < 100; _++) {
            vault = await vaultage.login({
                serverURL: serverUrl,
                username,
                masterPassword: masterpwd,
                log: vaultage.NoOPLog.INSTANCE
            });
        }

        const thisTime = new Date().getTime() - start;
        totalTime += thisTime;

        console.log(`Everything went well ! Test OK. (this test duration: ${thisTime} ms)`);
    }
}

runPerfTest().then(() => {
    console.log(`==== total test duration: ${totalTime}`);
    console.log(`==== average: ${totalTime / runs}`);
}).catch((e) => {
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
    console.log(util.inspect(vault, { showHidden: false, depth: null }));
    throw new Error('Assertion failure');
}
