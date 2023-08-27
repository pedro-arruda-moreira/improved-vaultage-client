import { Crypto } from '../src/Crypto';
import { PasswordStrength } from '../src/interface';
import { VaultDB } from '../src/VaultDB';

const verbose = false;

function cPrint(v: any) {
    if (verbose) {
        console.log(v);
    }
}

test('Workflow', async () => {

    cPrint('Demoing the encryption / decryption locally...');
    cPrint('Note that this is demoing the inside of the vaultage SDK but all of this complexity' +
        ' is going to be hidden behind the Vault class.\n');

    const crypto = new Crypto({
        LOCAL_KEY_SALT: 'abcdef',
        REMOTE_KEY_SALT: '01234576',
    });

    const masterKey = 'ilovesushi';

    const key = crypto.deriveLocalKey(masterKey);
    cPrint('My local key is: ' + key + '\n');

    // tslint:disable-next-line:object-literal-key-quotes
    const db = new VaultDB({'0': {
            title: 'Hello',
            id: '0',
            created: 'now',
            updated: '',
            login: 'Bob',
            password: 'zephyr',
            url: 'http://example.com',
            usage_count: 0,
            reuse_count: 0,
            password_strength_indication: PasswordStrength.WEAK,
            hidden: false,
        }
    });
    const plain = VaultDB.serialize(db);
    const fp = await crypto.getFingerprint(plain, await key);

    cPrint('Here is what the db looks like initially: ');
    cPrint(db);
    cPrint('Fingerprint: ' + fp);

    cPrint('\n\nNow I\'m gonna encrypt the db');
    const enc = await crypto.encrypt(await key, plain);

    cPrint('Here is the cipher:\n');
    cPrint(enc);

    cPrint('\n\nAnd now let\'s get back the original:');

    const dec = await crypto.decrypt(await key, await enc);
    const decFP = await crypto.getFingerprint(await dec, await key);
    const decDB = VaultDB.deserialize(await dec);

    cPrint(decDB);
    cPrint('Fingerprint: ' + decFP);

    expect(fp).toEqual(decFP);
    expect(plain).toEqual(dec);
});

