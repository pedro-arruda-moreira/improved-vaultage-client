import { Crypto } from './Crypto';
import { HttpApi } from './HTTPApi';
import { IHttpParams, IVaultDBEntry, IVaultDBEntryAttrs, IVaultDBEntryAttrsImproved, IVaultDBEntryImproved, PasswordStrength } from './interface';
import { deepCopy } from './utils';
import { VaultDB } from './VaultDB';

export interface ICredentials {
    localKey: string;
    remoteKey: string;
    serverURL: string;
    username: string;
}
// [BEGIN] pedro-arruda-moreira: secure notes
interface IUrlJson {
    url: string;
    secureNote: string;
}

const toBase64: (text: string) => string = (text) => {
    try {
        return btoa(text);
    } catch (e) {
        return Buffer.from(text).toString('base64');
    }
};
const fromBase64: (text: string) => string = (b64) => {
    try {
        return atob(b64);
    } catch (e) {
        return Buffer.from(b64, 'base64').toString();
    }
};
// [END] pedro-arruda-moreira: secure notes
/**
 * The vault class.
 *
 * @example
 * var vault = new Vault();
 * vault.auth(some_url, some_username, some_pwd, function(err) {
 *   if (err) throw err;
 *
 *   var nb_entries = vault.getNbEntries();
 *   console.log('Success! Fetched ' + nb_entries + ' entries.');
 * });
 */
export class Vault {
    private _creds: ICredentials;
    private _crypto: Crypto;
    private _db: VaultDB;
    private _httpParams?: IHttpParams;
    private _lastFingerprint?: string;
    private _isServerInDemoMode: boolean;

    constructor(creds: ICredentials, crypto: Crypto, cipher: string | undefined, httpParams?: IHttpParams, demoMode?: boolean) {
        this._creds = { ...creds };
        this._crypto = crypto;
        this._db = new VaultDB({});
        this._httpParams = httpParams;
        this._isServerInDemoMode = false;
        if (demoMode === true) {
            this._isServerInDemoMode = true;
        }
        if (cipher) {
            this._setCipher(creds, cipher);
        }
    }

    /**
     * Returns the username associated with this Vault.
     */
    public get username(): string {
        return this._creds.username;
    }

    /**
     * Returns the server URL associated with this Vault.
     */
    public get serverURL(): string {
        return this._creds.serverURL;
    }

    public getDBRevision(): number {
        if (!this._db) {
            return -1;
        }
        return this._db.getRevision();
    }


    /**
     * Saves the Vault on the server.
     * @throws if the server is in demo-mode, the UI should not try to call "save".
     *
     * The vault must be authenticated before this method can be called.
     */
    public save(): Promise<void> {
        // Bumping the revision on each push ensures that there are no two identical consecutive fingerprints
        // (in short we are pretending that we updated something even if we didn't)
        this._db.newRevision();

        // if in demo mode, we never push to the server
        if (this._isServerInDemoMode) {
            // we do not throw the error, this forces too many checks on the UI. We just pretend it worked
            // throw new VaultageError(ERROR_CODE.DEMO_MODE, 'Server in demo mode');
            return new Promise((resolve, _) => { resolve(); });
        }
        return this._pushCipher(this._creds, null);
    }

    /**
     * Refreshes the local data by pulling the latest cipher from the server.
     *
     * The vault must be authenticated before this method can be called.
     */
    public pull(): Promise<void> {
        return this._pullCipher(this._creds);
    }

    /**
     * Changes this vault's master password.
     *
     * The change is synced with the server immediately and
     * this operation fails if it could not sync with the server.
     *
     * @param newPassword The new master password
     * @param cb Callback invoked on completion.
     */
    public async updateMasterPassword(newPassword: string): Promise<void> {
        const newCredentials = deepCopy(this._creds);
        const newLocalKey = this._crypto.deriveLocalKey(newPassword);
        const newRemoteKey = this._crypto.deriveRemoteKey(newPassword);

        this._db.newRevision();

        // first, let's do a request with (oldRemoteKey, newLocalKey), and provide new_password=newRemoteKey.
        // This will encrypt the cipher with the newLocalKey, instruct the server to use newRemoteKey for the
        // *** subsequent *** updates; of course, this message is still authenticated with oldRemoteKey
        newCredentials.localKey = newLocalKey;

        await this._pushCipher(newCredentials, newRemoteKey);


        // at this point, the server accepted the update. Let's confirm it by trying to pull with the new
        // accesses

        newCredentials.remoteKey = newRemoteKey;
        await this._pullCipher(newCredentials);

        // everything went fine, now we use the new credentials
        newCredentials.remoteKey = newRemoteKey;
        this._setCredentials(newCredentials);
    }

    /**
     * Gets the number of entries in the db.
     * @returns {number} the number of entries in the db.
     * @throws If this vault is not authenticated.
     */
    public getNbEntries(): number {
        return this._db.size();
    }

    /**
     * Adds a new entry in the db
     * pedro-arruda-moreira: Changed return type.
     * @returns the id of the newly created entry
     */
    public addEntry(attrs: IVaultDBEntryAttrsImproved): string {
        return this._db.add(this._convertFromImprovedAttr([attrs])[0]);
    }

    /**
     * Records that one entry has been used (for usage_count statistics)
     * @returns the new usage count
     */
    public entryUsed(id: string): number {
        return this._db.entryUsed(id);
    }

    /**
     * Deletes an entry
     */
    public removeEntry(id: string): void {
        this._db.remove(id);
    }

    /**
     * Returns the set of entries matching the specified query
     * pedro-arruda-moreira: Changed return type.
     * @param query attribute substrings to match
     */
    public findEntries(...query: string[]): IVaultDBEntryImproved[] {
        return this._convertToImproved(this._db.find(...query));
    }

    /**
     * Returns all weak passwords in the DB
     * pedro-arruda-moreira: Changed return type.
     * @param threshold the threshold below which an entry is returned
     */
    public getWeakPasswords(threshold: PasswordStrength = PasswordStrength.WEAK): IVaultDBEntryImproved[] {
        const entries = this.getAllEntries();
        return entries.filter((e) => e.password_strength_indication <= threshold);
    }

    /**
     * Returns the set of all entries in the DB
     * pedro-arruda-moreira: Changed return type.
     */
    public getAllEntries(): IVaultDBEntryImproved[] {
        return this.findEntries('');
    }

    /**
     * Returns the set of all entries in the DB
     * pedro-arruda-moreira: Changed return type.
     */
    public getEntriesWhichReusePasswords(): IVaultDBEntryImproved[] {
        return this._convertToImproved(this._db.getEntriesWhichReusePasswords());
    }

    /**
     * Edits an entry in the vault.
     * pedro-arruda-moreira: Changed return type.
     *
     * @param id Id of the entry to edit
     * @param attrs new set of attributes. undefined values are ignored (the entry keeps its previous value)
     * @returns an updated version of the entry
     */
    public updateEntry(id: string, attrs: Partial<IVaultDBEntryAttrsImproved>): IVaultDBEntryImproved {
        this._db.update(id, this._convertFromImprovedAttr([attrs as IVaultDBEntryAttrsImproved])[0]);
        return this._convertToImproved([this._db.get(id)])[0];
    }

    /**
     * Returns an entry by its id
     * pedro-arruda-moreira: Changed return type.
     */
    public getEntry(id: string): IVaultDBEntryImproved {
        return this._convertToImproved([this._db.get(id)])[0];
    }

    /**
     * Replaces the current entries with the new set of provided entries.
     * Then, manually "push" to overwrite the remote database's ciphertext, or "pull" to cancel this import
     * pedro-arruda-moreira: Changed return type.
     * @param entries The entries to replace this db's entries
     */
    public replaceAllEntries(entries: IVaultDBEntryImproved[]) {
        return this._db.replaceAllEntries(this._convertFromImproved(entries));
    }

    /**
     * Returns true if the "demo" flag has been set on the server. This means that typically some operations will be restricted, or
     * that the UI should indicate that the DB is reset periodically, etc.
     */
    public isInDemoMode(): boolean {
        return this._isServerInDemoMode;
    }


    // Private methods
    private _setCredentials(creds: ICredentials): void {
        // Copy for immutability
        this._creds = {
            serverURL: creds.serverURL,
            username: creds.username,
            localKey: creds.localKey,
            remoteKey: creds.remoteKey
        };
    }

    private async _pullCipher(creds: ICredentials): Promise<void> {
        const cipher = await HttpApi.pullCipher(creds, this._httpParams);
        if (cipher) {
            this._setCipher(creds, cipher);
        } else {
            // Create an empty DB if there is nothing on the server.
            this._db = new VaultDB({});
            this._lastFingerprint = '';
        }
    }

    private async _pushCipher(creds: ICredentials, newRemoteKey: (string|null)): Promise<void> {
        const plain = VaultDB.serialize(this._db);
        const cipher = this._crypto.encrypt(creds.localKey, plain);
        const fingerprint = this._crypto.getFingerprint(plain, creds.localKey);

        await HttpApi.pushCipher(
            creds,
            newRemoteKey,
            cipher,
            this._lastFingerprint,
            fingerprint,
            this._httpParams);

        this._lastFingerprint = fingerprint;
    }

    private _setCipher(creds: ICredentials, cipher: string): void {
        const plain = this._crypto.decrypt(creds.localKey, cipher);
        this._db = VaultDB.deserialize(plain);
        this._lastFingerprint = this._crypto.getFingerprint(plain, creds.localKey);
    }

    /**
     * pedro-arruda-moreira: converts array of IVaultDBEntry to array
     * of IVaultDBEntryImproved
     * @param entries entries to convert
     */
    private _convertToImproved(entries: IVaultDBEntry[]): IVaultDBEntryImproved[] {
        const returnVal: IVaultDBEntryImproved[] = [];
        for (const entry of entries) {
            const cloneAny = deepCopy(entry) as any;
            const url = cloneAny.url as string;
            delete cloneAny.url;
            const clone = cloneAny as IVaultDBEntryImproved;
            try {
                const urlJson = JSON.parse(url.split('|||').join(',')) as IUrlJson;
                clone.itemUrl = urlJson.url;
                clone.secureNoteText = fromBase64(urlJson.secureNote);
            } catch (e) {
                clone.itemUrl = url;
                clone.secureNoteText = '';
            }
            returnVal.push(clone);
        }
        return returnVal;
    }
    /**
     * pedro-arruda-moreira: converts array of IVaultDBEntryAttrsImproved to array
     * of IVaultDBEntryAttrs
     * @param entries entries to convert
     */
    private _convertFromImproved(entries: IVaultDBEntryImproved[]): IVaultDBEntry[] {
        const returnVal: IVaultDBEntry[] = [];
        for (const entry of entries) {
            const cloneAny = deepCopy(entry) as any;
            const secureNoteText = cloneAny.secureNoteText as string;
            delete cloneAny.secureNoteText;
            const itemUrl = cloneAny.itemUrl as string;
            delete cloneAny.itemUrl;
            const clone = cloneAny as IVaultDBEntry;
            clone.url = JSON.stringify({
                url: itemUrl,
                secureNote: toBase64(secureNoteText)
            } as IUrlJson);
            returnVal.push(clone);
        }
        return returnVal;
    }
    /**
     * pedro-arruda-moreira: converts array of IVaultDBEntryAttrsImproved to array
     * of IVaultDBEntryAttrs
     * @param entries entries to convert
     */
    private _convertFromImprovedAttr(entries: IVaultDBEntryAttrsImproved[]): IVaultDBEntryAttrs[] {
        const returnVal: IVaultDBEntryAttrs[] = [];
        for (const entry of entries) {
            const cloneAny = deepCopy(entry) as any;
            const secureNoteText = cloneAny.secureNoteText as string;
            delete cloneAny.secureNoteText;
            const itemUrl = cloneAny.itemUrl as string;
            delete cloneAny.itemUrl;
            const clone = cloneAny as IVaultDBEntryAttrs;
            clone.url = JSON.stringify({
                url: itemUrl,
                secureNote: toBase64(secureNoteText)
            } as IUrlJson);
            returnVal.push(clone);
        }
        return returnVal;
    }
}
