import { IErrorPushPullResponse, IVaultageConfig, PushPullResponse, UpdateCipherRequest } from 'vaultage-protocol';

import { HttpRequestParameters, HttpService } from './HTTPService';
import { IHttpParams } from './interface';
import { ICredentials } from './Vault';
import { ERROR_CODE, VaultageError } from './VaultageError';


/**
 * Client-side of the HTTP interface between the Vaultage server and the client.
 *
 * This class strictly takes care of formatting the data to proper HTTP payloads and
 * sending them over the wire (or to the mock HTTP interface if it is mocked).
 * This class does not handle crypto stuff.
 */
export abstract class HttpApi {

    public static async pullConfig(serverURL: string, httpParams?: IHttpParams): Promise<IVaultageConfig> {

        let parameters: HttpRequestParameters = {
            url: serverURL + '/config'
        };

        if (httpParams != null) {
            parameters = this._configureRequestParameters(parameters, httpParams);
        }

        const res = await HttpService.request<IVaultageConfig>(parameters);
        try {
            return res.data;
        } catch (e) {
            throw new VaultageError(ERROR_CODE.NETWORK_ERROR, 'Bad server response', e);
        }
    }

    public static async pullCipher(creds: ICredentials, httpParams?: IHttpParams): Promise<string> {

        let parameters: HttpRequestParameters = {
            url: this._makeURL(creds.serverURL, creds.username, creds.remoteKey)
        };

        if (httpParams != null) {
            parameters = this._configureRequestParameters(parameters, httpParams);
        }

        const resp = await HttpService.request<PushPullResponse>(parameters);
        const body = resp.data;

        if (body.error != null && body.error === true) {
            return this.throwProtocolError(body);
        }
        return (body.data || '').replace(/[^a-z0-9+/:"{},]/ig, '');
    }

    public static async pushCipher(
            creds: ICredentials,
            newRemoteKey: (string|null),
            cipher: string,
            lastFingerprint: string | undefined,
            fingerprint: string,
            httpParams?: IHttpParams): Promise<void> {

        const request: UpdateCipherRequest = {
            new_password: newRemoteKey || undefined,
            new_data: cipher,
            old_hash: lastFingerprint,
            new_hash: fingerprint,
            force: false,
        };

        let parameters: HttpRequestParameters = {
            method: 'POST',
            url: this._makeURL(creds.serverURL, creds.username, creds.remoteKey),
            data: request,
            headers: {
                'Content-Type': 'application/json'
            }
        };

        if (httpParams != null) {
            parameters = this._configureRequestParameters(parameters, httpParams);
        }

        const resp = await HttpService.request<PushPullResponse>(parameters);
        const body = resp.data;
        if (body.error === true) {
            return this.throwProtocolError(body);
        }
    }

    // Applies the user-provided http config parameters onto the axios request parameters
    private static _configureRequestParameters(params: HttpRequestParameters, config: IHttpParams): HttpRequestParameters {
        return {
            ...params,
            auth: (config.auth !== undefined) ? config.auth : undefined
        };
    }

    private static _makeURL(serverURL: string, username: string, remotePwdHash: string): string {
        return `${serverURL}/${encodeURIComponent(username)}/${remotePwdHash}/vaultage_api`;
    }

    private static throwProtocolError(err: IErrorPushPullResponse): never {
        switch (err.code) {
            case 'EFAST':
                throw new VaultageError(ERROR_CODE.NOT_FAST_FORWARD,
                        'The server has a newer version of the DB');
            case 'EAUTH':
                throw new VaultageError(ERROR_CODE.BAD_CREDENTIALS,
                        'Invalid credentials');
            case 'EDEMO':
                throw new VaultageError(ERROR_CODE.DEMO_MODE, 'Server in demo mode');
            default:
                throw this.ensureAllErrorsHandled(err.code);
        }
    }

    private static ensureAllErrorsHandled(_code: never) {
        // If this function causes a type error, then it means an error type was added or changed and
        // you forgot to update the error handling function accordingly.
        return new Error('The response received is not defined in the protocol.');
    }
}

