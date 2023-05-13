import * as api from '../src/sjcl_api';

describe('sjcl_api.ts', () => {
    const KEY = 'vaultage';
    const EXPECTED = 'vaultage';

    const CT_CCM_128 = `{"iv":"976Eu+cNLe9j3qVp2MJlrw==",
        "v":1,
        "iter":1000,
        "ks":128,
        "ts":64,
        "mode":"ccm",
        "adata":"",
        "cipher":"aes",
        "salt":"zwqZOimTjZc=",
        "ct":"N6t1P7l5JQyNF68TKqG3qA=="}
    `;
    const CT_CCM_256 = `{"iv":"py8w45skhcrKmKEdDWu08w==",
        "v":1,
        "iter":1000,
        "ks":256,
        "ts":64,
        "mode":"ccm",
        "adata":"",
        "cipher":"aes",
        "salt":"zwqZOimTjZc=",
        "ct":"mcW1GZGjHRTtkaypxwzXxg=="}
    `;
    const CT_GCM_128 = `{"iv":"EjIoO7nvcttUwvpCaOPs0g==",
        "v":1,
        "iter":1000,
        "ks":128,
        "ts":64,
        "mode":"gcm",
        "adata":"",
        "cipher":"aes",
        "salt":"zwqZOimTjZc=",
        "ct":"ILLpHHfudxBk5hVTQ/a/1A=="}
    `;
    const CT_GCM_256 = `{"iv":"Rb0BxGV7+PtOxVOqoHdm7g==",
        "v":1,
        "iter":1000,
        "ks":256,
        "ts":64,
        "mode":"gcm",
        "adata":"",
        "cipher":"aes",
        "salt":"zwqZOimTjZc=",
        "ct":"vh7YBNdfdcjT04erps34rQ=="}
    `;
    const CT_OCB2_128 = `{"iv":"13ePdCtUuFQ24ca5SU8oaQ==",
        "v":1,
        "iter":1000,
        "ks":128,
        "ts":64,
        "mode":"ocb2",
        "adata":"",
        "cipher":"aes",
        "salt":"zwqZOimTjZc=",
        "ct":"ZybsAhsiGmoiiNTBBWOr9w=="}
    `;
    const CT_OCB2_256 = `{"iv":"1ZHiCVTHBVheFM8q8rjUnA==",
        "v":1,
        "iter":1000,
        "ks":256,
        "ts":64,
        "mode":"ocb2",
        "adata":"",
        "cipher":"aes",
        "salt":"zwqZOimTjZc=",
        "ct":"VMRD6cRLbshisbRGiQ/XyA=="}
    `;
    it('decrypts CCM/128', () => {
        expect(api.sjcl_decrypt(KEY, CT_CCM_128)).toEqual(EXPECTED);
    });
    it('decrypts CCM/256', () => {
        expect(api.sjcl_decrypt(KEY, CT_CCM_256)).toEqual(EXPECTED);
    });
    it('decrypts GCM/128', () => {
        expect(api.sjcl_decrypt(KEY, CT_GCM_128)).toEqual(EXPECTED);
    });
    it('decrypts GCM/256', () => {
        expect(api.sjcl_decrypt(KEY, CT_GCM_256)).toEqual(EXPECTED);
    });
    it('decrypts OCB2/128', () => {
        expect(api.sjcl_decrypt(KEY, CT_OCB2_128)).toEqual(EXPECTED);
    });
    it('decrypts OCB2/256', () => {
        expect(api.sjcl_decrypt(KEY, CT_OCB2_256)).toEqual(EXPECTED);
    });
    it('encypts/decrypts in various configs', () => {
        const cfg1: api.ISJCLParams = {
            iter: 262144,
            mode: 'ccm',
            ks: 192
        };
        expect(api.sjcl_decrypt(KEY, api.sjcl_encrypt(KEY, EXPECTED, cfg1))).toEqual(EXPECTED);
        const cfg2: api.ISJCLParams = {
            iter: 99999,
            mode: 'gcm',
            ks: 128
        };
        expect(api.sjcl_decrypt(KEY, api.sjcl_encrypt(KEY, EXPECTED, cfg2))).toEqual(EXPECTED);
        const cfg3: api.ISJCLParams = {
            iter: 524288,
            mode: 'ocb2',
            ks: 256
        };
        expect(api.sjcl_decrypt(KEY, api.sjcl_encrypt(KEY, EXPECTED, cfg3))).toEqual(EXPECTED);
        expect(api.sjcl_decrypt(KEY, api.sjcl_encrypt(KEY, EXPECTED))).toEqual(EXPECTED);
    });
});
