// Public facing interfaces

/**
 * Local and remote salts used to secure encryption.
 */
export interface ISaltsConfig {
    LOCAL_KEY_SALT: string;
    REMOTE_KEY_SALT: string;
}

/**
 * Attributes of an entry in the Vault database.
 */
export interface IVaultDBEntryAttrs {
    title: string;
    url: string;
    login: string;
    password: string;
    hidden?: boolean;
}

/**
 * pedro-arruda-moreira: Improved IVaultDBEntryAttrs supporting
 * secure notes
 */
export interface IVaultDBEntryAttrsImproved {
    title: string;
    itemUrl: string;
    login: string;
    password: string;
    hidden?: boolean;
    secureNoteText: string;
}

/**
 * Subjective password strength based on a heuristic which computes how easy it is to guess the password.
 */
export enum PasswordStrength {
    WEAK = 1,
    MEDIUM,
    STRONG
}

/**
 * Actual entry in the passwords database.
 */
export interface IVaultDBEntry {
    title: string;
    url: string;
    login: string;
    password: string;
    id: string;
    created: string;
    updated: string;
    usage_count: number;
    reuse_count: number;
    password_strength_indication: PasswordStrength;
    hidden: boolean;
}
/**
 * pedro-arruda-moreira: Improved IVaultDBEntry supporting
 * secure notes
 */
export interface IVaultDBEntryImproved {
    title: string;
    itemUrl: string;
    login: string;
    password: string;
    id: string;
    created: string;
    updated: string;
    usage_count: number;
    reuse_count: number;
    password_strength_indication: PasswordStrength;
    hidden: boolean;
    secureNoteText: string;
}

/**
 * HTTP-level parameters to add to all requests
 */
export interface IHttpParams {
    // Basic auth credentials
    auth?: {
        username: string;
        password: string;
    };
}
