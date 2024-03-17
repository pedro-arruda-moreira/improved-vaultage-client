export interface ILog {
    info(info: () => string): Promise<void>;
    error(msg: () => string, error?: Error): Promise<void>;
}
