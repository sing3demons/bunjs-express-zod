import { readFileSync } from "fs";
const packageJsonPath = require.resolve("../../package.json")
const packageJsonContents = readFileSync(packageJsonPath).toString();
const packageJson = JSON.parse(packageJsonContents);

interface IConfig {
    host: string;
    port: number;
    timeout: number;
    level: string;
    app_name: string;
    privateKey: string;
    publicKey: string;
    refreshPrivateKey: string;
    refreshPublicKey: string;
}

type ConfigKey = keyof IConfig;

class ConfigManager {
    private config: IConfig;
    constructor() {
        const port = process.env.PORT ? parseInt(process.env.PORT) : 3000;
        const host = process.env.HOST || 'http://localhost:3000';
        const timeout = process.env.TIMEOUT ? parseInt(process.env.TIMEOUT) : 3000;
        const level = process.env.LOG_LEVEL || 'info'
        const app_name = process.env.APP_NAME || packageJson.name
        const privateKey = process.env.PRIVATE_KEY || ''
        const publicKey = process.env.PUBLIC_KEY || ''
        const refreshPrivateKey = process.env.REFRESH_PRIVATE_KEY || ''
        const refreshPublicKey = process.env.REFRESH_PUBLIC_KEY || ''

        this.config = {
            host,
            port,
            timeout,
            level,
            app_name,
            privateKey,
            publicKey,
            refreshPrivateKey,
            refreshPublicKey
        }
    }

    get<K extends ConfigKey>(key: K) {
        return this.config[key];
    }

    set<K extends ConfigKey>(key: K, value: IConfig[K]) {
        this.config[key] = value;
        return this;
    }
}

const config = new ConfigManager()

export default config;