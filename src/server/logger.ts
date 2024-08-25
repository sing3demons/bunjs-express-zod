import dayjs from 'dayjs'
import type { Request } from 'express'
import { v7 as uuid } from 'uuid'
import { createLogger, format, transports } from 'winston'
import config from '../config'
import path from 'path'
import 'winston-daily-rotate-file'; // Importing to extend winston
import fs from 'fs'

const level = config.get('level')
const appName = config.get('app_name')
export const logger = createLogger({
    level,
    format: format.combine(
        format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss', alias: '@timestamp', }),
        format.json()
    ),
    defaultMeta: { service: appName },
    transports: [
        new transports.Console(),

    ],
    exceptionHandlers: [],
    exitOnError: false,
})

if (config.get('logFile')) {
    const logDir = 'logs';
    const filename = path.join(path.basename(logDir))
    if (!fs.existsSync(logDir)) {
        fs.mkdirSync(logDir);
    }
    const dailyRotateFileTransport = new transports.DailyRotateFile({
        filename: `${filename}/%DATE%-app.log`,
        datePattern: 'YYYY-MM-DD',
        zippedArchive: true,
    });
    logger.transports.push(dailyRotateFileTransport)
}

const formatDate = 'YYYY-MM-DD HH:mm:ss'

interface ILogger {
    Host: string
    AppName: string
    Instance: string
    Session: string
    InitInvoke: string
    Scenario: string
    Identity: string
    InputTimeStamp: string
    Input: Input[]
    OutputTimeStamp: string
    Output: Output[]
    ProcessingTime: string
    Request?: Record<string, any>
}

interface Input {
    Invoke: string
    Event: string
    Type: ELogType
    Data?: Data
    Protocol?: string
    ResTime?: string
}

type Data = string | number | boolean | object | object[] | null | any

interface Output {
    Invoke: string
    Event: string
    Type: ELogType
    Data: Data
    Protocol?: string
}
enum ELogType {
    SUMMARY,
    DETAIL
}

interface Sequence {
    Node: string
    Command: string
    result: Result[]
}

interface Result {
    Result: string
    Desc: string
}

export class DetailLog {
    private Host: string
    private AppName: string
    private Instance: string
    private Session: string
    private InitInvoke: string
    private Scenario: string
    private Identity: string
    private InputTimeStamp: string
    private Input: Input[]
    private OutputTimeStamp: string
    private Output: Output[]
    private ProcessingTime: string
    private Type = ELogType.DETAIL

    constructor(req: Request, invoke: string, cmd: string, identity: string | undefined) {
        this.Host = req.hostname || ''
        this.AppName = appName
        this.Instance = '0'
        if (!req.headers['x-transaction-id']) { req.headers['x-transaction-id'] = uuid() }
        const session = <string>req.headers['x-transaction-id']
        this.Session = session
        this.InitInvoke = `${invoke}_${dayjs().format(formatDate)}`
        this.Scenario = cmd
        this.Identity = identity || ''
        this.InputTimeStamp = dayjs().format(formatDate)
        this.Input = []
        this.OutputTimeStamp = ''
        this.Output = []
        this.ProcessingTime = ''

        const event = 'client.' + req.method.toLowerCase() + req.path.replace(/\//g, '.')
        const protocol = 'http.' + req.method.toLowerCase()
        this.Input.push({
            Invoke: 'default',
            Event: event,
            Type: this.Type,
            Data: {},
            Protocol: protocol,
        })
    }

    public createInvoke(nodeName: string = appName) {
        if (!this.Session) return nodeName
        return this.InitInvoke = nodeName + '_' + dayjs().format('YYYYMMDDHHmmssSSS')
    }

    public addInputRequest<T>(node: string, cmd: string, invoke: string, Data: T, protocol?: string, protocolMethod?: string) {
        this.Input.push({
            Invoke: invoke,
            Event: `${node}.${cmd}`,
            Type: this.Type,
            Data: Data as Data,
            Protocol: protocol && protocolMethod ? `${protocol}.${protocolMethod}` : undefined
        })
        return this
    }
    public addOutputRequest(node: string, cmd: string, invoke: string, data: Data, protocol?: string, protocolMethod?: string) {
        this.Output.push({
            Invoke: invoke,
            Event: `${node}.${cmd}`,
            Type: this.Type,
            Data: data,
            Protocol: protocol && protocolMethod ? `${protocol}.${protocolMethod}` : undefined
        })
        return this
    }

    public addInputResponse<T>(node: string, cmd: string, invoke: string, Data: T, protocol?: string, protocolMethod?: string) {
        this.Input.push({
            Invoke: invoke,
            Event: `${node}.${cmd}`,
            Type: this.Type,
            Data: Data as Data,
            Protocol: protocol && protocolMethod ? `${protocol}.${protocolMethod}` : undefined
        })
        return this
    }

    public addOutputResponse(node: string, cmd: string, invoke: string, data: Data, protocol?: string, protocolMethod?: string) {
        this.Output.push({
            Invoke: invoke,
            Event: `${node}.${cmd}`,
            Type: this.Type,
            Data: data,
            Protocol: protocol && protocolMethod ? `${protocol}.${protocolMethod}` : undefined
        })
        return this
    }

    public addError(node: string, cmd: string, invoke: string, err: unknown) {
        if (err instanceof Error) {
            this.Output.push({
                Invoke: invoke,
                Event: `${node}.${cmd}`,
                Type: this.Type,
                Data: {
                    Code: err.name,
                    Message: err.message,
                    Stack: err.stack
                },
                Protocol: 'http.error'
            })
        } else {
            this.Output.push({
                Invoke: invoke,
                Event: `${node}.${cmd}`,
                Type: this.Type,
                Data: {
                    Code: 'unknown',
                    Message: String(err),
                    Stack: 'unknown'
                },
                Protocol: 'http.error'
            })
        }

        this.end()
    }

    public end(result: string = 'OK', desc: string = 'Success') {
        this.OutputTimeStamp = dayjs().format(formatDate)
        this.ProcessingTime = dayjs(this.OutputTimeStamp).diff(dayjs(this.InputTimeStamp), 'ms').toString()
        const loggerInfo: ILogger = {
            Host: this.Host,
            AppName: this.AppName,
            Instance: this.Instance,
            Session: this.Session,
            InitInvoke: this.InitInvoke,
            Scenario: this.Scenario,
            Identity: this.Identity,
            InputTimeStamp: this.InputTimeStamp,
            Input: this.Input,
            OutputTimeStamp: this.OutputTimeStamp,
            Output: this.Output,
            ProcessingTime: this.ProcessingTime
        }

        loggerInfo.Output.push({
            Invoke: 'end',
            Event: 'client.response',
            Type: this.Type,
            Data: {
                Result: result,
                Desc: desc
            },
            Protocol: 'http.response'
        })
        logger.log(level, loggerInfo)
        loggerInfo.Output.length = 0
        loggerInfo.Input.length = 0
    }
}

interface ISummary {
    InputTimeStamp: string
    Host: string
    Type: ELogType
    AppName: string
    Instance: string
    Session: string
    InitInvoke: string
    Scenario: string
    Identity: {}
    ResponseResult: string
    ResponseDesc: string
    Sequences: Sequence[]
    EndProcessTimeStamp: string
    ProcessTime: string
    Request: Record<string, any> | undefined
}

export class SummaryLog {
    private Host: string
    private AppName: string
    private Instance: string
    private Session: string
    private InitInvoke: string
    private Scenario: string
    private Identity: string
    private ResponseResult: string
    private ResponseDesc: string
    private Sequences: Sequence[]
    private EndProcessTimeStamp: string
    private ProcessTime: string
    private Type = ELogType.SUMMARY
    private req: Request
    private InputTimeStamp: string

    constructor(req: Request, invoke: string, cmd: string, identity: string = '') {
        this.req = req
        this.Host = req.hostname
        this.AppName = appName
        this.Instance = '0'
        if (!req.headers['x-transaction-id']) { req.headers['x-transaction-id'] = uuid() }
        const session = <string>req.headers['x-transaction-id']
        this.Session = session
        this.InitInvoke = `${invoke}_${dayjs().format(formatDate)}`
        this.Scenario = cmd
        this.Identity = identity
        this.ResponseResult = ''
        this.ResponseDesc = ''
        this.Sequences = []
        this.EndProcessTimeStamp = ''
        this.ProcessTime = ''
        this.InputTimeStamp = dayjs().format(formatDate)
    }

    private addBlock(node: string, cmd: string, Result: string, Desc: string) {
        this.Sequences.push({
            Node: node,
            Command: cmd,
            result: [{ Result, Desc }],
        });
    }

    public addSuccessBlock(node: string, cmd: string, Result: string, Desc: string) {
        this.addBlock(node, cmd, Result, Desc);
        return this
    }

    public addErrorBlock(node: string, cmd: string, Result: string, Desc: string) {
        this.addBlock(node, cmd, Result, Desc);
        return this
    }

    public end(result: string = 'OK', desc: string = 'Success') {
        this.ResponseResult = result
        this.ResponseDesc = desc
        this.EndProcessTimeStamp = dayjs().format(formatDate)
        this.ProcessTime = dayjs(this.EndProcessTimeStamp).diff(dayjs(this.InputTimeStamp), 'ms').toString()
        const loggerInfo = {
            Host: this.Host,
            Type: this.Type,
            AppName: this.AppName,
            Instance: this.Instance,
            Session: this.Session,
            InitInvoke: this.InitInvoke,
            Scenario: this.Scenario,
            Identity: this.Identity,
            ResponseResult: this.ResponseResult,
            ResponseDesc: this.ResponseDesc,
            Sequences: this.Sequences,
            EndProcessTimeStamp: this.EndProcessTimeStamp,
            ProcessTime: this.ProcessTime,
            Request: this.extractRequestInfo()
        }

        // console.log(JSON.stringify(logger, null, 2))
        logger.log(level, loggerInfo)
        // logger.info(loggerInfo)
    }
    private extractRequestInfo() {
        const headers = this.req.headers;

        return {
            path: this.req.originalUrl,
            connection: headers.connection,
            'cache-control': headers['cache-control'],
            'sec-ch-ua': headers['sec-ch-ua'],
            'sec-ch-ua-mobile': headers['sec-ch-ua-mobile'],
            'sec-ch-ua-platform': headers['sec-ch-ua-platform'],
            'upgrade-insecure-requests': headers['upgrade-insecure-requests'],
            ip: this.req.ip || headers['x-forwarded-for'] || this.req.socket.remoteAddress,
            device: headers['user-agent'],
            location: headers['x-location'],
            host: headers.host,
            baseUrl: this.req.baseUrl,
            url: this.req.url,
            method: this.req.method,
            clientIp: headers['x-forwarded-for'] ?? this.req.socket.remoteAddress,
            // body: this.req.body,
            // params: this.req.params,
            // query: this.req.query,
        };
    }

}

export default class Logger {
    detailLog: DetailLog
    summaryLog: SummaryLog
    constructor(req: Request, invoke: string, cmd: string, identity: string) {
        this.detailLog = new DetailLog(req, invoke, cmd, identity)
        this.summaryLog = new SummaryLog(req, invoke, cmd, identity)
    }
}