import type { DetailLog, SummaryLog } from "../server/logger";
import type { t } from "../server";
import { createUserSchema, loginSchema, paramsSchema, type ReturnTypeResponse, type User } from "./schema";
import jwt from "jsonwebtoken";
import config from "../server/config";
import type { TPrismaClient } from "../db";


export default class AuthService {
    constructor(private readonly prisma: TPrismaClient) { }
    private node = 'postgres'

    private query = (detailLog: DetailLog) => {
        this.prisma.$on('query', (e) => {
            detailLog?.addInputRequest(this.node, 'query', 'initInvoke', {
                query: e.query.replace(/"/g, `'`),
                params: e.params.replace(/"/g, `'`),
                duration: `${e.duration} ms`,
                target: e.target
            })
        })

        return this.prisma
    }

    private hashPassword = async (password: string) => await Bun.password.hash(password)
    private verifyPassword = async (password: string, hash: string) => await Bun.password.verify(password, hash)

    async createUser(data: t.infer<typeof createUserSchema>, detailLog: DetailLog, summaryLog: SummaryLog): ReturnTypeResponse<{}> {
        const cmd = 'insert-user', invoke = 'initInvoke'
        try {
            const { username, password, email, firstName, lastName, address, phone, status } = data
            const checkUser = await this.query(detailLog).user.findUnique({
                where: { email, deleted: false },
                select: { password: false, id: true, email: true }
            })
            detailLog.addOutputRequest(this.node, 'select-user', invoke, checkUser)
            summaryLog.addSuccessBlock(this.node, 'select-user', '20000', 'Success')
            if (checkUser) {
                return {
                    statusCode: 400,
                    success: false,
                    message: 'User already exists',
                    data: []
                }
            }
            const hashedPassword = await this.hashPassword(password)

            const bodyUser = {
                email,
                password: hashedPassword,
                createBy: username,
                updateBy: username
            }

            const result = await this.query(detailLog).user.create({
                data: bodyUser,
                select: { password: false, id: true, email: true }
            })

            detailLog.addOutputRequest(this.node, cmd, invoke, result)
            summaryLog.addSuccessBlock(this.node, cmd, '20000', 'Success')

            if (firstName || lastName || address || phone || status) {
                const body = {
                    firstName,
                    lastName,
                    address,
                    phone,
                    status,
                    userId: result.id,
                    createBy: username,
                    updateBy: username,
                    username: username,
                }

                const resultProfile = await this.query(detailLog).profile.create({ data: body })
                detailLog.addOutputRequest(this.node, 'insert-profile', invoke, resultProfile)
                summaryLog.addSuccessBlock(this.node, cmd, '20000', 'Success')
            }

            return {
                statusCode: 200,
                success: true,
                message: 'Success',
                data: result
            }

        } catch (error) {
            detailLog.addError(this.node, 'insert-user', 'initInvoke', error);
            summaryLog.addErrorBlock(this.node, 'insert-user', '500', 'An error occurred')
            throw error
        }
    }

    public async findUser(query: t.infer<typeof createUserSchema>, detailLog: DetailLog, summaryLog: SummaryLog): ReturnTypeResponse<{}[]> {
        try {
            const cmd = 'select-user', invoke = 'initInvoke'
            const result = await this.query(detailLog).user.findMany({
                where: { deleted: false },
                select: { password: false, id: true, email: true }
            })
            detailLog.addOutputRequest(this.node, cmd, invoke, result)
            summaryLog.addSuccessBlock(this.node, cmd, '20000', 'Success')
            return {
                statusCode: 200,
                success: true,
                data: result,
                message: 'Success',
            }
        } catch (error) {
            detailLog.addError(this.node, 'select-user', 'initInvoke', error);
            summaryLog.addErrorBlock(this.node, 'select-user', '500', 'An error occurred')
            throw error
        }
    }

    public async findUserById(params: t.infer<typeof paramsSchema>, detailLog: DetailLog, summaryLog: SummaryLog): ReturnTypeResponse<User | null> {
        try {
            const cmd = 'select-user', invoke = 'initInvoke'
            const result = await this.query(detailLog).user.findUnique({
                where: { id: params.id, deleted: false },
                include: { profile: true },
            })

            if (!result) {
                return {
                    success: false,
                    data: null,
                    message: 'User not found',
                    statusCode: 404
                }
            }

            if (result?.password) {
                delete (result as { password?: string }).password;
            }
            detailLog.addOutputRequest(this.node, cmd, invoke, result)
            summaryLog.addSuccessBlock(this.node, cmd, '20000', 'Success')
            return {
                success: true,
                message: 'Success',
                statusCode: 200,
                data: result as unknown as User,
            }
        } catch (error) {
            detailLog.addError(this.node, 'select-user', 'initInvoke', error);
            summaryLog.addErrorBlock(this.node, 'select-user', '500', 'An error occurred')
            throw error
        }
    }

    private generateToken = <T extends {}>(data: T, type: 'ACCESS' | 'REFRESH' = 'ACCESS', expiresIn: string) => {
        if (type === 'ACCESS') {
            const secret = config.get('privateKey')
            const options: jwt.SignOptions = {
                expiresIn: expiresIn ?? '1h',
                algorithm: 'RS256',
            }
            const secretOrPrivateKey = Buffer.from(secret, 'base64')
            const token = jwt.sign(data, secretOrPrivateKey, options)
            return token
        } else {
            const secret = config.get('refreshPrivateKey')
            const options: jwt.SignOptions = {
                expiresIn: '1h',
                algorithm: 'RS256',
            }
            const secretOrPrivateKey = Buffer.from(secret, 'base64')
            const token = jwt.sign(data, secretOrPrivateKey, options)
            return token
        }
    }

    private verifyToken = async (token: string, type: 'ACCESS' | 'REFRESH' = 'ACCESS') => {
        if (type === 'ACCESS') {
            return jwt.verify(token, config.get('publicKey'))
        }
        return jwt.verify(token, config.get('refreshPublicKey'))
    }


    public async login({ email, password }: t.infer<typeof loginSchema>, detailLog: DetailLog, summaryLog: SummaryLog): ReturnTypeResponse<{}> {
        try {
            const cmd = 'select-user', invoke = 'initInvoke'
            const result = await this.query(detailLog).user.findUnique({
                where: { email, deleted: false },
                include: { profile: true }
            })
            detailLog.addOutputRequest(this.node, cmd, invoke, result)
            summaryLog.addSuccessBlock(this.node, cmd, '20000', 'Success')
            if (!result) {
                return {
                    statusCode: 404,
                    success: false,
                    message: 'User not found',
                    data: []
                }
            }
            const verifyPassword = await this.verifyPassword(password, result.password)
            if (!verifyPassword) {
                return {
                    statusCode: 400,
                    success: false,
                    message: 'Password is incorrect',
                    data: []
                }
            }

            return {
                statusCode: 200,
                success: true,
                message: 'Success',
                data: {
                    access_token: this.generateToken({ id: result.id, email: result.email, role: result.role }, 'ACCESS', '1h'),
                    refresh_token: this.generateToken({ email: result.email }, 'REFRESH', '1d')
                }

            }
        } catch (error) {
            detailLog.addError(this.node, 'select-user', 'initInvoke', error);
            summaryLog.addErrorBlock(this.node, 'select-user', '500', 'An error occurred')
            throw error
        }
    }
}