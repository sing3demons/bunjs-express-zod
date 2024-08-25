import config from "../config";
import authMiddleware from "../middleware/auth";
import type { MyRouter } from "../server";
import Logger from "../server/logger";
import { createUserSchema, loginSchema, paramsSchema, type Profile, type User } from "./schema";
import type AuthService from "./service";

export default class AuthController {
    constructor(
        private readonly router: MyRouter,
        private readonly authService: AuthService,
    ) {
        this.findUser()
        this.register()
        this.login()
        this.profile()
        this.verifyToken()
        this.findUserById()
    }
    private register() {
        this.router.post(
            '/register',
            async ({ body }, req) => {

                const cmd = 'post-register', invoke = 'initInvoke', node = 'client'
                const { detailLog, summaryLog } = new Logger(req, invoke, cmd, '');
                try {
                    detailLog.addInputRequest(node, cmd, invoke, body);
                    summaryLog.addSuccessBlock(node, cmd, 'null', 'Success')
                    const response = await this.authService.createUser(body, detailLog, summaryLog)

                    detailLog.addOutputRequest(node, cmd, invoke, response)
                    summaryLog.addSuccessBlock(node, cmd, '20000', 'Success')

                    return response
                } catch (error) {
                    detailLog.addError(node, cmd, invoke, error);
                    summaryLog.addErrorBlock(node, cmd, '500', 'An error occurred');
                    return {
                        statusCode: 500,
                        error: 'An error occurred'
                    }
                } finally {
                    detailLog.end()
                    summaryLog.end()
                }
            },
            {
                body: createUserSchema
            }
        )
    }

    private login() {
        this.router.post(
            '/login',
            async ({ body }, req) => {
                const cmd = 'post-login', invoke = 'initInvoke', node = 'client'
                const { detailLog, summaryLog } = new Logger(req, invoke, cmd, '');
                try {
                    detailLog.addInputRequest(node, cmd, invoke, {});
                    summaryLog.addSuccessBlock(node, cmd, 'null', 'Success')
                    const response = await this.authService.login(body, detailLog, summaryLog)

                    detailLog.addOutputRequest(node, cmd, invoke, response)
                    summaryLog.addSuccessBlock(node, cmd, '20000', 'Success')

                    return response
                } catch (error) {
                    detailLog.addError(node, cmd, invoke, error);
                    summaryLog.addErrorBlock(node, cmd, '500', 'An error occurred');
                    return { statusCode: 500, error: 'An error occurred' }
                } finally {
                    detailLog.end()
                    summaryLog.end()
                }
            },
            {
                body: loginSchema
            }
        )
    }

    private findUser = () => this.router.get('/users', async ({ query }, req) => {
        const cmd = 'post-register', invoke = 'initInvoke', node = 'client'
        const { detailLog, summaryLog } = new Logger(req, invoke, cmd, '');
        try {
            detailLog.addInputRequest(node, cmd, invoke, query);
            summaryLog.addSuccessBlock(node, cmd, 'null', 'Success')
            const response = await this.authService.findUser(query, detailLog, summaryLog)
            return { data: response }
        } catch (error) {
            detailLog.addError(node, cmd, invoke, error);
            summaryLog.addErrorBlock(node, cmd, '500', 'An error occurred');
            return { error: 'An error occurred' }
        } finally {
            detailLog.end()
            summaryLog.end()
        }
    }, {
        middleware: authMiddleware
    })

    private findUserById = () => this.router.get('/users/:id', async ({ params }, req) => {
        const cmd = 'get-user', invoke = 'initInvoke', node = 'client'
        const { detailLog, summaryLog } = new Logger(req, invoke, cmd, '');
        try {
            detailLog.addInputRequest(node, cmd, invoke, {});
            summaryLog.addSuccessBlock(node, cmd, 'null', 'Success')

            const { data, success, message, statusCode } = await this.authService.findUserById({ id: params.id }, detailLog, summaryLog)
            const profile: Profile[] = []

            if (data?.profile.length) {
                data.profile.forEach((item: any) => {
                    const profileData: Profile = {
                        id: item.id,
                        href: `/profile/${item.id}`,
                        bio: item?.bio || '',
                        userId: item.userId,
                        langCode: item.langCode,
                        firstName: item.firstName || '',
                        lastName: item.lastName || '',
                        username: item.username || '',
                        phone: item.phone || '',
                        address: item.address || '',
                        status: item.status || '',
                    }
                    profile.push(profileData)
                })
            }
            const users: User = {
                id: data?.id || '',
                href: data?.id ? `/users/${data?.id}` : '',
                email: data?.email || '',
                role: data?.role || '',
                profile: profile

            }

            detailLog.addOutputResponse(node, cmd, invoke, users)
            summaryLog.addSuccessBlock(node, cmd, '20000', 'Success')
            return { data: users, success, message, statusCode }
        } catch (error) {
            detailLog.addError(node, cmd, invoke, error);
            summaryLog.addErrorBlock(node, cmd, '500', 'An error occurred');
            return {
                statusCode: 500,
                message: 'An error occurred'
            }
        } finally {
            detailLog.end()
            summaryLog.end()
        }
    }, {
        middleware: authMiddleware,
        params: paramsSchema
    })

    private profile = () => this.router.get('/profile', async ({ }, req) => {
        const cmd = 'get-profile', invoke = 'initInvoke', node = 'client'
        const { detailLog, summaryLog } = new Logger(req, invoke, cmd, '');
        const { id } = <{ id: string }>req.signedToken

        try {
            detailLog.addInputRequest(node, cmd, invoke, {});
            summaryLog.addSuccessBlock(node, cmd, 'null', 'Success')

            const { data, success, message, statusCode } = await this.authService.findUserById({ id }, detailLog, summaryLog)
            const profile: Profile[] = []

            if (data?.profile.length) {
                data.profile.forEach((item: any) => {
                    const profileData: Profile = {
                        id: item.id,
                        href: `${config.get('host')}/api/auth/profile/${item.id}`,
                        bio: item?.bio || '',
                        userId: item.userId,
                        langCode: item.langCode,
                        firstName: item.firstName || '',
                        lastName: item.lastName || '',
                        username: item.username || '',
                        phone: item.phone || '',
                        address: item.address || '',
                        status: item.status || '',
                    }
                    profile.push(profileData)
                })
            }
            const users: User = {
                id: data?.id || '',
                href: data?.id ? `${config.get('host')}/api/auth/users/${data?.id}` : '',
                email: data?.email || '',
                role: data?.role || '',
                profile: profile

            }

            detailLog.addOutputResponse(node, cmd, invoke, users)
            summaryLog.addSuccessBlock(node, cmd, '20000', 'Success')
            return { data: users, success, message, statusCode }
        } catch (error) {
            detailLog.addError(node, cmd, invoke, error);
            summaryLog.addErrorBlock(node, cmd, '500', 'An error occurred');
            return {
                statusCode: 500,
                message: 'An error occurred'
            }

        } finally {
            detailLog.end()
            summaryLog.end()
        }
    }, {
        middleware: authMiddleware
    })

    private verifyToken = () => this.router.post('/verify-token', async ({ body }, req) => {
        const cmd = 'post-verify-token', invoke = 'initInvoke', node = 'client'
        const { detailLog, summaryLog } = new Logger(req, invoke, cmd, '');
        try {
            detailLog.addInputRequest(node, cmd, invoke, body);
            summaryLog.addSuccessBlock(node, cmd, 'null', 'Success')
            const response = await this.authService.verifyToken(body, detailLog, summaryLog)
            detailLog.addOutputRequest(node, cmd, invoke, response)
            summaryLog.addSuccessBlock(node, cmd, '20000', 'Success')
            return response
        } catch (error) {
            detailLog.addError(node, cmd, invoke, error);
            summaryLog.addErrorBlock(node, cmd, '500', 'An error occurred');
            return { statusCode: 500, error: 'An error occurred' }
        } finally {
            detailLog.end()
            summaryLog.end()
        }
    })

    execute = () => this.router.Register()
}