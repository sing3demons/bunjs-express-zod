import express, { type Express, type Request, type Response, type NextFunction, type RequestHandler, Router } from 'express';
import { z, type ZodTypeAny } from 'zod';
import http from 'http';
import { Socket } from 'net';
import { v7 as uuid } from 'uuid'
import promBundle from 'express-prom-bundle'
import { fromZodError } from 'zod-validation-error';
const transaction = 'x-transaction-id'
const metricsMiddleware = promBundle({ includeMethod: true })

type TSchema<Query extends ZodTypeAny, Params extends ZodTypeAny, Body extends ZodTypeAny> = {
    query?: Query;
    params?: Params;
    body?: Body;
    middleware?: RequestHandler;
};

// type TRequest<Params, Query, Body> = { params: z.infer<Params>, body: z.infer<Body>, query: z.infer<Query> }
type TRequestSchema<Params, Query, Body> = { params: Params, body: Body, query: Query }

type TypedHandler<
    Query extends ZodTypeAny = z.ZodAny,
    Params extends ZodTypeAny = z.ZodAny,
    Body extends ZodTypeAny = z.ZodAny
> = (
    context: TRequestSchema<z.infer<Params>, z.infer<Query>, z.infer<Body>>,
    req: Request,
    res: Response<BaseResponse>
) => Promise<BaseResponse>;

class HttpError extends Error {
    constructor(public statusCode: number, message: string) {
        super(message)
        this.name = 'HttpError'
    }
}

class ValidationError extends HttpError {
    constructor(public message: string) {
        super(400, message)
        this.name = 'ValidationError'
    }
}

const globalErrorHandler = (
    error: unknown,
    _request: Request,
    response: Response,
    _next: NextFunction
) => {
    let statusCode = 500
    let message = 'An unknown error occurred'

    if (error instanceof HttpError) {
        statusCode = error.statusCode
    }

    if (error instanceof Error) {
        console.log(`${error.name}: ${error.message}`)
        message = error.message

        if (message.includes('not found')) {
            statusCode = 404
        }
    } else {
        console.log('Unknown error')
        message = `An unknown error occurred, ${String(error)}`
    }

    const data = {
        statusCode: statusCode,
        message,
        success: false,
        data: null,
        traceStack: process.env.NODE_ENV === 'development' && error instanceof Error ? error.stack : undefined,
    }

    response.status(statusCode).send(data)
}

class Server {
    private readonly app: Express = express();
    constructor(cb?: () => void) {
        this.app.use(express.json());
        this.app.use(express.urlencoded({ extended: true }));
        this.app.use(metricsMiddleware)
        this.app.use((req: Request, _res: Response, next: NextFunction) => {
            if (!req.headers[transaction]) {
                req.headers[transaction] = `default-${uuid()}`
            }
            next()
        })


        cb?.()
    }

    public router(path: string, router: Router, ...middleware: RequestHandler[]) {
        this.app.use(path, middleware, router)
    }

    public get<
        Query extends ZodTypeAny = z.ZodAny,
        Params extends ZodTypeAny = z.ZodAny,
        Body extends ZodTypeAny = z.ZodAny
    >(
        path: string,
        handler: TypedHandler<Query, Params, Body>,
        schema: TSchema<Query, Params, Body> = {}
    ) {
        const middlewares: Array<RequestHandler> = [];

        if (schema.middleware) {
            middlewares.push(schema.middleware);
        }

        this.app.get(
            path,
            ...middlewares,
            async (req: Request, res: Response) => {
                if (schema.params) {
                    const validation = schema.params.safeParse(req.params);
                    if (!validation.success) {
                        const validationError = fromZodError(validation.error)
                        const msg = `${validationError.message}`.replace(/"/g, `'`)
                        return res.status(400).json({
                            success: false,
                            message: msg,
                            details: validationError.details.map(detail => {
                                return {
                                    path: detail.path,
                                    message: detail.message,
                                }
                            }),
                        });
                    }
                }
                if (schema.query) {
                    const validation = schema.query.safeParse(req.query);
                    if (!validation.success) {
                        const validationError = fromZodError(validation.error)
                        const msg = `${validationError.message}`.replace(/"/g, `'`)
                        return res.status(400).json({
                            success: false,
                            message: msg,
                            details: validationError.details.map(detail => {
                                return {
                                    path: detail.path,
                                    message: detail.message,
                                }
                            }),
                        });
                    }
                }
                if (schema.body) {
                    const validation = schema.body.safeParse(req.body);
                    if (!validation.success) {
                        const validationError = fromZodError(validation.error)
                        const msg = `${validationError.message}`.replace(/"/g, `'`)
                        return res.status(400).json({
                            success: false,
                            message: msg,
                            details: validationError.details.map(detail => {
                                return {
                                    path: detail.path,
                                    message: detail.message,
                                }
                            }),
                        });
                    }
                }
                const ctx = req as Request<z.infer<Params>, any, z.infer<Body>, z.infer<Query>>
                const result = await handler(ctx, req, res)
                res.json(result);
            }
        );

        return this;
    }

    public use(middleware: RequestHandler[]) {
        this.app.use(middleware)
        return this
    }

    public post<
        Query extends ZodTypeAny = z.ZodAny,
        Params extends ZodTypeAny = z.ZodAny,
        Body extends ZodTypeAny = z.ZodAny>(path: string, handler: TypedHandler<Query, Params, Body>, schema: TSchema<Query, Params, Body> = {}) {
        const middlewares: Array<RequestHandler> = [];

        if (schema.middleware) {
            middlewares.push(schema.middleware);
        }

        this.app.post(
            path,
            ...middlewares, // Apply middleware from schema
            async (req: Request, res: Response) => {
                if (schema.params) {
                    const validation = schema.params.safeParse(req.params);
                    if (!validation.success) {
                        const validationError = fromZodError(validation.error)
                        const msg = `${validationError.message}`.replace(/"/g, `'`)
                        return res.status(400).json({
                            success: false,
                            message: msg,
                            details: validationError.details.map(detail => {
                                return {
                                    path: detail.path,
                                    message: detail.message,
                                }
                            }),
                        });
                    }
                }
                if (schema.query) {
                    const validation = schema.query.safeParse(req.query);
                    if (!validation.success) {
                        const validationError = fromZodError(validation.error)
                        const msg = `${validationError.message}`.replace(/"/g, `'`)
                        return res.status(400).json({
                            success: false,
                            message: msg,
                            details: validationError.details.map(detail => {
                                return {
                                    path: detail.path,
                                    message: detail.message,
                                }
                            }),
                        });
                    }
                }
                if (schema.body) {
                    const validation = schema.body.safeParse(req.body);
                    if (!validation.success) {
                        const validationError = fromZodError(validation.error)
                        const msg = `${validationError.message}`.replace(/"/g, `'`)
                        return res.status(400).json({
                            success: false,
                            message: msg,
                            details: validationError.details.map(detail => {
                                return {
                                    path: detail.path,
                                    message: detail.message,
                                }
                            }),
                        });
                    }
                }

                // Ensure correct type casting when passing req to handler
                const ctx = req as Request<z.infer<Params>, any, z.infer<Body>, z.infer<Query>>
                const result = await handler(ctx, req, res)
                res.json(result)
            }
        );

        return this;
    }

    public put<
        Query extends ZodTypeAny = z.ZodAny,
        Params extends ZodTypeAny = z.ZodAny,
        Body extends ZodTypeAny = z.ZodAny>(path: string, handler: TypedHandler<Query, Params, Body>, schema: TSchema<Query, Params, Body> = {}) {
        const middlewares: Array<RequestHandler> = [];

        if (schema.middleware) {
            middlewares.push(schema.middleware);
        }

        this.app.put(
            path,
            ...middlewares, // Apply middleware from schema
            async (req: Request, res: Response) => {
                if (schema.params) {
                    const validation = schema.params.safeParse(req.params);
                    if (!validation.success) {
                        const validationError = fromZodError(validation.error)
                        const msg = `${validationError.message}`.replace(/"/g, `'`)
                        return res.status(400).json({
                            success: false,
                            message: msg,
                            details: validationError.details.map(detail => {
                                return {
                                    path: detail.path,
                                    message: detail.message,
                                }
                            }),
                        });
                    }
                }
                if (schema.query) {
                    const validation = schema.query.safeParse(req.query);
                    if (!validation.success) {
                        const validationError = fromZodError(validation.error)
                        const msg = `${validationError.message}`.replace(/"/g, `'`)
                        return res.status(400).json({
                            success: false,
                            message: msg,
                            details: validationError.details.map(detail => {
                                return {
                                    path: detail.path,
                                    message: detail.message,
                                }
                            }),
                        });
                    }
                }
                if (schema.body) {
                    const validation = schema.body.safeParse(req.body);
                    if (!validation.success) {
                        const validationError = fromZodError(validation.error)
                        const msg = `${validationError.message}`.replace(/"/g, `'`)
                        return res.status(400).json({
                            success: false,
                            message: msg,
                            details: validationError.details.map(detail => {
                                return {
                                    path: detail.path,
                                    message: detail.message,
                                }
                            }),
                        });
                    }
                }

                const ctx = req as Request<z.infer<Params>, any, z.infer<Body>, z.infer<Query>>
                const result = await handler(ctx, req, res)
                res.json(result)
            }
        );
        return this;
    }

    public patch<
        Query extends ZodTypeAny = z.ZodAny,
        Params extends ZodTypeAny = z.ZodAny,
        Body extends ZodTypeAny = z.ZodAny>(path: string, handler: TypedHandler<Query, Params, Body>, schema: TSchema<Query, Params, Body> = {}) {
        const middlewares: Array<RequestHandler> = [];

        if (schema.middleware) {
            middlewares.push(schema.middleware);
        }

        this.app.patch(
            path,
            ...middlewares, // Apply middleware from schema
            async (req: Request, res: Response) => {
                if (schema.params) {
                    const validation = schema.params.safeParse(req.params);
                    if (!validation.success) {
                        const validationError = fromZodError(validation.error)
                        const msg = `${validationError.message}`.replace(/"/g, `'`)
                        return res.status(400).json({
                            success: false,
                            message: msg,
                            details: validationError.details.map(detail => {
                                return {
                                    path: detail.path,
                                    message: detail.message,
                                }
                            }),
                        });
                    }
                }
                if (schema.query) {
                    const validation = schema.query.safeParse(req.query);
                    if (!validation.success) {
                        const validationError = fromZodError(validation.error)
                        const msg = `${validationError.message}`.replace(/"/g, `'`)
                        return res.status(400).json({
                            success: false,
                            message: msg,
                            details: validationError.details.map(detail => {
                                return {
                                    path: detail.path,
                                    message: detail.message,
                                }
                            }),
                        });
                    }
                }
                if (schema.body) {
                    const validation = schema.body.safeParse(req.body);
                    if (!validation.success) {
                        const validationError = fromZodError(validation.error)
                        const msg = `${validationError.message}`.replace(/"/g, `'`)
                        return res.status(400).json({
                            success: false,
                            message: msg,
                            details: validationError.details.map(detail => {
                                return {
                                    path: detail.path,
                                    message: detail.message,
                                }
                            }),
                        });
                    }
                }

                const ctx = req as Request<z.infer<Params>, any, z.infer<Body>, z.infer<Query>>
                const result = await handler(ctx, req, res)
                res.json(result)
            }
        );

        return this;
    }

    public delete<
        Query extends ZodTypeAny = z.ZodAny,
        Params extends ZodTypeAny = z.ZodAny,
        Body extends ZodTypeAny = z.ZodAny>(path: string, handler: TypedHandler<Query, Params, Body>, schema: TSchema<Query, Params, Body> = {}) {
        const middlewares: Array<RequestHandler> = [];

        if (schema.middleware) {
            middlewares.push(schema.middleware);
        }

        this.app.delete(
            path,
            ...middlewares, // Apply middleware from schema
            async (req: Request, res: Response) => {
                if (schema.params) {
                    const validation = schema.params.safeParse(req.params);
                    if (!validation.success) {
                        const validationError = fromZodError(validation.error)
                        const msg = `${validationError.message}`.replace(/"/g, `'`)
                        return res.status(400).json({
                            success: false,
                            message: msg,
                            details: validationError.details.map(detail => {
                                return {
                                    path: detail.path,
                                    message: detail.message,
                                }
                            }),
                        });
                    }
                }
                if (schema.query) {
                    const validation = schema.query.safeParse(req.query);
                    if (!validation.success) {
                        const validationError = fromZodError(validation.error)
                        const msg = `${validationError.message}`.replace(/"/g, `'`)
                        return res.status(400).json({
                            success: false,
                            message: msg,
                            details: validationError.details.map(detail => {
                                return {
                                    path: detail.path,
                                    message: detail.message,
                                }
                            }),
                        });
                    }
                }
                if (schema.body) {
                    const validation = schema.body.safeParse(req.body);
                    if (!validation.success) {
                        const validationError = fromZodError(validation.error)
                        const msg = `${validationError.message}`.replace(/"/g, `'`)
                        return res.status(400).json({
                            success: false,
                            message: msg,
                            details: validationError.details.map(detail => {
                                return {
                                    path: detail.path,
                                    message: detail.message,
                                }
                            }),
                        });
                    }
                }

                const ctx = req as Request<z.infer<Params>, any, z.infer<Body>, z.infer<Query>>
                const result = await handler(ctx, req, res)
                res.json(result)
            }
        );

        return this;
    }

    public listen(port: number | string, close?: () => Promise<void> | void) {
        this.app.use((req: Request, res: Response, _next: NextFunction) => {
            res.status(404).json({ message: 'Unknown URL', path: req.originalUrl })
        })

        this.app.use(globalErrorHandler)
        const server = http.createServer(this.app).listen(port, () => {
            console.log(`Server is running on port: ${port}`)
        })

        const connections = new Set<Socket>();

        server.on('connection', (connection) => {
            connections.add(connection);
            connection.on('close', () => {
                connections.delete(connection);
            });
        });

        const signals = ['SIGINT', 'SIGTERM']
        signals.forEach(signal => {
            process.on(signal, () => {
                console.log(`Received ${signal}, shutting down gracefully...`);
                server.close(() => {
                    console.log('Closed out remaining connections.');
                    close?.()
                    process.exit(0);
                });

                setTimeout(() => {
                    console.error('Forcing shutdown as server is taking too long to close.');
                    connections.forEach((connection) => {
                        connection.destroy();
                    });
                    close?.()
                    process.exit(1);
                }, 10000);
            });
        });
    }
}

export default Server;
interface BaseResponse<T = unknown> {
    statusCode?: number
    message?: string
    /**
     * @default true
     */
    success?: boolean
    data?: T
    traceStack?: string
    page?: number
    pageSize?: number
    total?: number
}

class MyRouter {
    constructor(private readonly instance: Router = Router()) { }

    public Register() {
        return this.instance
    }

    public get<
        Query extends ZodTypeAny = z.ZodAny,
        Params extends ZodTypeAny = z.ZodAny,
        Body extends ZodTypeAny = z.ZodAny
    >(
        path: string,
        handler: TypedHandler<Query, Params, Body>,
        schema: TSchema<Query, Params, Body> = {}
    ) {
        const middlewares: Array<RequestHandler> = [];

        if (schema.middleware) {
            middlewares.push(schema.middleware);
        }

        this.instance.get(
            path,
            ...middlewares, // Apply middleware from schema
            async (req: Request, res: Response) => {
                if (schema.params) {
                    const validation = schema.params.safeParse(req.params);
                    if (!validation.success) {
                        const validationError = fromZodError(validation.error)
                        const msg = `${validationError.message}`.replace(/"/g, `'`)
                        return res.status(400).json({
                            success: false,
                            message: msg,
                            details: validationError.details.map(detail => {
                                return {
                                    path: detail.path,
                                    message: detail.message,
                                }
                            }),
                        });
                    }
                }
                if (schema.query) {
                    const validation = schema.query.safeParse(req.query);
                    if (!validation.success) {
                        const validationError = fromZodError(validation.error)
                        const msg = `${validationError.message}`.replace(/"/g, `'`)
                        return res.status(400).json({
                            success: false,
                            message: msg,
                            details: validationError.details.map(detail => {
                                return {
                                    path: detail.path,
                                    message: detail.message,
                                }
                            }),
                        });
                    }
                }
                if (schema.body) {
                    const validation = schema.body.safeParse(req.body);
                    if (!validation.success) {
                        const validationError = fromZodError(validation.error)
                        const msg = `${validationError.message}`.replace(/"/g, `'`)
                        return res.status(400).json({
                            success: false,
                            message: msg,
                            details: validationError.details.map(detail => {
                                return {
                                    path: detail.path,
                                    message: detail.message,
                                }
                            }),
                        });
                    }
                }

                const { params, body, query } = req as Request<z.infer<Params>, any, z.infer<Body>, z.infer<Query>>
                const ctx = { params, body, query } as { params: z.infer<Params>, body: z.infer<Body>, query: z.infer<Query> }
                const result = await handler(ctx, req, res)
                res.json(result)
            }
        );

        return this;
    }

    public use(middleware: (req: Request, res: Response, next: NextFunction) => void) {
        this.instance.use(middleware)
        return this
    }

    public post<
        Query extends ZodTypeAny = z.ZodAny,
        Params extends ZodTypeAny = z.ZodAny,
        Body extends ZodTypeAny = z.ZodAny>(path: string, handler: TypedHandler<Query, Params, Body>, schema: TSchema<Query, Params, Body> = {}) {
        const middlewares: Array<RequestHandler> = [];

        if (schema.middleware) {
            middlewares.push(schema.middleware);
        }

        this.instance.post(
            path,
            ...middlewares, // Apply middleware from schema
            async (req: Request, res: Response) => {
                if (schema.params) {
                    const validation = schema.params.safeParse(req.params);
                    if (!validation.success) {
                        const validationError = fromZodError(validation.error)
                        const msg = `${validationError.message}`.replace(/"/g, `'`)
                        return res.status(400).json({
                            success: false,
                            message: msg,
                            details: validationError.details.map(detail => {
                                return {
                                    path: detail.path,
                                    message: detail.message,
                                }
                            }),
                        });
                    }
                }
                if (schema.query) {
                    const validation = schema.query.safeParse(req.query);
                    if (!validation.success) {
                        const validationError = fromZodError(validation.error)
                        const msg = `${validationError.message}`.replace(/"/g, `'`)
                        return res.status(400).json({
                            success: false,
                            message: msg,
                            details: validationError.details.map(detail => {
                                return {
                                    path: detail.path,
                                    message: detail.message,
                                }
                            }),
                        });
                    }
                }
                if (schema.body) {
                    const validation = schema.body.safeParse(req.body);
                    if (!validation.success) {
                        const validationError = fromZodError(validation.error)
                        const msg = `${validationError.message}`.replace(/"/g, `'`)
                        return res.status(400).json({
                            success: false,
                            message: msg,
                            details: validationError.details.map(detail => {
                                return {
                                    path: detail.path,
                                    message: detail.message,
                                }
                            }),
                        });
                    }
                }

                const ctx = req as Request<z.infer<Params>, any, z.infer<Body>, z.infer<Query>>
                const result = await handler(ctx, req, res)

                if (result?.statusCode) {
                    const statusCode = result.statusCode.toString().substring(0, 3)
                    res.status(+statusCode)
                    delete result.statusCode
                } else {
                    res.status(200)
                }

                res.json(result)
            }
        );

        return this;
    }

    public put<
        Query extends ZodTypeAny = z.ZodAny,
        Params extends ZodTypeAny = z.ZodAny,
        Body extends ZodTypeAny = z.ZodAny>(path: string, handler: TypedHandler<Query, Params, Body>, schema: TSchema<Query, Params, Body> = {}) {
        const middlewares: Array<RequestHandler> = [];

        if (schema.middleware) {
            middlewares.push(schema.middleware);
        }

        this.instance.put(
            path,
            ...middlewares, // Apply middleware from schema
            async (req: Request, res: Response) => {
                if (schema.params) {
                    const validation = schema.params.safeParse(req.params);
                    if (!validation.success) {
                        const validationError = fromZodError(validation.error)
                        const msg = `${validationError.message}`.replace(/"/g, `'`)
                        return res.status(400).json({
                            success: false,
                            message: msg,
                            details: validationError.details.map(detail => {
                                return {
                                    path: detail.path,
                                    message: detail.message,
                                }
                            }),
                        });
                    }
                }
                if (schema.query) {
                    const validation = schema.query.safeParse(req.query);
                    if (!validation.success) {
                        const validationError = fromZodError(validation.error)
                        const msg = `${validationError.message}`.replace(/"/g, `'`)
                        return res.status(400).json({
                            success: false,
                            message: msg,
                            details: validationError.details.map(detail => {
                                return {
                                    path: detail.path,
                                    message: detail.message,
                                }
                            }),
                        });
                    }
                }
                if (schema.body) {
                    const validation = schema.body.safeParse(req.body);
                    if (!validation.success) {
                        const validationError = fromZodError(validation.error)
                        const msg = `${validationError.message}`.replace(/"/g, `'`)
                        return res.status(400).json({
                            success: false,
                            message: msg,
                            details: validationError.details.map(detail => {
                                return {
                                    path: detail.path,
                                    message: detail.message,
                                }
                            }),
                        });
                    }
                }

                const ctx = req as Request<z.infer<Params>, any, z.infer<Body>, z.infer<Query>>
                const result = await handler(ctx, req, res)
                res.json(result)
            }
        );
        return this;
    }

    public patch<
        Query extends ZodTypeAny = z.ZodAny,
        Params extends ZodTypeAny = z.ZodAny,
        Body extends ZodTypeAny = z.ZodAny>(path: string, handler: TypedHandler<Query, Params, Body>, schema: TSchema<Query, Params, Body> = {}) {
        const middlewares: Array<RequestHandler> = [];

        if (schema.middleware) {
            middlewares.push(schema.middleware);
        }

        this.instance.patch(
            path,
            ...middlewares, // Apply middleware from schema
            async (req: Request, res: Response) => {
                if (schema.params) {
                    const validation = schema.params.safeParse(req.params);
                    if (!validation.success) {
                        const validationError = fromZodError(validation.error)
                        const msg = `${validationError.message}`.replace(/"/g, `'`)
                        return res.status(400).json({
                            success: false,
                            message: msg,
                            details: validationError.details.map(detail => {
                                return {
                                    path: detail.path,
                                    message: detail.message,
                                }
                            }),
                        });
                    }
                }
                if (schema.query) {
                    const validation = schema.query.safeParse(req.query);
                    if (!validation.success) {
                        const validationError = fromZodError(validation.error)
                        const msg = `${validationError.message}`.replace(/"/g, `'`)
                        return res.status(400).json({
                            success: false,
                            message: msg,
                            details: validationError.details.map(detail => {
                                return {
                                    path: detail.path,
                                    message: detail.message,
                                }
                            }),
                        });
                    }
                }
                if (schema.body) {
                    const validation = schema.body.safeParse(req.body);
                    if (!validation.success) {
                        const validationError = fromZodError(validation.error)
                        const msg = `${validationError.message}`.replace(/"/g, `'`)
                        return res.status(400).json({
                            success: false,
                            message: msg,
                            details: validationError.details.map(detail => {
                                return {
                                    path: detail.path,
                                    message: detail.message,
                                }
                            }),
                        });
                    }
                }
                const ctx = req as Request<z.infer<Params>, any, z.infer<Body>, z.infer<Query>>
                const result = await handler(ctx, req, res)
                res.json(result)
            }
        );

        return this;
    }

    public delete<
        Query extends ZodTypeAny = z.ZodAny,
        Params extends ZodTypeAny = z.ZodAny,
        Body extends ZodTypeAny = z.ZodAny>(path: string, handler: TypedHandler<Query, Params, Body>, schema: TSchema<Query, Params, Body> = {}) {
        const middlewares: Array<RequestHandler> = [];

        if (schema.middleware) {
            middlewares.push(schema.middleware);
        }

        this.instance.delete(
            path,
            ...middlewares, // Apply middleware from schema
            async (req: Request, res: Response) => {
                if (schema.params) {
                    const validation = schema.params.safeParse(req.params);
                    if (!validation.success) {
                        const validationError = fromZodError(validation.error)
                        const msg = `${validationError.message}`.replace(/"/g, `'`)
                        return res.status(400).json({
                            success: false,
                            message: msg,
                            details: validationError.details.map(detail => {
                                return {
                                    path: detail.path,
                                    message: detail.message,
                                }
                            }),
                        });
                    }
                }
                if (schema.query) {
                    const validation = schema.query.safeParse(req.query);
                    if (!validation.success) {
                        const validationError = fromZodError(validation.error)
                        const msg = `${validationError.message}`.replace(/"/g, `'`)
                        return res.status(400).json({
                            success: false,
                            message: msg,
                            details: validationError.details.map(detail => {
                                return {
                                    path: detail.path,
                                    message: detail.message,
                                }
                            }),
                        });
                    }
                }
                if (schema.body) {
                    const validation = schema.body.safeParse(req.body);
                    if (!validation.success) {
                        const validationError = fromZodError(validation.error)
                        const msg = `${validationError.message}`.replace(/"/g, `'`)
                        return res.status(400).json({
                            success: false,
                            message: msg,
                            details: validationError.details.map(detail => {
                                return {
                                    path: detail.path,
                                    message: detail.message,
                                }
                            }),
                        });
                    }
                }
                const ctx = req as Request<z.infer<Params>, any, z.infer<Body>, z.infer<Query>>
                const result = await handler(ctx, req, res)
                res.json(result)
            }
        );

        return this;
    }
}

export { z as t, MyRouter }
