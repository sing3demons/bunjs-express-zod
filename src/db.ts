import { PrismaClient, Prisma } from "@prisma/client";
import type { DefaultArgs } from "@prisma/client/runtime/library";
const prismaOptions: Prisma.PrismaClientOptions = {
    log: [
        {
            emit: 'event',
            level: 'query',
        },
        {
            emit: 'stdout',
            level: 'error',
        },
        {
            emit: 'stdout',
            level: 'info',
        },
        {
            emit: 'stdout',
            level: 'warn',
        },
    ],
}

export type TPrismaClient = PrismaClient<{
    log: ({
        emit: "event";
        level: "query";
    } | {
        emit: "stdout";
        level: "error";
    } | {
        emit: "stdout";
        level: "info";
    } | {
        emit: "stdout";
        level: "warn";
    })[];
}, "query", DefaultArgs>

const prisma = new PrismaClient(prismaOptions)

export default prisma;
export const connect = async () => await prisma.$connect();
export const disconnect = async () => await prisma.$disconnect();

