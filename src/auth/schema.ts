import type { number } from "zod";
import { t } from "../server";

// Example schemas
const paramsSchema = t.object({
    id: t.string(),
});

const querySchema = t.object({
    search: t.string().optional(),
});

const createUserSchema = t.object({
    firstName: t.string(),
    lastName: t.string(),
    username: t.string(),
    password: t.string(),
    email: t.string().email(),
    phone: t.string().optional(),
    address: t.string().optional(),
    role: t.string().default('user').optional(),
    status: t.string().optional(),
});

const loginSchema = t.object({
    email: t.string().email(),
    password: t.string(),
})

export type Profile = {
    id: string
    href: string
    bio: string
    userId: string
    langCode: string
    firstName: string
    lastName: string
    username: string
    phone: string
    address: string
    status: string
}

export type User = {
    id: string
    href: string
    email: string
    role: string
    profile: Profile[]
}

export { paramsSchema, querySchema, createUserSchema, loginSchema };

export type ReturnTypeResponse<T extends unknown> = Promise<{
    statusCode: number,
    success: boolean,
    message: string,
    data: T
}>
