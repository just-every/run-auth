import type { AuthRuntime } from '../auth/index.mjs'
import type { ToolContext, ResourceContext } from '../modules/agent-door/index.ts'
type Native = AuthRuntime['context']
type Context = ToolContext | ResourceContext
export function read(native: Native, ctx: Context, path: string, scope: string, query?: Record<string, unknown>): Promise<Record<string, any>>
export function write(native: Native, ctx: ToolContext, path: string, method: string, data: Record<string, unknown>, scope: string): Promise<Record<string, any>>
export function snapshot(native: Native, ctx: Context): Promise<Record<string, string>>
export function group(native: Native, ctx: Context, id: string): Promise<{id: string; name: string}>
export function membership(native: Native, ctx: Context, id: unknown): Promise<{groupId: string; personId: string; present: boolean}>
export function internalGroup(native: Native, ctx: Context, id: string): Promise<void>
export function nativeAdmission(native: Native, person: {id: string; email: string; role: string}): Promise<boolean>
export function nativeLauncher(native: Native, personId: string): Promise<unknown[]>
