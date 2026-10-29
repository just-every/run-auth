import type { JsonSchema } from '../modules/agent-door/index.ts'

export const string = { type: 'string', minLength: 1, maxLength: 256 }
export const object = (properties: Record<string, JsonSchema> = {}, required = Object.keys(properties)) => ({ type: 'object' as const, properties, required, additionalProperties: false })
export const identity = object({ id: string, email: string, name: { type: 'string' }, state: { type: 'string', enum: ['active', 'invited', 'suspended', 'terminated'] } })
export const group = object({ id: string, name: { type: 'string' }, rule: { type: ['object', 'null'] } })
export const page = (record: JsonSchema) => object({ items: { type: 'array', items: record }, total: { type: 'integer', minimum: 0 }, nextOffset: { type: ['integer', 'null'] } })
export const recordOrPage = (record: JsonSchema) => ({ oneOf: [record, page(record)] })
export const snapshot = object({ people: string, groups: string, apps: string, assignments: string })
export const membership = object({ id: string })
export const createdGroup = object({ id: string, name: { type: 'string' } })
export const launcher = object({ tiles: { type: 'array', items: { type: 'object' } } })
export const activity = page({ type: 'object' })
