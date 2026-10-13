import {readFile} from 'node:fs/promises';
// Split a migration into statements, keeping trigger bodies whole.
export function statements(sql) {
 const text=sql.replace(/^\s*--.*$/gm,''),out=[];
 const pattern=/\s*(CREATE TRIGGER[\s\S]*?\bEND;|[^;]+;)/gy;
 for(let m;(m=pattern.exec(text));)if(m[1].trim()!==';')out.push(m[1].trim());
 return out;
}
export async function apply(db,root,files) {
 for(const file of files)for(const sql of statements(await readFile(new URL(file,root),'utf8')))await db.prepare(sql).run();
}
