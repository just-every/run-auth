export function organizationDatabase(db:D1Database,id:string):Promise<{db:D1Database;organization:{id:string;name:string;namespace:string;status:string}}|null>;
