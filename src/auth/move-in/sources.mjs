// Each export is read only through column and field names its provider documents
// (see tests/fixtures/move-in/README.md for the pages and read dates). A column
// that could not be confirmed is not read: its value is treated as absent.
const text=value=>typeof value==='string'?value.trim():typeof value==='number'?String(value):'';
const joined=(...parts)=>parts.map(text).filter(Boolean).join(' ');
const flag=value=>{const v=text(String(value??'')).toLowerCase();return v==='true'?true:v==='false'?false:null;};
const context=(label,value)=>text(value)?[`${label} ${text(value)}`]:[];

// CSV sources: recognised by the documented header names.
export const CSV_SOURCES=[
 {system:'google',format:'csv',label:'Google Workspace user list (CSV)',
  // Documented in the Admin Help CSV page; "Status [READ ONLY]" is not, so a
  // Google CSV carries no disabled state and no source id here.
  detect:headers=>headers.includes('Email Address [Required]')&&headers.includes('First Name [Required]'),
  columns:['Email Address [Required]','First Name [Required]','Last Name [Required]','Org Unit Path [Required]'],
  map:row=>({sourceId:null,email:row['Email Address [Required]'],name:joined(row['First Name [Required]'],row['Last Name [Required]']),disabled:null,groups:context('Org unit',row['Org Unit Path [Required]'])})},
 {system:'microsoft',format:'csv',label:'Microsoft Entra user list (CSV)',
  detect:headers=>headers.includes('userPrincipalName')&&headers.includes('objectId'),
  columns:['objectId','mail','userPrincipalName','displayName','givenName','surname','accountEnabled','department'],
  map:row=>{const enabled=flag(row.accountEnabled);return {sourceId:row.objectId,email:text(row.mail)||row.userPrincipalName,name:text(row.displayName)||joined(row.givenName,row.surname),disabled:enabled===null?null:!enabled,groups:context('Department',row.department)};}},
 {system:'auth0',format:'csv',label:'Auth0 bulk user export (CSV)',
  // Auth0 escapes every exported string with a leading single quote.
  detect:headers=>headers.includes('user_id')&&headers.includes('email'),
  columns:['user_id','email','name','given_name','family_name','blocked'],
  unescape:value=>value.startsWith("'")?value.slice(1):value,
  map:row=>({sourceId:row.user_id,email:row.email,name:text(row.name)||joined(row.given_name,row.family_name),disabled:flag(row.blocked),groups:[]})},
 {system:'jumpcloud',format:'csv',label:'JumpCloud user list (CSV)',
  // The portal page names no columns; these are JumpCloud's systemuser field names.
  detect:headers=>headers.includes('email')&&headers.includes('username')&&!headers.includes('user_id'),
  columns:['_id','id','email','displayname','firstname','lastname','suspended','state','department'],
  map:row=>jumpcloud(row)},
];

function jumpcloud(user) {
 const suspended=flag(user.suspended),state=text(user.state).toUpperCase();
 return {sourceId:user._id??user.id,email:user.email,name:text(user.displayname)||joined(user.firstname,user.lastname),disabled:suspended===true||state==='SUSPENDED'?true:suspended===false||state==='ACTIVATED'?false:null,groups:context('Department',user.department)};
}

// JSON sources: recognised by the documented field names of their user objects.
const object=value=>value&&typeof value==='object'&&!Array.isArray(value);
export const JSON_SOURCES=[
 {system:'custom',format:'json',label:'Reviewed custom directory (v1)',
  list:value=>object(value)&&value.format==='auth-custom-directory'&&value.version===1&&Array.isArray(value.people)?value.people:null,
  detect:user=>typeof user.directory_id==='string'&&typeof user.email==='string',
  map:user=>({sourceId:user.directory_id,email:user.email,name:user.name,disabled:typeof user.disabled==='boolean'?user.disabled:null,groups:[],history:user.history??[]})},
 {system:'google',format:'json',label:'Google Workspace user list (JSON)',
  list:value=>Array.isArray(value)?value:object(value)&&Array.isArray(value.users)?value.users:null,
  detect:user=>'primaryEmail' in user,
  map:user=>({sourceId:user.id,email:user.primaryEmail,name:text(user.name?.fullName)||joined(user.name?.givenName,user.name?.familyName),disabled:user.suspended===true||user.archived===true?true:user.suspended===false?false:null,groups:context('Org unit',user.orgUnitPath)})},
 {system:'okta',format:'json',label:'Okta Users API list (JSON)',
  list:value=>Array.isArray(value)?value:null,
  detect:user=>object(user.profile)&&typeof user.status==='string'&&'id' in user,
  map:user=>({sourceId:user.id,email:text(user.profile.email)||user.profile.login,name:text(user.profile.displayName)||joined(user.profile.firstName,user.profile.lastName),disabled:['SUSPENDED','DEPROVISIONED'].includes(user.status)?true:user.status?false:null,groups:context('Department',user.profile.department)})},
 {system:'auth0',format:'ndjson',label:'Auth0 bulk user export (NDJSON)',
  list:value=>Array.isArray(value)?value:object(value)&&'user_id' in value?[value]:null,
  detect:user=>'user_id' in user&&'email' in user,
  map:user=>({sourceId:user.user_id,email:user.email,name:text(user.name)||joined(user.given_name,user.family_name),disabled:typeof user.blocked==='boolean'?user.blocked:null,groups:[]})},
 {system:'jumpcloud',format:'json',label:'JumpCloud user list (JSON)',
  list:value=>Array.isArray(value)?value:object(value)&&Array.isArray(value.results)?value.results:null,
  detect:user=>'email' in user&&'username' in user,
  map:user=>jumpcloud(user)},
];

export const SOURCE_NAMES={custom:'Custom directory',google:'Google Workspace',microsoft:'Microsoft Entra',auth0:'Auth0',okta:'Okta',jumpcloud:'JumpCloud'};
