# Attribute mapping expressions

Auth mapping language **version 1** computes values from directory, source,
manager and group data. Expressions are JSON data, never JavaScript. They cannot
call a network, read environment variables, read credentials, mutate a person,
or resolve a field name dynamically. Saved mappings must record their language
version independently of their revision/audit version. Version 1 also accepts
an explicit envelope: `{"version":1,"expression":NODE}`. Other versions fail.

`validateExpression(expression, schema)` returns `text`, `number`, `boolean`,
`date`, `person`, `choice`, `list`, or `null`. A schema is
`{fields:{department:"text",start_date:"date"},manager:{department:"text"}}`.
Manager fields default to the field schema if `manager` is omitted. Email,
name, person_id, first_name and last_name are built-in text fields in both maps.
Date, person and choice values have string representations and can be used by
string functions. Incompatible types, unknown fields/functions, extra node
properties and malformed nodes are refused. Null is assignable to every type;
branch types must otherwise agree (string-represented types can combine as text).

`evaluateExpression(expression, context, budget?)` returns a scalar, null, or a
list of strings. The caller validates against the authoritative directory
schema before saving and before executing a persisted mapping. Runtime also
checks the entire expression, including branches that will not execute, against
the keys and value types in the supplied context. Supply **every allowed field
key**, using null for absent values; do the same for manager fields, including a
missing manager. This lets a misspelled field fail while a known missing value
remains null. Runtime context is an ordinary JSON-compatible object:

```json
{
  "fields": {"first_name":"Ada","last_name":"Lovelace","department":"Engineering","start_date":"2026-10-22"},
  "sources": {"hr":{"department":"Engineering"},"manual":{},"directory":{},"self":{}},
  "manager": {"email":null,"department":null},
  "groups": ["Engineering","App administrators"]
}
```

Context must be assembled from the allowed directory data, never from session,
connector or environment objects. Field names are fixed identifiers with an
optional `x.` custom-field prefix. Credential names containing a segment such
as `secret`, `token`, `password`, `passkey`, `credential` or `key` are forbidden
even if supplied in a schema. Prototype properties and accessors are not read.

## Nodes

Literals are strings, finite JSON numbers, booleans and null. Arrays and objects
are not literals. The only object nodes are:

| Node | Value |
| --- | --- |
| `{"field":"department"}` | Effective directory value |
| `{"source":"hr","field":"department"}` | Value from manual, hr, directory or self; no precedence lookup |
| `{"manager":"email"}` | Manager field, or null when absent |
| `{"groups":true}` | Person's group names, preserving context order |
| `{"op":"lower","args":[NODE]}` | Function call |

## Functions

All string indices, lengths and limits count UTF-16 code units. Comparisons are
case-sensitive and locale-independent. There is no implicit string/number/boolean
conversion. String functions propagate null, including concat; use coalesce
where a missing string should become empty. Empty string is a value, not null.

| Function arguments | Result |
| --- | --- |
| `concat(text, ...)` | Concatenate one or more strings |
| `lower(text)`, `upper(text)`, `trim(text)` | Unicode default case conversion; trim surrounding whitespace |
| `substring(text, start, length?)` | Slice from a nonnegative integer offset; omitted length extends to the end |
| `replace(text, search, replacement)` | Replace all non-overlapping literal matches; search must be nonempty; replacement is literal |
| `regexReplace(text, pattern, replacement)` | Replace all non-overlapping greedy matches of the safe grammar below; pattern must be a literal string; replacement is literal, with no `$1` expansion |
| `pad(text, width, fill?, side?)` | Pad to width, default fill space and side `start`; optional side is literal `start` or `end`; nonempty fill is repeated/truncated; existing longer text is preserved |
| `if(boolean, whenTrue, whenFalse)` | Evaluate only the selected value; null condition selects whenFalse |
| `coalesce(value, ...)` | Evaluate left to right and return the first non-null value, otherwise null |
| `date(text, format)` | Format a valid calendar date (`YYYY-MM-DD`) or UTC timestamp (`YYYY-MM-DDTHH:mm:ssZ`, optionally `.sss` before Z); format must be one of the literals below |
| `inGroup(text)` | Exact group-name membership; null returns false |
| `filter(list, mode, needle)` | Filter string list by literal mode `equals`, `contains`, `startsWith` or `endsWith`; null list/needle returns an empty list |
| `eq(value, other)` | Strict scalar equality; null equals null; no type coercion; lists are refused |

Date formats are `YYYY-MM-DD`, `YYYYMMDD`, `MM/DD/YYYY`, and
`YYYY-MM-DDTHH:mm:ssZ`. All dates use UTC, without locale, current time, timezone
lookup or implicit parsing of other date formats. Invalid dates fail.
Substring offsets/lengths and pad widths must be integers from 0 through 4096.
If/coalesce branches must have compatible types, even when not selected.

## Safe regex grammar

Patterns contain literal characters, `.`, character classes such as `[a-z]`,
`[^0-9]`, `\d`, `\D`, `\w`, `\W`, `\s` and `\S`, and optional `?`, `*` or
`+` on a single character atom. `^` is allowed only at the beginning and `$`
only at the end. Dot excludes newline and carriage return. Escaping regex
punctuation produces a literal character. JSON requires a doubled backslash:
`"\\s+"`. Matching is case-sensitive and uses UTF-16 code units. Word classes
are ASCII letters/digits/underscore; whitespace uses JavaScript's whitespace
definition. An empty match inserts the replacement and advances one code unit,
preserving that unit, so it cannot loop forever.

Groups, alternation, backreferences, lookaround, counted repetition (`{n}`),
flags, stacked/lazy quantifiers, unknown escapes and empty patterns/classes are
refused. Matching uses a dynamic-programming interpreter, with work bounded by
input length times pattern size (including character-class checks); user
patterns are never passed to a backtracking regular-expression engine. Complex
but syntactically valid patterns can exhaust gas and fail safely.

## Examples

Computed first.last username (null if either name is missing):

```json
{"op":"lower","args":[{"op":"concat","args":[{"field":"first_name"},".",{"field":"last_name"}]}]}
```

Role from membership:

```json
{"op":"if","args":[{"op":"inGroup","args":["App administrators"]},"admin","member"]}
```

Formatted source date and manager fallback:

```json
{"op":"date","args":[{"source":"hr","field":"start_date"},"MM/DD/YYYY"]}
```

```json
{"op":"coalesce","args":[{"manager":"email"},"unassigned"]}
```

Filter group names and remove characters outside username characters:

```json
{"op":"filter","args":[{"groups":true},"startsWith","App "]}
```

```json
{"op":"regexReplace","args":[{"field":"first_name"},"[^a-zA-Z0-9]+",""]}
```

Collision suffixes depend on other people's output and belong to the mapping
service, outside this side-effect-free language. There is no `unique` function.

## Bounds and failures

Every expression is limited to 128 nodes, depth 16 (root depth 1), 1024 code
units per literal, 128 per regex pattern, 4096 per input/intermediate/output
string, 256 list elements and 16384 total code units per list. Runtime maps
contain at most 512 keys each. The default budget is 1,000,000 charged steps and
10 milliseconds, including runtime validation. Character work is charged, as
well as node visits. A numeric budget lowers the step limit; an object
`{steps:50000,maxMs:5}` can lower both limits. Callers cannot raise the ceilings.
The interpreter checks elapsed monotonic time while traversing and inside its
loops, and again before returning; it refuses results completed past the bound.
Bounded native operations run on at most 4096 code units. There is no execution
retry or alternate result when a budget fails.

Failures are AuthError responses: `mapping_invalid_expression` for invalid
syntax/schema/access, `mapping_type` for incompatible types or invalid runtime
values, and `mapping_budget` for size, gas or elapsed-time limits. Errors contain
no field values or expression contents. Preview should show these per person;
an error must never silently become a claim or provisioning value. Preview,
duplicate detection, publication, revision history, audit and rollback are
responsibilities of the mapping service using this evaluator.

## Save and use a mapping

Open Company apps, expand **Attribute mapping**, select the people to preview,
and edit a program such as:

```json
{"language":1,"nameId":{"expression":{"op":"lower","args":[{"op":"concat","args":[{"field":"first_name"},".",{"field":"last_name"}]}]},"unique":true},"saml":{"app_role":{"op":"if","args":[{"op":"inGroup","args":["Finance"]},"approver","reader"]}},"oidc":{"department":{"field":"department"}},"scim":{"title":{"op":"date","args":[{"field":"start_date"},"YYYYMMDD"]}}}
```

`nameId` changes the SAML NameID. `username` has the same expression/unique
shape and changes the provisioned SCIM userName. `saml`, `oidc` and `scim` map
output names to expressions. OIDC outputs ride on the profile scope. Protocol
identity/security claims (subject, issuer, audience, times, session, proof and
administrator roles) cannot be mapping targets. SCIM accepts userName,
displayName, title, department, costCenter, employeeNumber, name.givenName,
name.familyName and name.formatted; externalId and active remain Auth-owned.
API provisioning adapters introduced under AUTH-CATALOG-002 and
AUTH-LIFECYCLE-001 must use the same validated computed values before shipping.

Preview shows empty outputs and original duplicates. For `unique:true`, every
person in a duplicate set gets a numeric suffix, allocated in person-ID order
against all directory people, skipping existing outputs. Preview and issuance
use this same allocation, even when only a few people are selected. Directory
changes can change the allocation: use an immutable person-id-based expression
when the external app requires a username that never changes. An empty or
unresolved duplicate NameID/username refuses issuance/provisioning.

**Save mapping** publishes only the exact preview against the current mapping
version and directory values. Changed inputs require another preview. Edits need
an administrator's passkey and fresh email confirmation. All versions are kept;
**Roll back mapping** copies an earlier version into a new audited version and
reconciles provisioning. No rollback rewrites history.

HTTP equivalents are POST `/api/auth/mapping/preview` with
`{appId,personIds:[personId],program}`; POST `/api/auth/mapping/save` with those
fields plus the returned `version` and `digest`; and POST
`/api/auth/mapping/rollback` with `{appId,personIds,version,targetVersion}`.
These use the same session, CSRF and administration checks as app setup.
