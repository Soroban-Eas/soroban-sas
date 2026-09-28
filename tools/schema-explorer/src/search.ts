import type { SchemaRecord } from "./registry.js";
import { parseSchema } from "./schema.js";

/**
 * Client-side filter over loaded schemas. Every whitespace-separated term
 * must match (case-insensitively) the UID, resolver, raw schema text, or a
 * parsed field name/type. `revocable:yes|no` and `valid:yes|no` narrow by
 * flag.
 */
export function filterSchemas(schemas: readonly SchemaRecord[], query: string): SchemaRecord[] {
  const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return [...schemas];

  return schemas.filter((record) => {
    const parsed = parseSchema(record.schema);
    const haystack = [
      record.uid,
      record.resolver.toLowerCase(),
      record.schema.toLowerCase(),
      ...parsed.fields.flatMap((f) => [f.name.toLowerCase(), f.type.toLowerCase()]),
    ];
    return terms.every((term) => {
      const flag = /^(revocable|valid):(yes|no|true|false)$/.exec(term);
      if (flag) {
        const want = flag[2] === "yes" || flag[2] === "true";
        return (flag[1] === "revocable" ? record.revocable : parsed.ok) === want;
      }
      return haystack.some((h) => h.includes(term));
    });
  });
}
