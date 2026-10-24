# JSON Schema Draft-7 mapping

SAS schema strings (`name type, name type`) export to JSON Schema Draft-7 through `soroban-sas schema lint`.

| SAS primitive | JSON Schema Draft-7 |
| --- | --- |
| `bool` | `{ "type": "boolean" }` |
| `string` | `{ "type": "string" }` |
| `uint256` | `{ "type": "string", "pattern": "^[0-9]+$" }` |
| `bytes32` | `{ "type": "string", "pattern": "^0x[0-9a-fA-F]{64}$" }` |

Every field is listed in `required`. The original scalar is kept on `x-sas-type` so a round trip restores the field name, required status, and SAS type.

Field names that differ only by ASCII case are rejected. Unknown or generic types (`T[]`, `bytes?`) export as `string` and print a warning.

```bash
soroban-sas schema lint --schema "name string, balance uint256, active bool, id bytes32"
```
