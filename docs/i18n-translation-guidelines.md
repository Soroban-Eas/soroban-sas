# Internationalization (i18n) and Translation Guidelines

This guide defines the standards, workflows, and best practices for localizing Soroban Attestation Service (SAS) documentation, user-facing client messages, and developer resources.

---

## 1. Objectives and Scope

The goal of the SAS localization effort is to make attestation primitives, SDK documentation, and developer tools accessible to global communities while maintaining strict technical accuracy, security clarity, and terminology consistency.

### In Scope
- Documentation under `docs/` and user guides.
- Command-line interface (`soroban-sas-cli`) error messages, help strings, and output formatting.
- Client SDK diagnostic messages, comments, and tutorials.
- Architecture diagrams and explanatory workflow descriptions.

### Out of Scope
- Core smart contract error symbol identifiers (`SASError`, Soroban contract symbols, event topics).
- Cryptographic algorithm identifiers and canonical field names (`schema_uid`, `ref_uid`, `revocable`, etc.).
- Machine-readable protocol schemas and JSON RPC responses.

---

## 2. Directory and File Conventions

All translated documentation must reside in language-tagged directory hierarchies mirroring the canonical English root:

```
docs/
├── architecture.md           # Canonical English source
├── fee-collection-and-treasury.md
├── i18n/
│   ├── es/                   # Spanish (Español)
│   │   ├── README.md
│   │   ├── architecture.md
│   │   └── fee-collection-and-treasury.md
│   ├── ja/                   # Japanese (日本語)
│   │   ├── README.md
│   │   ├── architecture.md
│   │   └── fee-collection-and-treasury.md
│   ├── pt-BR/                # Brazilian Portuguese (Português do Brasil)
│   │   ├── README.md
│   │   └── architecture.md
│   └── zh-CN/                # Simplified Chinese (简体中文)
│       ├── README.md
│       └── architecture.md
```

### Language Code Standard
Use BCP-47 / ISO 639-1 language codes, combined with ISO 3166-1 alpha-2 region subtags where applicable:
- `en`: English (canonical)
- `es`: Spanish
- `pt-BR`: Portuguese (Brazil)
- `zh-CN`: Chinese (Simplified)
- `zh-TW`: Chinese (Traditional)
- `ja`: Japanese
- `ko`: Korean
- `fr`: French
- `de`: German

---

## 3. Standardized Terminology Glossary

To avoid ambiguity, translators must adhere to the standardized terminology matrix below:

| English Term | Concept / Description | Spanish (`es`) | Portuguese (`pt-BR`) | Chinese (`zh-CN`) | Japanese (`ja`) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Attestation** | Verifiable digital assertion issued on-chain or off-chain | Atestación | Atestação | 证明 / 认证 (Attestation) | 構成証明 / アテステーション |
| **Attester** | Account or smart contract creating an attestation | Emisor de atestación / Atester | Emissor / Atester | 证明者 (Attester) | 証明者 (Attester) |
| **Recipient** | The subject or receiver of an attestation | Destinatario | Destinatário | 接收者 (Recipient) | 受信者 / 受益者 |
| **Schema** | Formal structural definition of an attestation's payload | Esquema | Esquema | 模式 / 架构 (Schema) | スキーマ |
| **Schema Registry** | On-chain contract managing schema definitions | Registro de esquemas | Registro de esquemas | 模式注册表 (Schema Registry) | スキーマレジストリ |
| **Revocation** | Invalidation of a revocable attestation | Revocación | Revogação | 撤销 (Revocation) | 取り消し / 失効 |
| **Resolver** | Smart contract hook verifying or gating attestations | Resolvedor (Resolver) | Resolvedor (Resolver) | 解析器 / 解析合约 (Resolver) | リゾルバー (Resolver) |
| **Indexer** | Off-chain or auxiliary contract indexing issued attestations | Indexador | Indexador | 索引器 (Indexer) | インデクサー |
| **Treasury** | Protocol account designated to receive fees | Tesorería | Tesouraria | 国库 / 资金库 (Treasury) | トレジャリー (Treasury) |
| **Instance Storage** | Soroban storage scoped to the contract instance | Almacenamiento de instancia | Armazenamento de instância | 实例存储 (Instance Storage) | インスタンスストレージ |
| **Persistent Storage** | Soroban storage for long-lived, individually indexed data | Almacenamiento persistente | Armazenamento persistente | 持久化存储 (Persistent Storage) | 永続ストレージ |
| **TTL (Time to Live)** | Ledger lifespan before Soroban state archiving | TTL (Tiempo de vida) | TTL (Tempo de vida) | 生存时间 (TTL) | 生存期間 (TTL) |

---

## 4. Translation Best Practices & Formatting Rules

### 4.1 Preserve Code Blocks and Inlines
- **Never translate:** Variable names, function names (`attest`, `revoke`, `set_fee`), Rust types (`UID`, `BytesN<32>`, `Option<Address>`), Soroban CLI flags (`--network`, `--source`), or file paths.
- Keep inline code ticks intact (e.g., `` `attest_with_value` `` must not be translated).

### 4.2 Relative Links and File References
- Relative markdown links pointing to other documentation files should point to the translated counterpart if available in the same language directory; otherwise, fallback directly to the canonical English document.
- Example: In `docs/i18n/es/architecture.md`, `[Registro de Esquemas](schemas.md)` points to `docs/i18n/es/schemas.md`, while referencing non-translated deployment guides uses `[Guía de Despliegue](DEPLOYMENT.md)` pointing to `docs/DEPLOYMENT.md`.

### 4.3 Keep Alerts and Warning Callouts
Preserve standard GitHub Flavored Markdown alerts:
```markdown
> [!NOTE]
> Nota: ...

> [!WARNING]
> Advertencia: ...

> [!IMPORTANT]
> Importante: ...
```

### 4.4 Numbers, Dates, and Currencies
- Express timestamps in ISO 8601 format (`YYYY-MM-DD` or `YYYY-MM-DDTHH:MM:SSZ`) or Soroban ledger sequence numbers.
- Stellar Lumens (XLM) and stroop notations must remain unaltered (1 XLM = 10,000,000 stroops).

---

## 5. CLI and SDK Localization Standards

When introducing localized string bundles to the CLI (`soroban-sas-cli`) or SDK:

1. **Keep Machine Identifiers Stable:** Standard error codes and enum variants (e.g., `SASError::FeeMismatch`) must never be modified.
2. **Error Output Pattern:** Human-readable explanations may be localized, but the technical error key or hex code should remain visible for debugging:
   ```
   Error: Fee mismatch [SASError::FeeMismatch]
   Expected: 500 stroops, Provided: 0 stroops
   ```
3. **Pluralization and Number Formatting:** Use standard locale-aware message format engines (such as Fluent or gettext) to avoid broken plural forms in Slavic, Romance, or East Asian languages.

---

## 6. Verification and Continuous Integration

All translations must pass automated verification checks before merging:

1. **Relative Link Integrity:** The relative link validator in `scripts/check_docs.sh` scans all `.md` files under `docs/` (including `docs/i18n/`) to ensure no broken links.
2. **Markdown Linting:** Ensure documents conform to markdown syntax standards without unterminated code blocks or broken formatting.
3. **Translation Synchronization Review:** When canonical English docs are modified in a PR, corresponding translations should be flagged with an `Outdated` banner or updated simultaneously.
