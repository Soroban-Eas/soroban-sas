//! Interactive schema-registration wizard (#469).
//!
//! `sas schema wizard` walks an operator through every input the registry's
//! `register` call needs — schema name, field definitions, revocability, an
//! optional resolver address, and a metadata URI — validating each answer the
//! moment it is entered instead of deferring mistakes to submission time.
//!
//! Two prompt backends share the same validators so behaviour matches
//! regardless of how the command is run:
//!
//! * [`Mode::Tty`] renders prompts, defaults, and inline validation errors
//!   directly in the terminal via `dialoguer`;
//! * [`Mode::Piped`] is the non-interactive fallback used whenever stdin is
//!   not a terminal (CI, pipes, redirected input). It reads one answer per
//!   line from stdin in the same order and re-prompts on invalid input.
//!
//! All prompts, summaries, and validation errors are written to **stderr**,
//! so `--output json` keeps stdout a single parseable document. Signing,
//! network, and registry selection stay flag/env-driven (the usual
//! `--secret-key`/`--identity`, `--network`, `--registry-contract-id`
//! plumbing); the caller prints the fee-estimated summary and asks for
//! final confirmation via [`confirm`] before submitting anything.
//!
//! The schema's *name* and *metadata URI* are off-chain labels: the registry
//! identifies a schema by the `(schema, resolver, revocable)` tuple alone
//! (see `specs/protocol-v1.md#schema-identity`), so the wizard surfaces them
//! in its summary and result output rather than on-chain.

use std::io::{IsTerminal, Write};

use crate::{validate_schema_syntax, MAX_INTERACTIVE_LINE_BYTES};

/// Maximum length, in bytes, of the wizard's schema name label.
const MAX_NAME_BYTES: usize = 64;
/// Maximum length, in bytes, of an optional metadata URI.
const MAX_METADATA_URI_BYTES: usize = 512;
/// URI schemes a metadata link may use.
const METADATA_SCHEMES: [&str; 4] = ["ipfs://", "ar://", "https://", "http://"];

/// Field-level byte caps the schema-registry contract enforces on `register`
/// (see `soroban_sas_common::validation`) but the client-side syntax check
/// alone does not: the wizard applies them at the prompt so a schema that
/// would be rejected on-chain is caught while typing, not at submission.
const MAX_FIELD_BYTES: usize = 64;
const MAX_IDENTIFIER_BYTES: usize = 32;
const MAX_FIELD_TYPE_BYTES: usize = 32;

/// Everything the wizard collected, ready for the summary and submission.
///
/// `name` and `metadata_uri` are off-chain labels (see the module docs);
/// `schema`/`resolver`/`revocable` are exactly the on-chain registration
/// arguments and the UID preimage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WizardAnswers {
    pub name: String,
    pub schema: String,
    pub resolver: String,
    pub revocable: bool,
    pub metadata_uri: Option<String>,
}

/// How the wizard drives its prompts.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Real terminal: `dialoguer` prompts with inline validation errors.
    Tty,
    /// stdin is not a terminal: one answer per line, re-prompting on errors.
    Piped,
}

impl Mode {
    /// Selects the prompt backend. `dialoguer` needs both a terminal to read
    /// keys from (stdin) and one to render on (stderr); if either is
    /// redirected, the line-based fallback is used so pipes and CI never
    /// hang waiting for raw keypresses.
    pub fn detect() -> Mode {
        if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
            Mode::Tty
        } else {
            Mode::Piped
        }
    }
}

/// Validates a schema name label: non-empty (after trimming), within
/// [`MAX_NAME_BYTES`], and free of control characters.
pub fn validate_name(input: &str) -> Result<(), String> {
    let name = input.trim();
    if name.is_empty() {
        return Err("name must not be empty".to_string());
    }
    if name.len() > MAX_NAME_BYTES {
        return Err(format!(
            "name is {} bytes, which exceeds the {MAX_NAME_BYTES}-byte limit",
            name.len()
        ));
    }
    if name.chars().any(char::is_control) {
        return Err("name must not contain control characters".to_string());
    }
    Ok(())
}

/// Validates one `name Type` field entry as it is typed: the shared syntax
/// check plus the contract's per-field byte caps, so real-time feedback
/// matches what `SchemaRegistry::register` will actually accept.
pub fn validate_field(input: &str) -> Result<(), String> {
    let field = input.trim();
    if field.is_empty() {
        return Err("field must use `name Type` (e.g. `bool verified`)".to_string());
    }
    if field.len() > MAX_FIELD_BYTES {
        return Err(format!(
            "field `{field}` is {} bytes, which exceeds the {MAX_FIELD_BYTES}-byte limit",
            field.len()
        ));
    }
    validate_schema_syntax(field)?;
    // `validate_schema_syntax` proved a single field exists with exactly one
    // space before the type, so this split cannot fail.
    let (identifier, field_type) = field.split_once(' ').expect("validated above");
    if identifier.len() > MAX_IDENTIFIER_BYTES {
        return Err(format!(
            "field name `{identifier}` is {} bytes, which exceeds the \
             {MAX_IDENTIFIER_BYTES}-byte limit",
            identifier.len()
        ));
    }
    if field_type.len() > MAX_FIELD_TYPE_BYTES {
        return Err(format!(
            "field type `{field_type}` is {} bytes, which exceeds the \
             {MAX_FIELD_TYPE_BYTES}-byte limit",
            field_type.len()
        ));
    }
    Ok(())
}

/// Validates a resolver answer. A blank answer resolves to `default` (the
/// `--resolver` / `SAS_RESOLVER_CONTRACT_ID` value, if configured); without
/// one it is an error, because the resolver is part of the schema's on-chain
/// identity. Non-blank answers must decode as a `C...` contract address.
pub fn validate_resolver(input: &str, default: Option<&str>) -> Result<String, String> {
    let value = input.trim();
    if value.is_empty() {
        return match default {
            Some(default) => Ok(default.to_string()),
            None => Err(
                "resolver is required: enter a C... contract address, or pass --resolver / \
                 SAS_RESOLVER_CONTRACT_ID to prefill a default"
                    .to_string(),
            ),
        };
    }
    soroban_sas_sdk::strkey::validate_strkey(
        value,
        soroban_sas_sdk::strkey::AddressKind::Contract,
        "resolver",
    )
    .map(|()| value.to_string())
    .map_err(|e| e.to_string())
}

/// Parses a `y`/`yes`/`n`/`no` answer (case-insensitive) into a bool,
/// rejecting anything else so the re-prompt is explicit.
pub fn validate_revocable(input: &str) -> Result<bool, String> {
    match input.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => Ok(true),
        "n" | "no" => Ok(false),
        _ => Err("please answer y or n".to_string()),
    }
}

/// Validates an optional metadata URI: blank means "skip" (`None`);
/// otherwise the value must be whitespace-free, within
/// [`MAX_METADATA_URI_BYTES`], and use a known scheme with a non-empty path.
pub fn validate_metadata_uri(input: &str) -> Result<Option<String>, String> {
    let uri = input.trim();
    if uri.is_empty() {
        return Ok(None);
    }
    if uri.len() > MAX_METADATA_URI_BYTES {
        return Err(format!(
            "metadata URI is {} bytes, which exceeds the {MAX_METADATA_URI_BYTES}-byte limit",
            uri.len()
        ));
    }
    if uri.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("metadata URI must not contain whitespace or control characters".to_string());
    }
    let lower = uri.to_ascii_lowercase();
    let scheme = METADATA_SCHEMES
        .iter()
        .copied()
        .find(|scheme| lower.starts_with(scheme));
    let Some(scheme) = scheme else {
        return Err(
            "metadata URI must start with ipfs://, ar://, https://, or http://".to_string(),
        );
    };
    if uri.len() == scheme.len() {
        return Err("metadata URI must include a path after the scheme".to_string());
    }
    Ok(Some(uri.to_string()))
}

/// Collects every wizard answer using the backend selected by `mode`.
///
/// `lines` supplies the answers for [`Mode::Piped`] and is ignored for
/// [`Mode::Tty`] (which reads keypresses directly from the terminal).
pub fn collect<I>(
    mode: Mode,
    lines: &mut I,
    default_resolver: Option<&str>,
) -> Result<WizardAnswers, String>
where
    I: Iterator<Item = std::io::Result<String>>,
{
    match mode {
        Mode::Tty => collect_tty(default_resolver),
        Mode::Piped => collect_piped(lines, default_resolver),
    }
}

/// Asks for final confirmation after the summary has been printed.
///
/// `true` means "submit": the caller has already shown the collected values
/// and the estimated network fee, so a `false` here is a clean abort with no
/// transaction built. `lines` is only read in [`Mode::Piped`].
pub fn confirm<I>(mode: Mode, lines: &mut I) -> Result<bool, String>
where
    I: Iterator<Item = std::io::Result<String>>,
{
    match mode {
        Mode::Tty => dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("Submit registration?")
            .default(false)
            .interact()
            .map_err(|e| format!("confirmation prompt failed: {e}")),
        Mode::Piped => loop {
            let line = prompt_line(lines, "Submit registration? [y/N]: ")?;
            match line.to_ascii_lowercase().as_str() {
                "y" | "yes" => return Ok(true),
                "" | "n" | "no" => return Ok(false),
                _ => eprintln!("please answer y or n"),
            }
        },
    }
}

/// Prints the registration summary (answers, UID, network, estimated fee) to
/// stderr, immediately before [`confirm`] asks for the go-ahead.
pub fn print_summary(
    answers: &WizardAnswers,
    uid_hex: &str,
    fee_estimate: Option<i64>,
    network_passphrase: &str,
    registry_contract_id: &str,
) {
    let fee = match fee_estimate {
        Some(fee) => format!("{fee} stroops"),
        None => "unavailable".to_string(),
    };
    eprintln!("Registration summary");
    eprintln!("  Name:               {}", answers.name);
    eprintln!("  Schema:             {}", answers.schema);
    eprintln!("  Resolver:           {}", answers.resolver);
    eprintln!(
        "  Revocable:          {}",
        if answers.revocable { "yes" } else { "no" }
    );
    match &answers.metadata_uri {
        Some(uri) => eprintln!("  Metadata URI:       {uri}"),
        None => eprintln!("  Metadata URI:       (none)"),
    }
    eprintln!("  Schema UID:         {uid_hex}");
    eprintln!("  Registry contract:  {registry_contract_id}");
    eprintln!("  Network:            {network_passphrase}");
    eprintln!("  Estimated network fee: {fee}");
}

// ---------------------------------------------------------------------------
// Line-based (non-TTY) backend
// ---------------------------------------------------------------------------

/// Reads one prompted answer from `lines`, echoing `prompt` to **stderr** and
/// enforcing [`MAX_INTERACTIVE_LINE_BYTES`] on the raw line, mirroring
/// [`crate::next_interactive_line`] but with stderr output so prompts never
/// pollute stdout.
fn prompt_line<I>(lines: &mut I, prompt: &str) -> Result<String, String>
where
    I: Iterator<Item = std::io::Result<String>>,
{
    eprint!("{prompt}");
    std::io::stderr()
        .flush()
        .map_err(|e| format!("cannot write to stderr: {e}"))?;
    let line = lines
        .next()
        .ok_or_else(|| "unexpected end of input".to_string())?
        .map_err(|e| format!("cannot read stdin: {e}"))?;
    if line.len() > MAX_INTERACTIVE_LINE_BYTES {
        return Err(format!(
            "input exceeds the {MAX_INTERACTIVE_LINE_BYTES}-byte limit"
        ));
    }
    Ok(line.trim().to_string())
}

/// Re-prompts with `error` on stderr until `parse` succeeds.
fn retry<I, F, T>(lines: &mut I, prompt: &str, mut parse: F) -> Result<T, String>
where
    I: Iterator<Item = std::io::Result<String>>,
    F: FnMut(&str) -> Result<T, String>,
{
    loop {
        let line = prompt_line(lines, prompt)?;
        match parse(&line) {
            Ok(value) => return Ok(value),
            Err(error) => eprintln!("{error}"),
        }
    }
}

/// The piped fallback: the same questions in the same order as the TTY
/// backend, answered one line at a time. Invalid lines print their error and
/// re-prompt; exhausted input fails with `unexpected end of input`.
pub fn collect_piped<I>(
    lines: &mut I,
    default_resolver: Option<&str>,
) -> Result<WizardAnswers, String>
where
    I: Iterator<Item = std::io::Result<String>>,
{
    eprintln!(
        "stdin is not a terminal: reading wizard answers line by line (invalid answers are \
         re-prompted)"
    );

    // `prompt_line` already trims, so the accepted line is summary-ready.
    let name = loop {
        let line = prompt_line(lines, "Schema name: ")?;
        match validate_name(&line) {
            Ok(()) => break line,
            Err(error) => eprintln!("{error}"),
        }
    };

    let mut fields: Vec<String> = Vec::new();
    loop {
        let prompt = format!("field {} (blank to finish): ", fields.len() + 1);
        let line = prompt_line(lines, &prompt)?;
        if line.is_empty() {
            if fields.is_empty() {
                eprintln!("at least one field is required");
                continue;
            }
            break;
        }
        if fields.len() >= soroban_sas_common::validation::MAX_SCHEMA_FIELDS as usize {
            eprintln!(
                "a schema may declare at most {} fields",
                soroban_sas_common::validation::MAX_SCHEMA_FIELDS
            );
            continue;
        }
        if let Err(error) = validate_field(&line) {
            eprintln!("{error}");
            continue;
        }
        // Validate the joined schema so cumulative limits (1024 bytes, …)
        // surface at the prompt that would break them, not at submission.
        let candidate = join_fields(&fields, &line);
        if let Err(error) = validate_schema_syntax(&candidate) {
            eprintln!("{error}");
            continue;
        }
        fields.push(line);
    }
    let schema = fields.join(", ");

    let revocable = retry(lines, "Revocable? [y/n]: ", validate_revocable)?;

    let resolver_prompt = match default_resolver {
        Some(default) => format!("Resolver contract address [{default}]: "),
        None => "Resolver contract address (C...): ".to_string(),
    };
    let resolver = retry(lines, &resolver_prompt, |line| {
        validate_resolver(line, default_resolver)
    })?;

    let metadata_uri = retry(lines, "Metadata URI (optional, blank to skip): ", |line| {
        validate_metadata_uri(line)
    })?;

    Ok(WizardAnswers {
        name,
        schema,
        resolver,
        revocable,
        metadata_uri,
    })
}

/// `fields` joined with a new entry appended, without allocating the whole
/// list again for every candidate check.
fn join_fields(fields: &[String], next: &str) -> String {
    let mut joined = fields.join(", ");
    if !joined.is_empty() {
        joined.push_str(", ");
    }
    joined.push_str(next);
    joined
}

// ---------------------------------------------------------------------------
// TTY backend (dialoguer)
// ---------------------------------------------------------------------------

/// The dialoguer-driven backend. Every prompt sets `allow_empty` where a
/// blank answer must produce an inline validation error (rather than a
/// silent re-prompt) and shares its validator with the piped backend, so the
/// same input is accepted or rejected by either path.
fn collect_tty(default_resolver: Option<&str>) -> Result<WizardAnswers, String> {
    use dialoguer::theme::ColorfulTheme;

    let theme = ColorfulTheme::default();
    let prompt_failed = |error: dialoguer::Error| format!("prompt failed: {error}");

    let name: String = dialoguer::Input::with_theme(&theme)
        .with_prompt("Schema name")
        .allow_empty(true)
        .validate_with(|input: &String| validate_name(input))
        .interact_text()
        .map_err(prompt_failed)?;
    let name = name.trim().to_string();

    let mut fields: Vec<String> = Vec::new();
    loop {
        let prompt = format!("field {} (blank to finish)", fields.len() + 1);
        let line: String = dialoguer::Input::with_theme(&theme)
            .with_prompt(prompt)
            .allow_empty(true)
            .validate_with(|input: &String| {
                if input.trim().is_empty() {
                    Ok(())
                } else {
                    validate_field(input)
                }
            })
            .interact_text()
            .map_err(prompt_failed)?;
        let line = line.trim().to_string();
        if line.is_empty() {
            if fields.is_empty() {
                eprintln!("at least one field is required");
                continue;
            }
            break;
        }
        if fields.len() >= soroban_sas_common::validation::MAX_SCHEMA_FIELDS as usize {
            eprintln!(
                "a schema may declare at most {} fields",
                soroban_sas_common::validation::MAX_SCHEMA_FIELDS
            );
            continue;
        }
        let candidate = join_fields(&fields, &line);
        if let Err(error) = validate_schema_syntax(&candidate) {
            eprintln!("{error}");
            continue;
        }
        fields.push(line);
    }
    let schema = fields.join(", ");

    let revocable = dialoguer::Confirm::with_theme(&theme)
        .with_prompt("Revocable")
        .default(false)
        .interact()
        .map_err(prompt_failed)?;

    let resolver = match default_resolver {
        Some(default) => dialoguer::Input::with_theme(&theme)
            .with_prompt("Resolver contract address")
            .default(default.to_string())
            .show_default(true)
            .validate_with(move |input: &String| {
                validate_resolver(input, Some(default)).map(|_| ())
            })
            .interact_text()
            .map_err(prompt_failed)?,
        None => dialoguer::Input::with_theme(&theme)
            .with_prompt("Resolver contract address (C...)")
            .allow_empty(true)
            .validate_with(|input: &String| validate_resolver(input, None).map(|_| ()))
            .interact_text()
            .map_err(prompt_failed)?,
    };

    let metadata: String = dialoguer::Input::with_theme(&theme)
        .with_prompt("Metadata URI (optional)")
        .allow_empty(true)
        .validate_with(|input: &String| validate_metadata_uri(input).map(|_| ()))
        .interact_text()
        .map_err(prompt_failed)?;
    let metadata_uri = validate_metadata_uri(&metadata)?;

    Ok(WizardAnswers {
        name,
        schema,
        resolver,
        revocable,
        metadata_uri,
    })
}
