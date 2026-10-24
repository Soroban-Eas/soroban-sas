//! Differential fuzzing of on-chain Rust and Node-based off-chain schema syntax.
//! A single persistent Node subprocess amortizes startup over many fuzz cases.
#![no_main]
use base64::{engine::general_purpose::STANDARD, Engine as _};
use libfuzzer_sys::fuzz_target;
use soroban_sas_common::{validate_schema_syntax, SASError};
use soroban_sdk::{Env, String as SorobanString};
use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{Mutex, OnceLock},
};

struct NodeValidator {
    _child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}
impl NodeValidator {
    fn spawn() -> Self {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../packages/soroban-sas-js/scripts/schema-validator-runner.mjs"
        );
        let mut child = Command::new("node")
            .arg(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("Node.js is required for differential fuzzing");
        Self {
            input: child.stdin.take().unwrap(),
            output: BufReader::new(child.stdout.take().unwrap()),
            _child: child,
        }
    }
    fn classify(&mut self, bytes: &[u8]) -> String {
        writeln!(self.input, "{}", STANDARD.encode(bytes)).unwrap();
        self.input.flush().unwrap();
        let mut answer = String::new();
        self.output
            .read_line(&mut answer)
            .expect("Node runtime exited during fuzzing");
        assert!(!answer.is_empty(), "Node validator closed stdout");
        answer.trim().to_owned()
    }
}
static NODE: OnceLock<Mutex<NodeValidator>> = OnceLock::new();

fuzz_target!(|bytes: &[u8]| {
    let rust = if bytes.is_empty() {
        "empty"
    } else if bytes.len() > 1024 {
        "invalid"
    } else if let Ok(s) = std::str::from_utf8(bytes) {
        let env = Env::default();
        let schema = SorobanString::from_str(&env, s);
        match validate_schema_syntax(&env, &schema) {
            Ok(()) => "valid",
            Err(SASError::EmptySchema) => "empty",
            Err(_) => "invalid",
        }
    } else {
        "invalid"
    };
    let js = NODE
        .get_or_init(|| Mutex::new(NodeValidator::spawn()))
        .lock()
        .unwrap()
        .classify(bytes);
    assert_eq!(
        rust,
        js,
        "Rust/JS syntax mismatch (input base64={})",
        STANDARD.encode(bytes)
    );
});
