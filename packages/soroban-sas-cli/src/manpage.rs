//! Groff man page generation for `soroban-sas` (issue #330).

use std::path::Path;

use clap::Command;

/// Renders `cmd` (and its subcommands) as a section-1 groff page.
pub fn render(cmd: &Command) -> String {
    let name = cmd.get_name();
    let about = styled(cmd.get_about());
    let mut out = String::new();
    out.push_str(&format!(".TH {} 1\n", groff_escape(name)));
    out.push_str(".SH NAME\n");
    out.push_str(&format!(
        "{} \\- {}\n",
        groff_escape(name),
        groff_escape(&about)
    ));
    out.push_str(".SH SYNOPSIS\n");
    out.push_str(&format!(".B {}\n", groff_escape(name)));
    out.push_str("[\\,\\fIOPTIONS\\fR\\,] \\,\\fICOMMAND\\fR\\, ...\n");
    out.push_str(".SH DESCRIPTION\n");
    let long_about = styled(cmd.get_long_about());
    let description = if long_about.is_empty() {
        about
    } else {
        long_about
    };
    out.push_str(&format!("{}\n", groff_escape(&description)));
    out.push_str(".SH COMMANDS\n");
    for sub in cmd.get_subcommands() {
        if sub.is_hide_set() {
            continue;
        }
        write_command(&mut out, sub, name);
    }
    out.push_str(".SH OPTIONS\n");
    write_args(&mut out, cmd);
    out.push_str(".SH SEE ALSO\n");
    out.push_str("Run \\fBsoroban-sas man\\fR to regenerate this page from the current CLI.\n");
    out
}

/// Writes the rendered page to `path`, or to stdout when `path` is absent.
pub fn write_man_page(cmd: &Command, path: Option<&Path>) -> Result<(), String> {
    let page = render(cmd);
    match path {
        Some(path) => {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)
                        .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
                }
            }
            std::fs::write(path, page)
                .map_err(|err| format!("failed to write man page {}: {err}", path.display()))
        }
        None => {
            print!("{page}");
            Ok(())
        }
    }
}

fn write_command(out: &mut String, cmd: &Command, parent: &str) {
    let about = styled(cmd.get_about());
    out.push_str(&format!(
        ".TP\n.B {} {}\n{}\n",
        groff_escape(parent),
        groff_escape(cmd.get_name()),
        groff_escape(&about)
    ));
    write_args(out, cmd);
    let nested = format!("{parent} {}", cmd.get_name());
    for sub in cmd.get_subcommands() {
        if sub.is_hide_set() {
            continue;
        }
        write_command(out, sub, &nested);
    }
}

fn write_args(out: &mut String, cmd: &Command) {
    for arg in cmd.get_arguments() {
        if arg.is_hide_set() {
            continue;
        }
        let mut flag = String::new();
        if let Some(short) = arg.get_short() {
            flag.push('-');
            flag.push(short);
        }
        if let Some(long) = arg.get_long() {
            if !flag.is_empty() {
                flag.push_str(", ");
            }
            flag.push_str("--");
            flag.push_str(long);
        }
        if flag.is_empty() {
            flag = arg.get_id().as_str().to_string();
        }
        let help = styled(arg.get_help());
        out.push_str(&format!(
            ".TP\n\\fB{}\\fR\n{}\n",
            groff_escape(&flag),
            groff_escape(&help)
        ));
    }
}

fn styled(value: Option<&clap::builder::StyledStr>) -> String {
    value.map(|text| text.to_string()).unwrap_or_default()
}

fn groff_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' | '\r' => out.push(' '),
            _ => out.push(ch),
        }
    }
    out
}
