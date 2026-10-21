use clapp{::Parser;
use std::process::ExitCode;

mod cli;
mod migrate;

#[derive(Parser)]
#[command(name = "sas", about = "Soroban SAS CLI", version)]
enum Cli {
    Migrate(cli::migrate::MigrateArgs),
}

fn main() {
    let cli = Cli::parse();
    let result = match cli {
        Cli::Migrate(args) => cli::migrate::run(args),
    };
    if let Err(err) = result {
        eprintln!("error: {}", err);
        std::process::exit(ExitCode::FAILURE);
    }
}
