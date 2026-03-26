#![cfg(feature = "cli")]

use clap::Parser;

fn main() {
    let _ = env_logger::try_init();
    let cli = lanyte_attest::Cli::parse();
    if let Err(err) = lanyte_attest::run(cli) {
        eprintln!("error: {err}");
        std::process::exit(err.exit_code());
    }
}
