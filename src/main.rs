#![forbid(unsafe_code)]
//! Sextant CLI binary entrypoint.

use std::process::ExitCode;

use clap::Parser;
use sextant_core::cli::{Cli, execute_cli};

fn main() -> ExitCode {
    let cli = Cli::parse();
    match execute_cli(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("sextant error: {err}");
            ExitCode::FAILURE
        }
    }
}
