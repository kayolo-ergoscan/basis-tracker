//! `basis_canary` binary: see the library documentation and `basis_canary --help`.

use clap::Parser;

#[tokio::main]
async fn main() {
    let cli = basis_canary::Cli::parse();
    let mut report = basis_canary::Report::new(true);
    if let Err(e) = basis_canary::run(cli, &mut report).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
