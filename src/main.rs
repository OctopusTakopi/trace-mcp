use clap::Parser;
use trace_mcp::cli::{Cli, run};

fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("trace_mcp=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let code = match rt.block_on(run(cli)) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("{err}");
            if let Some(next) = err.next_action {
                eprintln!("{next}");
            }
            1
        }
    };
    std::process::exit(code);
}
