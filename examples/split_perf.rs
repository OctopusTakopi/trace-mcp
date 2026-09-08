//! Dev helper: write one CPU's stream of a perf.data to a new file.
fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let cpus: Vec<u32> = a[1].split(',').map(|c| c.parse().unwrap()).collect();
    trace_mcp::capture::perfdata::split_by_cpus(
        std::path::Path::new(&a[0]),
        &cpus,
        std::path::Path::new(&a[2]),
    )
    .unwrap();
    println!(
        "{:?}",
        trace_mcp::capture::perfdata::auxtrace_cpus(std::path::Path::new(&a[2])).unwrap()
    );
}
