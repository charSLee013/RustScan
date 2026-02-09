#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown, clippy::if_not_else, clippy::non_ascii_literal)]

use rustscan::benchmark::{Benchmark, NamedTimer};
use rustscan::input::{self, Config, Opts, ScriptsRequired};
use rustscan::port_strategy::PortStrategy;
use rustscan::scanner::Scanner;
use rustscan::scripts::{init_scripts, Script, ScriptFile};
use rustscan::{detail, funny_opening, output, warning};

use colorful::{Color, Colorful};
use futures::executor::block_on;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::io::IsTerminal;
use std::net::IpAddr;
use std::str::FromStr;
use std::string::ToString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use cidr_utils::cidr::IpInet;
use rustscan::address::{parse_addresses, AddressStream};
use rustscan::progress::{ProgressSnapshot, ScanProgress};

extern crate colorful;
extern crate dirs;

// Average value for Ubuntu
#[cfg(unix)]
const DEFAULT_FILE_DESCRIPTORS_LIMIT: usize = 8000;
// Safest batch size based on experimentation
const AVERAGE_BATCH_SIZE: usize = 3000;

#[macro_use]
extern crate log;

#[cfg(not(tarpaulin_include))]
#[allow(clippy::too_many_lines)]
/// Faster Nmap scanning with Rust
/// If you're looking for the actual scanning, check out the module Scanner
fn main() {
    #[cfg(not(unix))]
    let _ = ansi_term::enable_ansi_support();

    env_logger::init();
    let mut benchmarks = Benchmark::init();
    let mut rustscan_bench = NamedTimer::start("RustScan");

    let mut opts: Opts = Opts::read();
    let config = Config::read(opts.config_path.clone());
    opts.merge(&config);

    debug!("Main() `opts` arguments are {opts:?}");

    let scripts_to_run: Vec<ScriptFile> = match init_scripts(&opts.scripts) {
        Ok(scripts_to_run) => scripts_to_run,
        Err(e) => {
            warning!(
                format!("Initiating scripts failed!\n{e}"),
                opts.greppable,
                opts.accessible
            );
            std::process::exit(1);
        }
    };

    debug!("Scripts initialized {:?}", &scripts_to_run);

    if !opts.greppable && !opts.accessible && !opts.no_banner {
        print_opening(&opts);
    }

    if !opts.stream {
        warn_large_cidrs(&opts);
    }

    #[cfg(unix)]
    let batch_size: usize = infer_batch_size(&opts, adjust_ulimit_size(&opts));

    #[cfg(not(unix))]
    let batch_size: usize = AVERAGE_BATCH_SIZE;

    let ports = build_ports(&opts);

    let mut ports_per_ip: HashMap<IpAddr, Vec<u16>> = HashMap::new();
    let mut portscan_bench = NamedTimer::start("Portscan");
    let mut stream_total_scanned_ips: u64 = 0;
    if opts.stream {
        let ports_len = ports.len().max(1);
        const MIN_IPS_PER_CHUNK: usize = 256;
        const MAX_IPS_PER_CHUNK: usize = 100_000;
        let ips_per_chunk = ((batch_size + ports_len - 1) / ports_len)
            .max(MIN_IPS_PER_CHUNK)
            .clamp(1, MAX_IPS_PER_CHUNK);

        let progress =
            should_show_progress(&opts).then(|| ScanProgress::new(ports.len() as u64, None));
        let progress_thread = progress.as_ref().map(|progress| {
            spawn_progress_bar(
                progress.clone(),
                true,
                batch_size,
                Duration::from_millis(opts.timeout.into()),
                std::cmp::max(opts.tries, 1),
            )
        });

        let mut addr_stream = AddressStream::new(&opts);
        loop {
            let chunk = addr_stream.by_ref().take(ips_per_chunk).collect::<Vec<_>>();
            if chunk.is_empty() {
                break;
            }

            stream_total_scanned_ips += chunk.len() as u64;
            if let Some(progress) = &progress {
                progress.add_resolved_ips(chunk.len() as u64);
            }

            let scanner = Scanner::new(
                &chunk,
                batch_size,
                Duration::from_millis(opts.timeout.into()),
                opts.tries,
                opts.greppable,
                PortStrategy::Manual(Vec::new()),
                opts.accessible,
                Vec::new(),
                opts.udp,
            );
            let scanner = match &progress {
                Some(progress) => scanner.with_progress(progress.clone()),
                None => scanner,
            };

            for socket in block_on(scanner.run_with_ports(&ports)) {
                match ports_per_ip.entry(socket.ip()) {
                    Entry::Occupied(mut entry) => entry.get_mut().push(socket.port()),
                    Entry::Vacant(entry) => {
                        if let Some(progress) = &progress {
                            progress.inc_open_ips(1);
                        }
                        entry.insert(vec![socket.port()]);
                    }
                }
            }
        }

        if let Some((stop, handle)) = progress_thread {
            stop.store(true, Ordering::Relaxed);
            let _ = handle.join();
        }

        if stream_total_scanned_ips == 0 {
            warning!(
                "No IPs could be resolved, aborting scan.",
                opts.greppable,
                opts.accessible
            );
            std::process::exit(1);
        }
    } else {
        let ips: Vec<IpAddr> = parse_addresses(&opts);

        if ips.is_empty() {
            warning!(
                "No IPs could be resolved, aborting scan.",
                opts.greppable,
                opts.accessible
            );
            std::process::exit(1);
        }

        let progress = should_show_progress(&opts)
            .then(|| ScanProgress::new(ports.len() as u64, Some(ips.len() as u64)));
        if let Some(progress) = &progress {
            progress.add_resolved_ips(ips.len() as u64);
        }
        let progress_thread = progress.as_ref().map(|progress| {
            spawn_progress_bar(
                progress.clone(),
                false,
                batch_size,
                Duration::from_millis(opts.timeout.into()),
                std::cmp::max(opts.tries, 1),
            )
        });

        let scanner = Scanner::new(
            &ips,
            batch_size,
            Duration::from_millis(opts.timeout.into()),
            opts.tries,
            opts.greppable,
            PortStrategy::Manual(Vec::new()),
            opts.accessible,
            Vec::new(),
            opts.udp,
        );
        let scanner = match &progress {
            Some(progress) => scanner.with_progress(progress.clone()),
            None => scanner,
        };
        debug!("Scanner finished building: {scanner:?}");

        for socket in block_on(scanner.run_with_ports(&ports)) {
            match ports_per_ip.entry(socket.ip()) {
                Entry::Occupied(mut entry) => entry.get_mut().push(socket.port()),
                Entry::Vacant(entry) => {
                    if let Some(progress) = &progress {
                        progress.inc_open_ips(1);
                    }
                    entry.insert(vec![socket.port()]);
                }
            }
        }

        if let Some((stop, handle)) = progress_thread {
            stop.store(true, Ordering::Relaxed);
            let _ = handle.join();
        }

        for ip in ips {
            if ports_per_ip.contains_key(&ip) {
                continue;
            }

            // If we got here it means the IP was not found within the HashMap, this
            // means the scan couldn't find any open ports for it.

            let x = format!("Looks like I didn't find any open ports for {:?}. This is usually caused by a high batch size.
        \n*I used {} batch size, consider lowering it with {} or a comfortable number for your system.
        \n Alternatively, increase the timeout if your ping is high. Rustscan -t 2000 for 2000 milliseconds (2s) timeout.\n",
        ip,
        opts.batch_size,
        "'rustscan -b <batch_size> -a <ip address>'");
            warning!(x, opts.greppable, opts.accessible);
        }
    }

    portscan_bench.end();
    benchmarks.push(portscan_bench);

    if opts.stream {
        detail!(
            format!(
                "Stream mode scanned {stream_total_scanned_ips} IPs; found open ports on {} IPs.",
                ports_per_ip.len()
            ),
            opts.greppable,
            opts.accessible
        );

        if ports_per_ip.is_empty() {
            let x = format!("Looks like I didn't find any open ports. This is usually caused by a high batch size.
        \n*I used {} batch size, consider lowering it with {} or a comfortable number for your system.
        \n Alternatively, increase the timeout if your ping is high. Rustscan -t 2000 for 2000 milliseconds (2s) timeout.\n",
        opts.batch_size,
        "'rustscan -b <batch_size> -a <ip address>'");
            warning!(x, opts.greppable, opts.accessible);
        }
    }

    let mut script_bench = NamedTimer::start("Scripts");
    for (ip, ports) in &ports_per_ip {
        let vec_str_ports: Vec<String> = ports.iter().map(ToString::to_string).collect();

        // nmap port style is 80,443. Comma separated with no spaces.
        let ports_str = vec_str_ports.join(",");

        // if option scripts is none, no script will be spawned
        if opts.greppable || opts.scripts == ScriptsRequired::None {
            println!("{} -> [{}]", &ip, ports_str);
            continue;
        }
        detail!("Starting Script(s)", opts.greppable, opts.accessible);

        // Run all the scripts we found and parsed based on the script config file tags field.
        for mut script_f in scripts_to_run.clone() {
            // This part allows us to add commandline arguments to the Script call_format, appending them to the end of the command.
            if !opts.command.is_empty() {
                let user_extra_args = &opts.command.join(" ");
                debug!("Extra args vec {user_extra_args:?}");
                if script_f.call_format.is_some() {
                    let mut call_f = script_f.call_format.unwrap();
                    call_f.push(' ');
                    call_f.push_str(user_extra_args);
                    output!(
                        format!("Running script {:?} on ip {}\nDepending on the complexity of the script, results may take some time to appear.", call_f, &ip),
                        opts.greppable,
                        opts.accessible
                    );
                    debug!("Call format {call_f}");
                    script_f.call_format = Some(call_f);
                }
            }

            // Building the script with the arguments from the ScriptFile, and ip-ports.
            let script = Script::build(
                script_f.path,
                *ip,
                ports.clone(),
                script_f.port,
                script_f.ports_separator,
                script_f.tags,
                script_f.call_format,
            );
            match script.run() {
                Ok(script_result) => {
                    detail!(script_result.clone(), opts.greppable, opts.accessible);
                }
                Err(e) => {
                    warning!(&format!("Error {e}"), opts.greppable, opts.accessible);
                }
            }
        }
    }

    // To use the runtime benchmark, run the process as: RUST_LOG=info ./rustscan
    script_bench.end();
    benchmarks.push(script_bench);
    rustscan_bench.end();
    benchmarks.push(rustscan_bench);
    debug!("Benchmarks raw {benchmarks:?}");
    info!("{}", benchmarks.summary());
}

/// Prints the opening title of RustScan
#[allow(clippy::items_after_statements, clippy::needless_raw_string_hashes)]
fn print_opening(opts: &Opts) {
    debug!("Printing opening");
    let s = r#".----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner."#;

    println!("{}", s.gradient(Color::Green).bold());
    let info = r#"________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------"#;
    println!("{}", info.gradient(Color::Yellow).bold());
    funny_opening!();

    let config_path = opts
        .config_path
        .clone()
        .unwrap_or_else(input::default_config_path);

    detail!(
        format!("The config file is expected to be at {config_path:?}"),
        opts.greppable,
        opts.accessible
    );

    if opts.config_path.is_none() {
        let old_config_path = input::old_default_config_path();
        detail!(
            format!(
                "For backwards compatibility, the config file may also be at {old_config_path:?}"
            ),
            opts.greppable,
            opts.accessible
        );
    }
}

fn warn_large_cidrs(opts: &Opts) {
    const LARGE_CIDR_THRESHOLD: u128 = 1_000_000;

    for address in &opts.addresses {
        let Ok(net) = IpInet::from_str(address) else {
            continue;
        };

        if cidr_size_at_least(&net, LARGE_CIDR_THRESHOLD) {
            warning!(
                format!("Large CIDR detected ({address}). Consider using --stream to reduce memory usage on low-memory systems."),
                opts.greppable,
                opts.accessible
            );
            break;
        }
    }
}

fn cidr_size_at_least(net: &IpInet, threshold: u128) -> bool {
    match net {
        IpInet::V4(inet) => {
            let host_bits = 32u32.saturating_sub(u32::from(inet.network_length()));
            (1u128 << host_bits) >= threshold
        }
        IpInet::V6(inet) => {
            let host_bits = 128u32.saturating_sub(u32::from(inet.network_length()));
            if host_bits >= 128 {
                return true;
            }
            (1u128 << host_bits) >= threshold
        }
    }
}

fn build_ports(opts: &Opts) -> Vec<u16> {
    let mut ports = PortStrategy::pick(&opts.range, opts.ports.clone(), opts.scan_order).order();

    if let Some(exclude_ports) = &opts.exclude_ports {
        if !exclude_ports.is_empty() {
            let exclude_ports: HashSet<u16> = exclude_ports.iter().copied().collect();
            ports.retain(|port| !exclude_ports.contains(port));
        }
    }

    ports
}

fn should_show_progress(opts: &Opts) -> bool {
    !opts.disable_progress && !opts.accessible && std::io::stderr().is_terminal()
}

fn spawn_progress_bar(
    progress: Arc<ScanProgress>,
    is_stream: bool,
    batch_size: usize,
    timeout: Duration,
    tries: u8,
) -> (Arc<AtomicBool>, std::thread::JoinHandle<()>) {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();

    let handle = std::thread::spawn(move || {
        let pb = if is_stream {
            ProgressBar::new_spinner()
        } else {
            let total_sockets = progress.snapshot().total_sockets.unwrap_or(0);
            ProgressBar::new(total_sockets)
        };

        pb.set_draw_target(ProgressDrawTarget::stderr_with_hz(10));

        if is_stream {
            let style = ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] {human_pos:>10} {per_sec} {wide_msg}",
            )
            .unwrap_or_else(|_| ProgressStyle::default_spinner());
            pb.set_style(style);
        } else {
            let style = ProgressStyle::with_template(
                "[{elapsed_precise}] {bar:40.cyan/blue} {human_pos:>10}/{human_len:10} {per_sec} eta {eta_precise} {wide_msg}",
            )
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("=>-");
            pb.set_style(style);
        }

        while !stop_thread.load(Ordering::Relaxed) {
            let snapshot = progress.snapshot();
            pb.set_position(snapshot.completed_sockets);
            pb.set_message(format_progress_message(
                &snapshot, batch_size, timeout, tries,
            ));
            if is_stream {
                pb.tick();
            }
            std::thread::sleep(Duration::from_millis(120));
        }

        pb.finish();
    });

    (stop, handle)
}

fn format_progress_message(
    snapshot: &ProgressSnapshot,
    batch_size: usize,
    timeout: Duration,
    tries: u8,
) -> String {
    let total_ips = snapshot
        .total_ips
        .map(|v| v.to_string())
        .unwrap_or_else(|| "?".to_owned());
    let last = snapshot
        .last_socket
        .map(|s| s.to_string())
        .unwrap_or_else(|| "-".to_owned());

    format!(
        "ips={}/{total_ips} ports={} inflight={} open_sockets={} open_ips={} cur={last} batch={batch_size} timeout={}ms tries={tries}",
        snapshot.resolved_ips,
        snapshot.ports_total,
        snapshot.inflight(),
        snapshot.open_sockets,
        snapshot.open_ips,
        timeout.as_millis(),
    )
}

#[cfg(unix)]
fn adjust_ulimit_size(opts: &Opts) -> usize {
    use rlimit::Resource;
    use std::convert::TryInto;

    if let Some(limit) = opts.ulimit {
        let limit = limit as u64;
        if Resource::NOFILE.set(limit, limit).is_ok() {
            detail!(
                format!("Automatically increasing ulimit value to {limit}."),
                opts.greppable,
                opts.accessible
            );
        } else {
            warning!(
                "ERROR. Failed to set ulimit value.",
                opts.greppable,
                opts.accessible
            );
        }
    }

    let (soft, _) = Resource::NOFILE.get().unwrap();
    soft.try_into().unwrap_or(usize::MAX)
}

#[cfg(unix)]
fn infer_batch_size(opts: &Opts, ulimit: usize) -> usize {
    let mut batch_size = opts.batch_size;

    // Adjust the batch size when the ulimit value is lower than the desired batch size
    if ulimit < batch_size {
        warning!("File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers",
            opts.greppable, opts.accessible
        );

        // When the OS supports high file limits like 8000, but the user
        // selected a batch size higher than this we should reduce it to
        // a lower number.
        if ulimit < AVERAGE_BATCH_SIZE {
            // ulimit is smaller than aveage batch size
            // user must have very small ulimit
            // decrease batch size to half of ulimit
            warning!("Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. ", opts.greppable, opts.accessible);
            info!("Halving batch_size because ulimit is smaller than average batch size");
            batch_size = ulimit / 2;
        } else if ulimit > DEFAULT_FILE_DESCRIPTORS_LIMIT {
            info!("Batch size is now average batch size");
            batch_size = AVERAGE_BATCH_SIZE;
        } else {
            batch_size = ulimit - 100;
        }
    }
    // When the ulimit is higher than the batch size let the user know that the
    // batch size can be increased unless they specified the ulimit themselves.
    else if ulimit + 2 > batch_size && (opts.ulimit.is_none()) {
        detail!(format!("File limit higher than batch size. Can increase speed by increasing batch size '-b {}'.", ulimit - 100),
        opts.greppable, opts.accessible);
    }

    batch_size
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::{adjust_ulimit_size, infer_batch_size};
    use super::{print_opening, Opts};

    #[test]
    #[cfg(unix)]
    fn batch_size_lowered() {
        let opts = Opts {
            batch_size: 50_000,
            ..Default::default()
        };
        let batch_size = infer_batch_size(&opts, 120);

        assert!(batch_size < opts.batch_size);
    }

    #[test]
    #[cfg(unix)]
    fn batch_size_lowered_average_size() {
        let opts = Opts {
            batch_size: 50_000,
            ..Default::default()
        };
        let batch_size = infer_batch_size(&opts, 9_000);

        assert!(batch_size == 3_000);
    }
    #[test]
    #[cfg(unix)]
    fn batch_size_equals_ulimit_lowered() {
        // because ulimit and batch size are same size, batch size is lowered
        // to ULIMIT - 100
        let opts = Opts {
            batch_size: 50_000,
            ..Default::default()
        };
        let batch_size = infer_batch_size(&opts, 5_000);

        assert!(batch_size == 4_900);
    }
    #[test]
    #[cfg(unix)]
    fn batch_size_adjusted_2000() {
        // ulimit == batch_size
        let opts = Opts {
            batch_size: 50_000,
            ulimit: Some(2_000),
            ..Default::default()
        };
        let batch_size = adjust_ulimit_size(&opts);

        assert!(batch_size == 2_000);
    }

    #[test]
    #[cfg(unix)]
    fn test_high_ulimit_no_greppable_mode() {
        let opts = Opts {
            batch_size: 10,
            greppable: false,
            ..Default::default()
        };

        let batch_size = infer_batch_size(&opts, 1_000_000);

        assert!(batch_size == opts.batch_size);
    }

    #[test]
    fn test_print_opening_no_panic() {
        let opts = Opts {
            ulimit: Some(2_000),
            ..Default::default()
        };
        // print opening should not panic
        print_opening(&opts);
    }
}
