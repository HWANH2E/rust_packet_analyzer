use std::env;

use packet_analyzer_capture::read_pcap_file;
use packet_analyzer_core::{AnalyzerError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReadCommand {
    path: String,
    limit: Option<usize>,
}

fn main() {
    if let Err(err) = run(env::args().skip(1).collect()) {
        eprintln!("error: {err}");
        eprintln!();
        eprintln!("{}", usage());
        std::process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<()> {
    if args.is_empty() || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
        println!("{}", usage());
        return Ok(());
    }

    match args[0].as_str() {
        "read" => run_read(parse_read_args(&args[1..])?),
        path if !path.starts_with('-') => run_read(parse_read_args(&args)?),
        command => Err(AnalyzerError::InvalidArgument(format!(
            "unknown command or option: {command}"
        ))),
    }
}

fn run_read(command: ReadCommand) -> Result<()> {
    let file = read_pcap_file(&command.path)?;
    let limit = command.limit.unwrap_or(usize::MAX);

    for packet in file.packets.iter().take(limit) {
        println!("{}", packet.summary());
    }

    Ok(())
}

fn parse_read_args(args: &[String]) -> Result<ReadCommand> {
    let mut path = None;
    let mut limit = None;
    let mut index = 0usize;

    while index < args.len() {
        match args[index].as_str() {
            "--limit" => {
                index += 1;
                if index >= args.len() {
                    return Err(AnalyzerError::InvalidArgument(
                        "--limit requires a number".to_string(),
                    ));
                }
                let parsed = args[index].parse::<usize>().map_err(|err| {
                    AnalyzerError::InvalidArgument(format!("invalid --limit value: {err}"))
                })?;
                limit = Some(parsed);
            }
            value if value.starts_with('-') => {
                return Err(AnalyzerError::InvalidArgument(format!(
                    "unknown read option: {value}"
                )));
            }
            value => {
                if path.is_some() {
                    return Err(AnalyzerError::InvalidArgument(format!(
                        "unexpected extra path: {value}"
                    )));
                }
                path = Some(value.to_string());
            }
        }
        index += 1;
    }

    let path = path.ok_or_else(|| {
        AnalyzerError::InvalidArgument("read command requires a PCAP file path".to_string())
    })?;

    Ok(ReadCommand { path, limit })
}

fn usage() -> &'static str {
    "packet-analyzer stage 1\n\nUSAGE:\n    packet-analyzer read <pcap-file> [--limit N]\n    packet-analyzer <pcap-file>\n    packet-analyzer help\n\nEXAMPLES:\n    packet-analyzer read tests/fixtures/sample.pcap\n    packet-analyzer read tests/fixtures/sample.pcap --limit 10"
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parses_read_command() -> Result<()> {
        let args = vec![
            "sample.pcap".to_string(),
            "--limit".to_string(),
            "5".to_string(),
        ];
        let command = parse_read_args(&args)?;
        assert_eq!(command.path, "sample.pcap");
        assert_eq!(command.limit, Some(5));
        Ok(())
    }
}
