#[macro_use]
extern crate serde_derive;

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::Command;
use std::{fs, io};

use chrono::{Local, TimeZone};
use chrono_english::{parse_date_string, Dialect};
use clap::{App, Arg, ArgGroup};
use colored::*;
use crypto::digest::Digest;
use crypto::sha1::Sha1;
use serde_json::Value;

#[derive(Debug, Deserialize)]
struct LogEvents {
    events: Vec<Value>,
    #[serde(rename = "nextToken")]
    next_token: Option<String>,
}

const NEWLINE: &[u8] = &['\n' as u8];

fn main() {
    let matches = App::new("cloudwatch")
        .version("1.0")
        .about("Does great things!")
        .arg(
            Arg::with_name("start-time")
                .long("start-time")
                .alias("since")
                .short("S")
                .help("The start of the time range. Events before this time are not returned.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("end-time")
                .long("end-time")
                .alias("until")
                .help("The end of the time range. Events later than this time are not returned.")
                .short("U")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("max-items")
                .long("max-items")
                .alias("lines")
                .short("n")
                .takes_value(true)
                .help("The total number of items to return in the command's output."),
        )
        .group(
            ArgGroup::with_name("limit")
                .args(&["start-time", "end-time", "max-items"])
                .multiple(true)
                .required(true),
        )
        .arg(
            Arg::with_name("log-group-name")
                .required(true)
                .takes_value(true)
                .help("The name of the log group."),
        )
        .arg(
            Arg::with_name("log-stream-name")
                .short("M")
                .takes_value(true)
                .help("The name of the log stream."),
        )
        .arg(
            Arg::with_name("force")
                .short("f")
                .help("Retreive data even if cached."),
        )
        .arg(
            Arg::with_name("text")
                .long("text")
                .help("Return results as text instead of JSON.")
                .short("t"),
        )
        .arg(Arg::with_name("filter-pattern").help("The filter pattern to use."))
        .get_matches();

    let log_group_name = matches.value_of("log-group-name").unwrap();
    let log_stream_name = matches.value_of("log-stream-name");
    let filter_pattern = matches.value_of("filter-pattern");
    let start_time = matches.value_of("start-time");
    let end_time = matches.value_of("end-time");
    let max_items = matches.value_of("max-items");
    let show_text = matches.is_present("text");
    let force = matches.is_present("force");

    let hash = {
        let mut hasher = Sha1::new();
        hasher.input(&[2]); // version
        hasher.input_str(log_group_name);
        hasher.input_str(log_stream_name.unwrap_or("log-stream-name"));
        hasher.input_str(filter_pattern.unwrap_or("filter-pattern"));
        hasher.input_str(start_time.unwrap_or("start-time"));
        hasher.input_str(end_time.unwrap_or("end-time"));
        hasher.input_str(max_items.unwrap_or("max-items"));
        hasher.result_str()
    };

    let path = Path::new("/Users/admin/.local/cache/cloudwatch/").join(Path::new(&hash));

    let stdout = io::stdout();
    let mut stdout = stdout.lock();

    // Check cache first
    if !force && path.exists() {
        let mut file = File::open(path).unwrap();
        if show_text {
            let file = BufReader::new(file);
            for line in file.lines() {
                let string = line.unwrap();
                let value = serde_json::from_str(&string).unwrap();
                print_event(&value);
            }
        } else {
            io::copy(&mut file, &mut stdout).unwrap();
        }
        return;
    }

    let now = Local::now();
    let to_timestamp = |x| {
        let time = parse_date_string(x, now, Dialect::Uk).unwrap();
        time.timestamp_millis().to_string()
    };

    let mut args = Args::new();
    args.add("--log-group-name", log_group_name);
    args.add("--output", "json");
    args.option("--start-time", start_time.map(to_timestamp));
    args.option("--end-time", end_time.map(to_timestamp));
    args.option("--filter-pattern", filter_pattern);
    args.option("--log-stream-names", log_stream_name);

    let temporary_path = path.with_extension("partial");
    let mut file = File::create(temporary_path.clone()).unwrap();

    // Custom paging to avoid loading the entire data set into memory
    let mut remaining = max_items.map(|x| x.parse::<u32>().unwrap());
    let mut next_token = None;

    while remaining.is_none() || remaining.unwrap() > 0 {
        let command = {
            let mut command = Command::new("aws");
            command
                .env("LC_ALL", "en_US.UTF-8")
                .arg("logs")
                .arg("filter-log-events")
                .arg("--no-paginate")
                .args(&args.args)
                .arg("--limit")
                .arg(remaining.unwrap_or(1000).min(1000).to_string().as_str());
            if let Some(token) = next_token {
                command.arg("--next-token").arg(token);
            }
            command.output().unwrap()
        };

        if !command.status.success() {
            std::io::stderr().write(&command.stderr).unwrap();
            return;
        }

        let response: LogEvents = serde_json::from_slice(&command.stdout).unwrap();
        next_token = response.next_token;

        for event in &response.events {
            let json = event.to_string();
            let bytes = json.as_bytes();
            file.write(bytes).unwrap();
            file.write(NEWLINE).unwrap();
            if show_text {
                print_event(event);
            } else {
                stdout.write(bytes).unwrap();
                stdout.write(NEWLINE).unwrap();
            }
        }

        if let Some(count) = remaining {
            remaining = Some(count - *&response.events.len() as u32);
        }

        if next_token.is_none() {
            // At the end of the stream
            break;
        }
    }

    fs::rename(temporary_path, path).unwrap();
}

fn print_event(event: &Value) {
    let timestamp = event
        .as_object()
        .unwrap()
        .get("timestamp")
        .unwrap()
        .as_i64()
        .unwrap();
    let message = event
        .as_object()
        .unwrap()
        .get("message")
        .unwrap()
        .as_str()
        .unwrap();
    let time = Local.timestamp_millis(timestamp);
    println!("{} {}", time.to_rfc3339().green(), message);
}

struct Args {
    args: Vec<String>,
}

impl Args {
    fn new() -> Args {
        Args { args: vec![] }
    }
    fn add(&mut self, name: &str, value: &str) -> &mut Args {
        self.args.push(name.into());
        self.args.push(value.into());
        self
    }
    fn option<T: Into<String>>(&mut self, name: &str, value: Option<T>) -> &mut Args {
        if let Some(inner) = value {
            self.args.push(name.into());
            self.args.push(inner.into());
        }
        self
    }
}
