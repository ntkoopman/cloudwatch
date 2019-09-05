#[macro_use]
extern crate serde_derive;

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::{fs, io};

use chrono::{Local, TimeZone};
use chrono_english::{parse_date_string, Dialect};
use clap::{App, Arg, ArgGroup};
use colored::*;
use crypto::digest::Digest;
use crypto::sha1::Sha1;
use rusoto_core::Region;
use rusoto_logs::{CloudWatchLogs, CloudWatchLogsClient, FilterLogEventsRequest};

#[derive(Debug, Deserialize, Serialize)]
struct LogEvent {
    #[serde(rename = "eventId")]
    event_id: Option<String>,
    #[serde(rename = "ingestionTime")]
    ingestion_time: Option<i64>,
    #[serde(rename = "logStreamName")]
    log_stream_name: Option<String>,
    #[serde(rename = "message")]
    message: Option<String>,
    #[serde(rename = "timestamp")]
    timestamp: Option<i64>,
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

    let cache_dir = dirs::cache_dir().unwrap().join(Path::new("cloudwatch"));
    fs::create_dir_all(&cache_dir).expect("could not create cache dir");
    let path = cache_dir.join(Path::new(&hash));

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
                print_event(value);
            }
        } else {
            io::copy(&mut file, &mut stdout).unwrap();
        }
        return;
    }

    let now = Local::now();
    let to_timestamp = |x| {
        parse_date_string(x, now, Dialect::Uk)
            .unwrap()
            .timestamp_millis()
    };

    let client = CloudWatchLogsClient::new(Region::default());

    let temporary_path = path.with_extension("partial");
    let mut file = File::create(temporary_path.clone()).unwrap();

    // Custom paging to avoid loading the entire data set into memory
    let mut remaining = max_items.map(|x| x.parse::<i64>().unwrap());
    let mut next_token = None;

    while remaining.is_none() || remaining.unwrap() > 0 {
        let event = FilterLogEventsRequest {
            end_time: end_time.map(to_timestamp),
            filter_pattern: filter_pattern.map(|x| x.to_string()),
            interleaved: Some(true),
            limit: Some(remaining.unwrap_or(1000).min(1000)),
            log_group_name: log_group_name.to_string(),
            log_stream_name_prefix: None,
            log_stream_names: log_stream_name.map(|x| vec![x.to_string()]),
            next_token,
            start_time: start_time.map(to_timestamp),
        };

        let response = client.filter_log_events(event).sync();
        if let Err(e) = response {
            std::io::stderr()
                .write(format!("{:?}", e).as_bytes())
                .unwrap();
            return;
        }

        let response = response.unwrap();
        let events = response.events.unwrap();

        if let Some(count) = remaining {
            remaining = Some(count - events.len() as i64);
        }

        for event in events {
            let event = LogEvent {
                event_id: event.event_id,
                ingestion_time: event.ingestion_time,
                log_stream_name: event.log_stream_name,
                message: event.message,
                timestamp: event.timestamp,
            };

            let json = serde_json::to_string(&event).unwrap();
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

        next_token = response.next_token;
        if next_token.is_none() {
            // At the end of the stream
            break;
        }
    }

    fs::rename(temporary_path, path).unwrap();
}

fn print_event(event: LogEvent) {
    let timestamp = event.timestamp.unwrap();
    let message = event.message.unwrap();
    let time = Local.timestamp_millis(timestamp);
    println!("{} {}", time.to_rfc3339().green(), message);
}
