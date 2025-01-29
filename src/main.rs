use error_chain::error_chain;
use futures::stream::{self, StreamExt};
use std::io::{self, BufRead};
use std::fs::File;
use std::path::PathBuf;
use url::Url;
use regex::Regex;
use urlencoding::decode;
use clap::Parser;

error_chain! {
    foreign_links {
        Io(std::io::Error);
        HttpRequest(reqwest::Error);
        UrlParse(url::ParseError);
        RegexError(regex::Error);
    }
}

#[derive(Parser, Debug)]
#[clap(author = "by wintermut3", version = "1.3", about = None, long_about = None)]
struct Args {
    #[clap(short = 'H', long = "headers", value_name = "HEADER", help = "Sets custom headers")]
    headers: Vec<String>,

    #[clap(short = 'l', long = "list", value_name = "FILE", help = "File containing URLs (one per line)")]
    url_list: Option<PathBuf>,

    #[clap(short = 't', long = "threads", value_name = "THREADS", help = "Number of concurrent threads", default_value = "5")]
    threads: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // read URLs from file
    let urls = if let Some(file_path) = args.url_list {
        let file = File::open(file_path)?;
        io::BufReader::new(file)
            .lines()
            .filter_map(|line| line.ok())
            .map(|line| line.trim().to_owned())
            .filter(|line| !line.is_empty())
            .collect()
    } else {
        // read URLs from stdin
        io::stdin()
            .lock()
            .lines()
            .filter_map(|line| line.ok())
            .map(|line| line.trim().to_owned())
            .filter(|line| !line.is_empty())
            .collect()
    };

    let urls: Vec<String> = urls;
    let total_urls = urls.len();

    if urls.is_empty() {
        println!("No URLs provided. Please either pipe URLs to the program or use the -l option to specify a file.");
        return Ok(());
    }

    println!("Starting scan with {} threads for {} URLs", args.threads, total_urls);

    let client = reqwest::Client::new();

    let results = stream::iter(urls)
        .map(|url| {
            let client = client.clone();
            let headers = args.headers.clone();
            tokio::spawn(async move {
                match check_xss_reflection(&client, &url, &headers).await {
                    Ok(result) => result,
                    Err(e) => (url, format!("Error: {:?}", e)),
                }
            })
        })
        .buffer_unordered(args.threads)
        .collect::<Vec<_>>()
        .await;

    for result in results {
        match result {
            Ok((url, status)) => println!("{} -> {}", url, status),
            Err(e) => eprintln!("Task error: {:?}", e),
        }
    }

    Ok(())
}

async fn check_xss_reflection(client: &reqwest::Client, url: &str, custom_headers: &[String]) -> Result<(String, String)> {
    let mut request = client.get(url);
    
    for header in custom_headers {
        let parts: Vec<&str> = header.splitn(2, ':').collect();
        if parts.len() == 2 {
            request = request.header(parts[0].trim(), parts[1].trim());
        }
    }

    let resp = request.send().await?;
    let status = resp.status();
    let body = resp.text().await?;

    let parsed_url = Url::parse(url)?;
    let query_params: Vec<(String, String)> = parsed_url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    for (_, value) in query_params {
        let decoded_value = decode(&value).map_err(|e| Error::from(format!("Decoding error: {}", e)))?;
        if let Some(injected_tags) = extract_tags_from_param(&decoded_value) {
            for tag in injected_tags {
                if body.contains(&tag) {
                    return Ok((
                        url.to_string(),
                        format!(
                            "Potential XSS found! Tag '{}' reflected ({})",
                            tag, status
                        ),
                    ));
                }
            }
        }
    }

    Ok((
        url.to_string(),
        format!("No tag reflection found ({})", status),
    ))
}

fn extract_tags_from_param(param: &str) -> Option<Vec<String>> {
    // regex patterns for different types of tags
    let patterns = vec![
        // tags with closing
        r"<[^>]+>[^<]*</[^>]+>",
        // tags self-closing or without closing
        r"<[^>]+>",
        // specifics attributes that mat indicate XSS
        r"onerror=[^>\s]+",
        r"OnError=[^>\s]+",
        r"onclick=[^>\s]+",
        r"OnCliCk=[^>\s]+",
        r"onload=[^>\s]+",
        r"OnLoAd=[^>\s]+",
        r"ontoggle=[^>\s]+",
        r"OnToGgLe=[^>\s]+",
        r"src=[^>\s]+",
    ];

    let mut found_tags = Vec::new();

    for pattern in patterns {
        if let Ok(re) = Regex::new(pattern) {
            for cap in re.find_iter(param) {
                found_tags.push(cap.as_str().to_string());
            }
        }
    }

    if found_tags.is_empty() {
        None
    } else {
        Some(found_tags)
    }
}