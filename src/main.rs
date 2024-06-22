use std::error::Error;
use std::fs::File;
use std::io::{Error as IOError, ErrorKind, Read};
use std::path::Path;
use std::time::Duration;

use clap::{arg, command, Parser};
use futures_util::StreamExt;
use goblin::pe::PE;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use tokio::io::AsyncWriteExt;

#[derive(Debug)]
struct DllInfo {
    dll_path: String,
    dll_guid: String,
    pdb_name: String,
    pdb_path: String,
    cab_path: String,
}

fn parse_dll(dll_path: &str) -> Result<DllInfo, Box<dyn Error>> {
    let mut dll_buffer = Vec::new();
    File::open(dll_path)?.read_to_end(&mut dll_buffer)?;

    let pe = PE::parse(&dll_buffer).expect("dll parse failed");
    let debug_info = pe.debug_data.expect("dll no debug data")
        .codeview_pdb70_debug_info.expect("dll no debug info");

    let pdb_path_raw = std::str::from_utf8(debug_info.filename)
        .unwrap_or("")
        .trim_end_matches('\0')
        .trim_end();

    let pdb_name = Path::new(pdb_path_raw)
        .file_name().expect("parse pdb name failed")
        .to_str().expect("parse pdb name failed")
        .to_string();

    let pdb_name_without_ext = Path::new(pdb_path_raw)
        .file_stem().expect("parse pdb name failed")
        .to_str().expect("parse pdb name failed")
        .to_string();

    let guid_buf = debug_info.signature;
    let dll_guid = format!(
        "{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        u32::from_le_bytes([guid_buf[0], guid_buf[1], guid_buf[2], guid_buf[3]]),
        u16::from_le_bytes([guid_buf[4], guid_buf[5]]),
        u16::from_le_bytes([guid_buf[6], guid_buf[7]]),
        guid_buf[8], guid_buf[9], guid_buf[10], guid_buf[11], guid_buf[12], guid_buf[13], guid_buf[14], guid_buf[15]
    );

    let cab_path = Path::new(dll_path).parent().unwrap();
    let cab_path = Path::join(&cab_path, format!("{}.cab", pdb_name_without_ext));
    let cab_path = cab_path.to_str().unwrap();

    let pdb_path = Path::new(dll_path).parent().unwrap();
    let pdb_path = Path::join(pdb_path, pdb_name);
    let pdb_path = pdb_path.to_str().unwrap();

    Ok(DllInfo { dll_path: dll_path.to_string(), dll_guid, pdb_name: pdb_name_without_ext, pdb_path: pdb_path.to_string(), cab_path: cab_path.to_string() })
}

async fn download_cab(dll_info: &DllInfo) -> Result<(), Box<dyn Error>> {
    let cab_url = format!("http://symbolserver.unity3d.com/{}.pdb/{}1/{}.pd_",
                          dll_info.pdb_name, dll_info.dll_guid, dll_info.pdb_name);
    // println!("{cab_url}");
    // if Path::new(&dll_info.cab_path).exists() {
    //     return Err(Box::new(IOError::new(ErrorKind::AlreadyExists, "Cab file already exists")));
    // }

    let client = Client::builder()
        // .proxy(Proxy::http("http://127.0.0.1:10809/").unwrap())
        .build()?;
    let resp = client.get(cab_url).send().await?;

    if !resp.status().is_success() {
        return Err(Box::new(IOError::new(ErrorKind::AddrNotAvailable, "Cab request failed")));
    }

    let total_size = resp.headers()
        .get("content-length")
        .and_then(|x| x.to_str().ok())
        .and_then(|x| x.parse::<u64>().ok())
        .unwrap_or(0);

    if total_size == 0 {
        return Err(Box::new(IOError::new(ErrorKind::AddrNotAvailable, "Cab size wrong")));
    }

    let mut out_file = tokio::fs::File::create(&dll_info.cab_path).await?;

    let mut stream = resp.bytes_stream();

    // 创建一个新的进度条
    let progress_bar = ProgressBar::new(total_size);
    progress_bar.set_message("Download cab file");

    // 设置进度条的样式
    progress_bar.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} {msg} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
        //.progress_chars("#>-")
    );

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        out_file.write_all(&chunk).await?;
        progress_bar.inc(chunk.len() as u64);
    }

    progress_bar.finish();

    Ok(())
}

async fn extract_cab(dll_info: &DllInfo) -> Result<(), Box<dyn Error>> {
    let spinner = ProgressBar::new_spinner();
    spinner.set_message("Extract cab file");
    spinner.enable_steady_tick(Duration::from_millis(100));
    spinner.set_style(ProgressStyle::default_spinner().template("{spinner:.green} {msg} {elapsed_precise}").unwrap());

    {
        let cab_file = File::open(&dll_info.cab_path)?;
        let mut cabinet = cab::Cabinet::new(cab_file)?;

        let mut files: Vec<String> = vec![];

        for folder in cabinet.folder_entries().into_iter() {
            for file in folder.file_entries() {
                files.push(file.name().to_string());
            }
        }

        for file in files {
            let mut reader = cabinet.read_file(file.as_str())?;
            let mut writer = File::create(dll_info.pdb_path.as_str())?;
            std::io::copy(&mut reader, &mut writer)?;
        }
    }

    spinner.finish();

    Ok(())
}

async fn delete_cab(dll_info: &DllInfo) -> Result<(), Box<dyn Error>> {
    tokio::fs::remove_file(&dll_info.cab_path).await?;
    Ok(())
}

#[derive(Parser, Debug)]
#[command(name = "Unity PDB Downloader", version = "1.0.0", author = "jeferwang")]
struct Args {
    #[arg(short, long)]
    input: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let dll_path = args.input;

    println!("Input DLL file: {dll_path}");

    let dll_info = parse_dll(dll_path.as_str()).expect("parse dll failed");
    println!("Parsed {:#?}", dll_info);

    download_cab(&dll_info).await.expect("download cab failed");

    extract_cab(&dll_info).await.expect("extract cab failed");

    delete_cab(&dll_info).await.expect("delete cab failed");

    Ok(())
}
