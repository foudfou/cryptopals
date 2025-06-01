extern crate cryptopals;
extern crate getopts;

use std::env;
use std::fs::File;
use std::io;
use std::io::{Read, Write};

use cryptopals::{aes, b64, xor};
use getopts::Options;

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options] FILE", program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optopt(
        "c",
        "cmd",
        "Command, one of {aes-128-ecb-detect,h2b,xorguess}.
                 Defaults to xorguess",
        "CMD",
    );
    opts.optflag("h", "help", "Print this help menu");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!("{}", f.to_string()),
    };
    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }

    let cmd = &matches.opt_str("c").unwrap_or("xorguess".to_string());
    if matches.free.is_empty() {
        print_usage(&program, opts);
        return;
    };
    let filename = matches.free[0].clone();

    if cmd == "xorguess" {
        let mut file = File::open(filename).expect("file not found");
        let mut cipher: Vec<u8> = Vec::new();
        file.read_to_end(&mut cipher)
            .expect("something went wrong reading the file");
        for possible_key in xor::guess_xor(&cipher) {
            let k = String::from_utf8(possible_key).unwrap();
            println!("{}", k);
        }
    } else if cmd == "h2b" {
        let mut file = File::open(filename).expect("file not found");
        let mut content = String::new();
        file.read_to_string(&mut content)
            .expect("something went wrong reading the file");
        let bin = b64::hex2bytes(content.trim_end().to_string()).expect("could not parse hex");
        let mut stdout = io::stdout();
        stdout.write_all(&bin).expect("I/O error");
    } else if cmd == "aes-128-ecb-detect" {
        let mut file = File::open(filename).expect("file not found");
        let mut encoded: Vec<u8> = Vec::new();
        file.read_to_end(&mut encoded)
            .expect("something went wrong reading the file");
        if aes::detect_ecb(&encoded, 16) {
            println!("Yes, this very likely is AES_128_ECB !!!");
        } else {
            println!("No, this is not AES_128_ECB :(");
        };
    }
}
