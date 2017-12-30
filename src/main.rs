extern crate getopts;
extern crate cryptopals;

use std::env;
use std::fs::File;
use std::io::Read;

use getopts::Options;
use cryptopals::xor;

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options] FILE", program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    // opts.optopt("o", "", "set output file name", "NAME");
    opts.optflag("h", "help", "print this help menu");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(f) => { panic!(f.to_string()) }
    };
    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }

    // let output = matches.opt_str("o");
    let filename = if !matches.free.is_empty() {
        matches.free[0].clone()
    } else {
        print_usage(&program, opts);
        return;
    };

    let mut file = File::open(filename).expect("file not found");
    let mut cipher: Vec<u8> = Vec::new();
    file.read_to_end(&mut cipher)
        .expect("something went wrong reading the file");
    for possible_key in xor::guess_xor(&cipher) {
        let k = String::from_utf8(possible_key).unwrap();
        println!("{}", k);
    }

}
