mod cli;
mod error;
mod model;
mod runtime;

use std::env;
use std::process;

use cli::{HELP_TEXT, USAGE, parse_args};
use error::Error;
use model::Action;
use runtime::run_list;

fn main() {
    match run(env::args().collect()) {
        Ok(()) => process::exit(0),
        Err(Error::Usage(msg)) => {
            eprintln!("lsof: {msg}");
            eprintln!("{USAGE}");
            process::exit(1);
        }
        Err(err) => {
            eprintln!("lsof: {err}");
            process::exit(1);
        }
    }
}

fn run(args: Vec<String>) -> Result<(), Error> {
    match parse_args(&args[1..])? {
        Action::Help => {
            println!("{HELP_TEXT}");
            Ok(())
        }
        Action::Version => {
            println!("lsof {version}", version = env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Action::List(opts) => run_list(opts),
    }
}
