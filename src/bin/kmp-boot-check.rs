use std::env;
use std::process;

use kmp_boot_check::{
    RealSystemProbe, exit_code, human_output, json_output, load_policy_dirs, run_checks,
};

#[derive(Debug)]
struct Args {
    kernel: Option<String>,
    config_dirs: Vec<String>,
    json: bool,
    strict: bool,
}

fn main() {
    let args = parse_args(env::args().skip(1).collect());
    let probe = RealSystemProbe;
    let extra_policies = load_policy_dirs(&args.config_dirs, &probe);
    let result = run_checks(&probe, args.kernel.as_deref(), extra_policies);

    if args.json {
        println!("{}", json_output(&result));
    } else {
        print!("{}", human_output(&result));
    }
    process::exit(exit_code(&result, args.strict));
}

fn parse_args(raw: Vec<String>) -> Args {
    let mut args = Args {
        kernel: None,
        config_dirs: vec!["/etc/kmp-boot-check/modules.d".to_string()],
        json: false,
        strict: false,
    };

    let mut index = 0;
    while index < raw.len() {
        match raw[index].as_str() {
            "--kernel" => {
                index += 1;
                args.kernel = raw.get(index).cloned();
            }
            "--config-dir" => {
                index += 1;
                if let Some(value) = raw.get(index) {
                    args.config_dirs.push(value.clone());
                }
            }
            "--json" => args.json = true,
            "--strict" => args.strict = true,
            "--help" | "-h" => {
                print_help();
                process::exit(0);
            }
            _ => {}
        }
        index += 1;
    }

    args
}

fn print_help() {
    println!("Usage: kmp-boot-check [--kernel <uname-r>] [--config-dir <dir>] [--json] [--strict]");
}
