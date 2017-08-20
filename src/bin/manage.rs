extern crate auth;
extern crate clap;
extern crate rpassword;

use auth::pass_checker::PassChecker;
use auth::pass_db::PassDb;
use std::path::Path;

/// Command line options.
fn build_cli() -> clap::App<'static, 'static> {
    use clap::{App, Arg, SubCommand};
    App::new("Web auth")
        .about("Manages a passwords database.")
        .arg(
            Arg::with_name("PASS_DB")
                .long("pass-db")
                .value_name("path")
                .takes_value(true)
                .required(true)
                .help("Path to the passwords database."),
        )
        .arg(
            Arg::with_name("PASS_CHECKER")
                .long("pass-checker")
                .value_name("path")
                .takes_value(true)
                .required(true)
                .help("Path to the passwords checker configuration."),
        )
        .subcommand(
            SubCommand::with_name("add-user")
                .about("Add a user to the database")
                .arg(
                    Arg::with_name("user")
                        .short("u")
                        .long("user")
                        .help("User name")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("remove-user")
                .about("Remove a user to the database")
                .arg(
                    Arg::with_name("user")
                        .short("u")
                        .long("user")
                        .help("User name")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(SubCommand::with_name("list-users").about(
            "List users in the database",
        ))
}

/// Initialize a new password checker.
fn new_pass_checker() -> PassChecker {
    const HASH_ITERATIONS: u32 = 100_000;
    let salt = vec![1u8, 2u8];
    PassChecker::new(HASH_ITERATIONS, salt)
}

/// Asks for a user input.
fn get_password() -> String {
    rpassword::prompt_password_stdout("Password: ").expect("Can't read a password")
}

fn main() {
    let matches = build_cli().get_matches();
    let db_path = matches.value_of("PASS_DB").expect(
        "No path to the database is given.",
    );
    let pass_checker_path = matches.value_of("PASS_CHECKER").expect(
        "No path to the password storage configuration is given.",
    );

    if matches.subcommand.is_none() {
        panic!["No subcommand has been specified"]
    }

    let mut db: PassDb = if Path::new(db_path).is_file() {
        PassDb::load(db_path).expect("Can't load a database.")
    } else {
        PassDb::new()
    };

    let pass_checker: PassChecker = if Path::new(pass_checker_path).is_file() {
        PassChecker::load(pass_checker_path).expect("Can't load a password checker configuration.")
    } else {
        let db = new_pass_checker();
        db.save(pass_checker_path).expect(
            "Can't save the password checker configuration.",
        );
        db
    };

    if let Some(matches) = matches.subcommand_matches("add-user") {
        let user = matches.value_of("user").expect("No user name provided.");
        let hash = pass_checker.hash_password(user, &get_password());
        db.insert(user, hash);
    }

    if let Some(matches) = matches.subcommand_matches("remove-user") {
        let user = matches.value_of("user").expect("No user name provided.");
        db.remove(user);
    }

    if let Some(_) = matches.subcommand_matches("list-users") {
        for user in db.list_users() {
            println!["{}", user];
        }
    }

    db.save(db_path).expect("Can't save the database");
}
