#![feature(plugin)]
#![feature(custom_derive)]
#![plugin(rocket_codegen)]

extern crate auth;
extern crate clap;
extern crate rocket;
#[macro_use]
extern crate rocket_contrib;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

use auth::firewall::Firewall;
use auth::pass_checker::PassChecker;
use auth::pass_db::PassDb;
use auth::shorewall::Shorewall;
use rocket::State;
use rocket::http::{Cookie, Cookies};
use rocket::request::{Form, FlashMessage};
use rocket::response::{Flash, Redirect};
use rocket_contrib::Template;
use std::net::SocketAddr;

mod helpers;
use helpers::FlashMsg;

/// Command line options.
fn build_cli() -> clap::App<'static, 'static> {
    use clap::{App, Arg};
    App::new("Web auth")
        .about("Launches a web server.")
        .arg(
            Arg::with_name("SHOREWALL_BIN")
                .long("shorewall")
                .value_name("path")
                .takes_value(true)
                .required(true)
                .help("Path to the shorewall executable."),
        )
        .arg(
            Arg::with_name("PRIVATE_ZONE")
                .short("z")
                .long("private-zone")
                .value_name("zone")
                .takes_value(true)
                .required(true)
                .help("Name of the private zone."),
        )
        .arg(
            Arg::with_name("PASS_CONFIG")
                .long("pass-checker")
                .value_name("path")
                .takes_value(true)
                .required(true)
                .help("Path to the password checked configuration."),
        )
        .arg(
            Arg::with_name("PASS_DB")
                .long("pass-db")
                .value_name("path")
                .takes_value(true)
                .required(true)
                .help("Path to the passwords database."),
        )
}

/// Checks user authorization on the firewall.
#[get("/auth")]
fn auth_get(
    remote_addr: SocketAddr,
    fw: State<Shorewall>,
    flash: Option<FlashMessage>,
    cookies: Cookies,
) -> Result<Template, <Shorewall as Firewall>::Error> {
    let ip = remote_addr.ip();
    let flash: Option<FlashMsg> = flash.map(|f| f.into());
    Ok(Template::render(
        "auth",
        json!{{
            "ip": ip.to_string(),
            "already_there": fw.check_ip(&ip)?,
            "flash": flash,
            "name": cookies.get("name").map(|c| c.value()),
        }},
    ))
}

/// Authentication form.
#[derive(FromForm)]
struct AuthForm {
    login: String,
    password: String,
}

/// Authorizes a user on the firewall.
#[post("/auth", data = "<form>")]
fn auth_post(
    form: Form<AuthForm>,
    remote_addr: SocketAddr,
    pass_checker: State<PassChecker>,
    pass_db: State<PassDb>,
    fw: State<Shorewall>,
    mut cookies: Cookies,
) -> Result<Flash<Redirect>, <Shorewall as Firewall>::Error> {
    cookies.add(Cookie::new("name", form.get().login.clone()));
    let hash = match pass_db.find_hash(&form.get().login) {
        Some(hash) => hash,
        None => return Ok(Flash::error(Redirect::to("/auth"), "User not found")),
    };
    if pass_checker.check_password(&form.get().login, &hash, &form.get().password) {
        let ip = remote_addr.ip();
        if !fw.check_ip(&ip)? {
            fw.add_ip(&ip)?;
        }
        Ok(Flash::success(Redirect::to("/auth"), "Success!"))
    } else {
        Ok(Flash::error(
            Redirect::to("/auth"),
            "Password doesn't match",
        ))
    }
}

/// Index page. Simply redirects to the auth page.
#[get("/")]
fn index() -> Redirect {
    Redirect::to("/auth")
}

fn main() {
    let matches = build_cli().get_matches();
    let shorewall_bin = matches.value_of("SHOREWALL_BIN").expect(
        "Shorewall binary not provided.",
    );
    let private_zone = matches.value_of("PRIVATE_ZONE").expect(
        "Private zone not provided.",
    );
    let pass_config_path = matches.value_of("PASS_CONFIG").expect(
        "Password configuration path not provided.",
    );
    let pass_db_path = matches.value_of("PASS_DB").expect(
        "Passwords database path not provided.",
    );

    let pass_checker =
        PassChecker::load(pass_config_path).expect("Can't load password checker configuration");
    let pass_db = PassDb::load(pass_db_path).expect("Can't load a password database");
    let shorewall = Shorewall::new(shorewall_bin, private_zone);
    rocket::ignite()
        .mount("/", routes!{auth_get, auth_post, index})
        .attach(Template::fairing())
        .manage(shorewall)
        .manage(pass_checker)
        .manage(pass_db)
        .launch();
}
