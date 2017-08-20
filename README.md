# Web-firewall authorization.
A simple web-server and a command line interface to manage users.

## Purpose
The purpose of the software is a simple and straightforward one: add an IP
address to the firewall's white list. Currently only `shorewall` is supported
and a user is supposed to use a special *zone* as the white list.

## How to build
The project is managed by [Cargo](https://github.com/rust-lang/cargo) so one can
easily build it using the usual command (`cargo build`, …).


## How to run

### Web server
The project uses [Rocket](https://rocket.rs/) web server under the cover. To
configure it please consider reading a
[Configuration](https://rocket.rs/guide/configuration/) chapter in the
[Rocket guide](https://rocket.rs/guide/).

After building the project a `web` binary should be available. Here's an
example:
```sh
web --pass-db data/passwords.db --pass-checker data/db-checker.conf \
--shorewall shorewall --private-zone priv
```

To see available options and their descriptions:
```sh
web --help
```

### Manage users

### Client
After building the project a `manage` binary should be available. Please a
'help' command to see available options:
```sh
manage --help
```

Here's an example:
```sh
manage --pass-db data/passwords.db --pass-checker data/db-checker.conf add-user --user foo
```

## TODO
- [ ] Online changes to the database.
- [ ] Support different firewalls.
- [ ] Work on this readme.
