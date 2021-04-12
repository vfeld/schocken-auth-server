# What is this?

This is a fun project for creating the back and frontend for the dice game "schocken": http://de.wikipedia.org/wiki/Schocken.
The project consists of 
- an authentication/user management backend: schocken-auth-server (the repo you look at)
- a game backend: schocken-game-server (does not exist yet)
- client front ends (do not exists yet)

The backends are written in rust-lang and you will need a working rust/cargo system (https://www.rust-lang.org) for building them. Postgres 12 is the supported database backend. Unittest rely on docker-compose (https://docs.docker.com/compose/).

This project is very much work in progress and will likely never yield something useable, but its a nice way to kill time.

# Getting Started

Building the schocken-auth-server:
```
$ git clone https://github.com/vfeld/schocken-auth-server.git
$ cd schocken-auth-server
$ cargo build --release
```

To run the unit test you need to have docker-compose installed (not in the scope of this tutorial)
and have an .env file with the following settings
```
$ cat .env
DB_HOST=127.0.0.1
DB_PORT=5432
DB_USER=pgadmin
DB_PWD=secret
DAY0_TOKEN=1234567890
HOST=127.0.0.1
PORT=8080
RUST_LOG=info
```
Now you are ready to execute the tests 
```
$ docker-compose -f integrations/docker-compose-unittest/docker-compose.yml up -d
$ cargo test
$ docker-compose -f integrations/docker-compose-unittest/docker-compose.yml down
```

# Further Reading
- [Architecture Overview](doc/dev/README.md)
