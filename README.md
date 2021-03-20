This is a fun project for generating a game sever for the dice game schocken: http://de.wikipedia.org/wiki/Schocken.
The project consists of 
- an authentication/user management backend: schocken-auth-server (the repo you look at)
- a game backend: schocken-game-server (does not exist yet)
- client front ends (does not exists yet)

The backends are written in rust-lang and you will need a working rust/cargo system (https://www.rust-lang.org) for building them. Postgresql is the supported database backend. Unit test rely on docker-compose (https://docs.docker.com/compose/).

This project is very much work in progress and will likely never yield something useable.

Building the schocken-auth-server:
```
$ git clone https://github.com/vfeld/schocken-auth-server.git
$ cd schocken-auth-server
$ cargo build --release
```

To run the unit test you need to have docker-compose installed.
In a seperate new shell starting from the schocken-auth-server root directory run:
```
$ cd docker-unittest
$ docker-compose up -d 
```
in the original shell create a .env with the following environment settings in the schocken-auth-server root directory:
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
and finaly run the tests via:
```
$ cargo test
```