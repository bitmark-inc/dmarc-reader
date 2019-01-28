// config.rs

use rlua::{Lua, Result, Table};
//use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;

#[derive(Debug, PartialEq)]
pub struct Database {
    pub database: String,
    pub user: String,
    pub password: String,
    pub host: String,
    pub port: Option<u16>,
}

// allow use of '?' to quick return error
//type MyResult<T> = Result<T, Box<Error>>;

pub fn read(filename: &str, debug: bool) -> Result<Database> {
    if debug {
        println!("configuration file: {}", filename);
    }

    let file = File::open(filename).unwrap();
    let mut buf_reader = BufReader::new(file);
    let mut contents = String::new();
    buf_reader.read_to_string(&mut contents).unwrap();

    if debug {
        println!("configuration text: {}", contents);
    }

    let lua = Lua::new();
    let db = lua.context(|lua| {
        let arg = lua.create_table()?;
        arg.set(0, filename)?;

        let globals = lua.globals();
        globals.set("arg", arg)?;

        let config = lua.load(&contents).set_name("config")?.eval::<Table>()?;

        let database: Table = config.get("database")?;

        let db = Database {
            database: database.get("database")?,
            user: database.get("user")?,
            password: database.get("password")?,
            host: database.get("host")?,
            port: match database.get::<_, String>("port")?.parse::<u16>() {
                Ok(n) => Some(n),
                Err(_) => None,
            },
        };

        Ok(db)
    })?;

    Ok(db)
}
