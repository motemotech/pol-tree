mod attr_val;
mod parser;

use std::env;
use parser::Parser;
use std::fs::File;
use std::io::prelude::*;

fn main() {
    println!("In File: {}", "data/university.abac");

    let mut file = File::open("data/university.abac").expect("File not found");

    let mut contents = String::new();
    file.read_to_string(&mut contents).expect("There was an error reading the file");

    let mut parser = Parser::new();
    for line in contents.lines() {
        if let Err(e) = parser.parse_line(line) {
            eprintln!("Error parsing line '{}' : {}", line, e);
        }
    }

    println!("\nParsed {} users", parser.users.len());
    println!("Parsed {} resources", parser.resources.len());
    println!("Parsed {} rules", parser.rules.len());

    // デバッグ出力
    for user in &parser.users {
        println!("User: {:?}", user);
    }

}
