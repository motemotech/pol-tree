mod attr_val;
mod parser;
mod cal_probabilities;
mod cal_shannon_entropy;

use parser::Parser;
use std::fs::File;
use std::io::prelude::*;

use cal_probabilities::*;
use attr_val::*;

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

    for attr_key in [
        UserAttributeKey::Position,
        UserAttributeKey::Department,
        UserAttributeKey::CrsTaken,
        UserAttributeKey::CrsTaught,
        UserAttributeKey::IsChair,
    ] {
        let entropy = cal_user_attribute_entropy(&parser.users, &attr_key);
        println!("{:?}: {:.4}", attr_key, entropy);
    }

    for attr_key in [
        ResourceAttributeKey::Type,
        ResourceAttributeKey::Crs,
        ResourceAttributeKey::Student,
        ResourceAttributeKey::Departments,
    ] {
        let entropy = cal_resource_attribute_entropy(&parser.resources, &attr_key);
        println!("{:?}: {:.4}", attr_key, entropy);
    }
    
}
