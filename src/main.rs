mod abac_lab;
mod cal_probabilities;
mod cal_shannon_entropy;
mod ip_based;

use abac_lab::parser::Parser;
use std::fs::File;
use std::io::prelude::*;

use cal_probabilities::*;
use abac_lab::attr_val::*;
use ip_based::entity::*;

use serde_json::Value;

fn main() {
    println!("In File: {}", "data/ip_based_abac_entity.json");
    let json_str = std::fs::read_to_string("data/ip_based_abac_entity.json").expect("File not found");
    let json: Value = serde_json::from_str(&json_str).expect("JSON parse error");

    if let Some(Value::Array(source_entities)) = json.get("source_entities") {
        for entity in source_entities {
            let entity = SourceEntity::from_json_value(entity).expect("Failed to parse source entity");
            println!("{:?}", entity);
        }
    }

    if let Some(Value::Array(destination_entities)) = json.get("destination_entities") {
        for entity in destination_entities {
            let entity = DestinationEntity::from_json_value(entity).expect("Failed to parse destination entity");
            println!("{:?}", entity);
        }
    }

    // let mut file = File::open("data/university.abac").expect("File not found");

    // let mut contents = String::new();
    // file.read_to_string(&mut contents).expect("There was an error reading the file");

    // let mut parser = Parser::new();
    // for line in contents.lines() {
    //     if let Err(e) = parser.parse_line(line) {
    //         eprintln!("Error parsing line '{}' : {}", line, e);
    //     }
    // }

    // println!("\nParsed {} users", parser.users.len());
    // println!("Parsed {} resources", parser.resources.len());
    // println!("Parsed {} rules", parser.rules.len());

    // for attr_key in [
    //     UserAttributeKey::Position,
    //     UserAttributeKey::Department,
    //     UserAttributeKey::CrsTaken,
    //     UserAttributeKey::CrsTaught,
    //     UserAttributeKey::IsChair,
    // ] {
    //     let entropy = cal_user_attribute_entropy(&parser.users, &attr_key);
    //     println!("{:?}: {:.4}", attr_key, entropy);
    // }

    // for attr_key in [
    //     ResourceAttributeKey::Type,
    //     ResourceAttributeKey::Crs,
    //     ResourceAttributeKey::Student,
    //     ResourceAttributeKey::Departments,
    // ] {
    //     let entropy = cal_resource_attribute_entropy(&parser.resources, &attr_key);
    //     println!("{:?}: {:.4}", attr_key, entropy);
    // }
    
}
