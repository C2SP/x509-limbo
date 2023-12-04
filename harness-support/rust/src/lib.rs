use std::io::Read;

use models::Limbo;

pub mod models;

pub fn load_limbo() -> Limbo {
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf).unwrap();
    serde_json::from_str::<Limbo>(&buf).unwrap()
}
