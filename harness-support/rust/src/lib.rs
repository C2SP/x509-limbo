use models::Limbo;

pub mod models;

pub fn load_limbo() -> Limbo {
    serde_json::from_reader(std::io::stdin()).unwrap()
}

pub const LIMBO_JSON: &[u8] = include_bytes!("../../../limbo.json");
