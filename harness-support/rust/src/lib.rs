use models::Limbo;

pub mod models;

// `cargo run` runs from the workspace root, so this is relative to
// the root.
const LIMBO_JSON: &str = "limbo.json";

pub fn load_limbo() -> Limbo {
    serde_json::from_str::<Limbo>(&std::fs::read_to_string(LIMBO_JSON).unwrap()).unwrap()
}
