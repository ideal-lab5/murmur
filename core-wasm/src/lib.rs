use murmur_core::murmur;
use wasm_bindgen::{prelude::wasm_bindgen, JsError, JsValue};

#[wasm_bindgen]
pub fn verify() -> bool {
    true
    // murmur::verify();
}

#[wasm_bindgen]
pub fn execute() -> Result<JsValue, JsError> {
    Ok(JsValue::from_str("Hello, world!"))
    // murmur::execute();
}

#[wasm_bindgen]
pub fn create() -> Result<JsValue, JsError> {
    Ok(JsValue::from_str("Hello, world!"))
    // murmur::create();
}
