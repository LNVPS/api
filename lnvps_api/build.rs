fn main() {
    #[cfg(feature = "openapi")]
    {
        use openapi_build_gen::{InfoBuilder, generate_spec};
        use std::env;
        use std::path::PathBuf;
        println!("cargo:rerun-if-changed=src");

        let out_dir = env::var("OUT_DIR").unwrap();
        let openapi_rs = PathBuf::from(&out_dir).join("openapi.rs");

        // Generate OpenAPI spec from src directory
        generate_spec("src")
            .expect("Failed to generate spec")
            .with_info(
                InfoBuilder::new("LNVPS", env!("CARGO_PKG_VERSION"))
                    .description("A lightning powered VPS provider")
                    .contact(
                        Some("Sales".to_string()),
                        Some("https://lnvps.net".to_string()),
                        Some("sales@lnvps.net".to_string()),
                    )
                    .license(
                        "MIT",
                        Some("https://opensource.org/licenses/MIT".to_string()),
                    )
                    .build(),
            )
            .write_rust_to_file(&openapi_rs, "OPENAPI_SPEC")
            .expect("Failed to write openapi.rs");
    }
}
