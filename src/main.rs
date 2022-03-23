#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .parse_env("MG_LOG")
        .init();

    log::info!("Hello, world!");
}
