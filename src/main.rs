//! Envoltorio delgado: inicializa el runtime y delega en `gateway::run`.

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    if let Err(err) = gateway::run().await {
        tracing::error!(error = %err, "el proceso de gateway terminó con un error fatal");
        std::process::exit(1);
    }
}
