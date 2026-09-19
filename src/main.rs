//! Envoltorio delgado: inicializa el runtime y delega en `gateway::run`.

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    gateway::run().await;
}
