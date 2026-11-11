//! Consumidor del Kinesis Data Stream `security-events` (feature
//! `admin_realtime_feed`, tarea KAP-09): lee los eventos de seguridad y los
//! entrega al [`AdminAggregator`] que sirve el panel de administración.
//!
//! ## Decisiones de diseño
//!
//! - **Lectura directa, sin KCL**: `ListShards`, y por shard
//!   `GetShardIterator(LATEST)` + `GetRecords`. Cada instancia del Gateway
//!   lee todos los eventos (el panel es una vista en vivo, no un registro de
//!   auditoría), así que no hay checkpoints ni coordinación entre
//!   instancias. Consecuencia aceptada: lo publicado mientras una instancia
//!   estaba caída no aparece en ella.
//! - **Puerto [`RecordsSource`]**: el bucle no conoce AWS. [`AwsRecordsSource`]
//!   es el adaptador real; los tests usan una fuente falsa y el reloj pausado
//!   de `tokio`, sin esperas reales.
//! - **Un worker por shard abierto**. Cada [`SHARD_REFRESH`] se vuelve a
//!   listar: un shard nuevo (resharding) recibe su worker, y uno cerrado
//!   (`next_iterator` ausente) termina el suyo.
//! - **Iterador vencido**: no es un error; el worker vuelve a tomar `LATEST`
//!   (lo ocurrido en el hueco se pierde, se loggea un `warn`).
//! - **Errores**: backoff exponencial de [`BACKOFF_INITIAL`] a [`BACKOFF_MAX`]
//!   (mismas constantes que el consumidor SQS), reiniciado tras un éxito. Los
//!   errores se loggean con su cadena de causas, nunca con el cuerpo de un
//!   registro.
//! - **Registros inválidos**: JSON roto o fuera del contrato
//!   ([`crate::event_contract`]) se descartan con un `warn` (solo la regla
//!   incumplida y el largo) y se cuentan en el agregador.
//! - **Shutdown**: un [`CancellationToken`] compite contra cada llamada y
//!   cada espera; `run` espera a sus workers y retorna de inmediato.
//!
//! Las credenciales salen de la cadena de proveedores por defecto de AWS;
//! `AWS_ENDPOINT_URL` solo se usa contra LocalStack (ver [`crate::kinesis`]).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use aws_sdk_kinesis::error::DisplayErrorContext;
use aws_sdk_kinesis::types::ShardIteratorType;
use aws_sdk_kinesis::Client;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::admin::AdminAggregator;
use crate::event_contract::parse_record;

/// Espera entre sondeos de `GetRecords` de un mismo shard (el límite de
/// Kinesis es de 5 lecturas por segundo y shard).
pub const POLL_INTERVAL: Duration = Duration::from_secs(1);
/// Primer backoff tras un error.
pub const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
/// Tope del backoff exponencial.
pub const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// Cada cuánto se vuelve a listar los shards del stream.
pub const SHARD_REFRESH: Duration = Duration::from_secs(30);
/// Máximo de registros por `GetRecords`.
const GET_RECORDS_LIMIT: i32 = 1000;

/// Errores de una [`RecordsSource`].
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    /// El iterador de shard venció; hay que tomar uno nuevo.
    #[error("el iterador del shard venció")]
    IteratorExpired,
    /// Cualquier otro fallo (red, permisos, throttling...). Su causa solo es
    /// visible vía `source()`.
    #[error("falló la lectura del stream de Kinesis")]
    Failed(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// Lote devuelto por [`RecordsSource::get_records`].
#[derive(Debug)]
pub struct RecordsBatch {
    /// Cuerpos de los registros, en orden.
    pub records: Vec<Vec<u8>>,
    /// Iterador siguiente; `None` si el shard se cerró.
    pub next_iterator: Option<String>,
}

/// Puerto: de dónde salen los registros del stream.
#[async_trait::async_trait]
pub trait RecordsSource: Send + Sync {
    /// Ids de los shards abiertos del stream.
    async fn list_open_shards(&self) -> Result<Vec<String>, SourceError>;
    /// Iterador que empieza en el registro más nuevo (`LATEST`) de `shard_id`.
    async fn latest_iterator(&self, shard_id: &str) -> Result<String, SourceError>;
    /// Lee un lote desde `iterator`.
    async fn get_records(&self, iterator: &str) -> Result<RecordsBatch, SourceError>;
}

/// Siguiente espera del backoff: el doble, con tope en [`BACKOFF_MAX`].
fn next_backoff(current: Duration) -> Duration {
    (current * 2).min(BACKOFF_MAX)
}

/// Consumidor de eventos de seguridad (ver la documentación del módulo).
pub struct SecurityEventConsumer {
    source: Arc<dyn RecordsSource>,
    aggregator: Arc<AdminAggregator>,
}

impl std::fmt::Debug for SecurityEventConsumer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityEventConsumer")
            .finish_non_exhaustive()
    }
}

/// Espera `duration`; `false` si `shutdown` se canceló antes.
async fn sleep_or_shutdown(duration: Duration, shutdown: &CancellationToken) -> bool {
    tokio::select! {
        () = shutdown.cancelled() => false,
        () = tokio::time::sleep(duration) => true,
    }
}

fn log_source_error(error: &SourceError, retry_in: Duration, what: &str) {
    let chain = match error {
        SourceError::Failed(source) => source.to_string(),
        SourceError::IteratorExpired => error.to_string(),
    };
    tracing::error!(
        error = %chain,
        retry_in_secs = retry_in.as_secs(),
        "{what}; reintentando"
    );
}

impl SecurityEventConsumer {
    /// Consumidor que lee de `source` y alimenta a `aggregator`.
    pub fn new(source: Arc<dyn RecordsSource>, aggregator: Arc<AdminAggregator>) -> Self {
        Self { source, aggregator }
    }

    /// Lee el stream hasta que `shutdown` se cancele (ver la nota de diseño
    /// del módulo).
    pub async fn run(self, shutdown: CancellationToken) {
        let mut workers: HashMap<String, JoinHandle<()>> = HashMap::new();
        let mut backoff = BACKOFF_INITIAL;
        loop {
            let wait = match self.source.list_open_shards().await {
                Ok(shards) => {
                    backoff = BACKOFF_INITIAL;
                    workers.retain(|_, worker| !worker.is_finished());
                    for shard_id in shards {
                        workers.entry(shard_id.clone()).or_insert_with(|| {
                            tokio::spawn(run_shard(
                                self.source.clone(),
                                self.aggregator.clone(),
                                shard_id,
                                shutdown.clone(),
                            ))
                        });
                    }
                    SHARD_REFRESH
                }
                Err(error) => {
                    log_source_error(&error, backoff, "error listando los shards de Kinesis");
                    let wait = backoff;
                    backoff = next_backoff(backoff);
                    wait
                }
            };
            if !sleep_or_shutdown(wait, &shutdown).await {
                break;
            }
        }
        for (_, worker) in workers {
            let _ = worker.await;
        }
        tracing::info!("consumidor de eventos de seguridad detenido");
    }
}

/// Bucle de un shard: toma `LATEST`, sondea siguiendo `next_iterator` y, si el
/// iterador vence, vuelve a tomar `LATEST`.
async fn run_shard(
    source: Arc<dyn RecordsSource>,
    aggregator: Arc<AdminAggregator>,
    shard_id: String,
    shutdown: CancellationToken,
) {
    let mut backoff = BACKOFF_INITIAL;
    'acquire: loop {
        let mut iterator = loop {
            let result = tokio::select! {
                () = shutdown.cancelled() => return,
                result = source.latest_iterator(&shard_id) => result,
            };
            match result {
                Ok(iterator) => break iterator,
                Err(error) => {
                    log_source_error(&error, backoff, "error tomando el iterador LATEST");
                    if !sleep_or_shutdown(backoff, &shutdown).await {
                        return;
                    }
                    backoff = next_backoff(backoff);
                }
            }
        };

        loop {
            let result = tokio::select! {
                () = shutdown.cancelled() => return,
                result = source.get_records(&iterator) => result,
            };
            match result {
                Ok(batch) => {
                    backoff = BACKOFF_INITIAL;
                    for body in &batch.records {
                        process_record(&aggregator, body);
                    }
                    let Some(next) = batch.next_iterator else {
                        tracing::info!("shard de Kinesis cerrado; su worker termina");
                        return;
                    };
                    iterator = next;
                    if !sleep_or_shutdown(POLL_INTERVAL, &shutdown).await {
                        return;
                    }
                }
                Err(SourceError::IteratorExpired) => {
                    tracing::warn!(
                        "el iterador del shard venció; se retoma desde LATEST (los registros \
                         del hueco no se muestran)"
                    );
                    continue 'acquire;
                }
                Err(error) => {
                    log_source_error(&error, backoff, "error leyendo registros de Kinesis");
                    if !sleep_or_shutdown(backoff, &shutdown).await {
                        return;
                    }
                    backoff = next_backoff(backoff);
                }
            }
        }
    }
}

/// Valida un registro y lo entrega al agregador; uno inválido se descarta con
/// un `warn` sin el cuerpo y se cuenta.
fn process_record(aggregator: &AdminAggregator, body: &[u8]) {
    match parse_record(body) {
        Ok(event) => aggregator.ingest(&event),
        Err(rejection) => {
            tracing::warn!(
                reason = %rejection,
                record_len = body.len(),
                "registro de Kinesis descartado por no cumplir el contrato"
            );
            aggregator.record_malformed();
        }
    }
}

/// Adaptador real de [`RecordsSource`] sobre el SDK de AWS.
#[derive(Clone)]
pub struct AwsRecordsSource {
    client: Client,
    stream_name: String,
}

impl std::fmt::Debug for AwsRecordsSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsRecordsSource")
            .field("stream_name", &self.stream_name)
            .finish_non_exhaustive()
    }
}

impl AwsRecordsSource {
    /// Fuente sobre un `client` ya configurado (los tests inyectan uno
    /// apuntando a LocalStack).
    pub fn from_client(client: Client, stream_name: String) -> Self {
        Self {
            client,
            stream_name,
        }
    }

    /// Fuente con la cadena de credenciales por defecto de AWS, la `region`
    /// indicada y, opcionalmente, un `endpoint_url` (solo LocalStack).
    pub async fn connect(region: &str, endpoint_url: Option<&str>, stream_name: String) -> Self {
        Self::from_client(
            crate::kinesis::build_client(region, endpoint_url).await,
            stream_name,
        )
    }
}

fn failed<E>(error: E) -> SourceError
where
    E: std::error::Error + Send + Sync + 'static,
{
    SourceError::Failed(Box::new(error))
}

#[async_trait::async_trait]
impl RecordsSource for AwsRecordsSource {
    async fn list_open_shards(&self) -> Result<Vec<String>, SourceError> {
        let mut open = Vec::new();
        let mut next_token: Option<String> = None;
        loop {
            // `ListShards` no admite `stream_name` junto con `next_token`.
            let request = self.client.list_shards();
            let request = match &next_token {
                Some(token) => request.next_token(token),
                None => request.stream_name(&self.stream_name),
            };
            let output = request
                .send()
                .await
                .map_err(|e| SourceError::Failed(DisplayErrorContext(e).to_string().into()))?;
            open.extend(
                output
                    .shards()
                    .iter()
                    // Un shard cerrado (tras un split/merge) ya tiene número
                    // de secuencia final.
                    .filter(|shard| {
                        shard
                            .sequence_number_range()
                            .is_none_or(|range| range.ending_sequence_number().is_none())
                    })
                    .map(|shard| shard.shard_id().to_string()),
            );
            next_token = output.next_token().map(str::to_string);
            if next_token.is_none() {
                return Ok(open);
            }
        }
    }

    async fn latest_iterator(&self, shard_id: &str) -> Result<String, SourceError> {
        let output = self
            .client
            .get_shard_iterator()
            .stream_name(&self.stream_name)
            .shard_id(shard_id)
            .shard_iterator_type(ShardIteratorType::Latest)
            .send()
            .await
            .map_err(|e| SourceError::Failed(DisplayErrorContext(e).to_string().into()))?;
        output
            .shard_iterator
            .ok_or_else(|| SourceError::Failed("Kinesis no devolvió un iterador".into()))
    }

    async fn get_records(&self, iterator: &str) -> Result<RecordsBatch, SourceError> {
        let output = self
            .client
            .get_records()
            .shard_iterator(iterator)
            .limit(GET_RECORDS_LIMIT)
            .send()
            .await
            .map_err(|error| {
                let service_error = error.into_service_error();
                if service_error.is_expired_iterator_exception() {
                    SourceError::IteratorExpired
                } else {
                    failed(service_error)
                }
            })?;
        Ok(RecordsBatch {
            records: output
                .records
                .into_iter()
                .map(|record| record.data.into_inner())
                .collect(),
            next_iterator: output.next_shard_iterator,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use tokio::time::Instant;
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::admin::{AdminAggregator, ManualClock};

    /// Fuente de registros falsa: guion de respuestas de `get_records` y
    /// bitácora de llamadas (con el instante virtual de cada una).
    #[derive(Default)]
    struct FakeSource {
        shards: Mutex<Vec<String>>,
        list_errors: Mutex<usize>,
        script: Mutex<VecDeque<Result<RecordsBatch, SourceError>>>,
        calls: Mutex<Vec<(String, Instant)>>,
        latest_counter: Mutex<u32>,
    }

    impl FakeSource {
        fn with_shards(shards: &[&str]) -> Arc<Self> {
            let source = Self::default();
            *source.shards.lock().unwrap() = shards.iter().map(|s| s.to_string()).collect();
            Arc::new(source)
        }

        fn push(&self, response: Result<RecordsBatch, SourceError>) {
            self.script.lock().unwrap().push_back(response);
        }

        fn names(&self) -> Vec<String> {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .map(|(n, _)| n.clone())
                .collect()
        }

        fn times_of(&self, prefix: &str) -> Vec<Instant> {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|(n, _)| n.starts_with(prefix))
                .map(|(_, at)| *at)
                .collect()
        }

        fn log(&self, name: String) {
            self.calls.lock().unwrap().push((name, Instant::now()));
        }
    }

    #[async_trait::async_trait]
    impl RecordsSource for FakeSource {
        async fn list_open_shards(&self) -> Result<Vec<String>, SourceError> {
            self.log("list".to_string());
            let mut errors = self.list_errors.lock().unwrap();
            if *errors > 0 {
                *errors -= 1;
                return Err(SourceError::Failed("list falló".into()));
            }
            Ok(self.shards.lock().unwrap().clone())
        }

        async fn latest_iterator(&self, shard_id: &str) -> Result<String, SourceError> {
            self.log(format!("latest:{shard_id}"));
            let mut counter = self.latest_counter.lock().unwrap();
            *counter += 1;
            Ok(format!("latest-{counter}"))
        }

        async fn get_records(&self, iterator: &str) -> Result<RecordsBatch, SourceError> {
            self.log(format!("get:{iterator}"));
            self.script.lock().unwrap().pop_front().unwrap_or_else(|| {
                Ok(RecordsBatch {
                    records: vec![],
                    next_iterator: Some(iterator.to_string()),
                })
            })
        }
    }

    fn batch(records: Vec<Vec<u8>>, next: &str) -> Result<RecordsBatch, SourceError> {
        Ok(RecordsBatch {
            records,
            next_iterator: Some(next.to_string()),
        })
    }

    fn login_record(n: u64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "event_id": format!("00000000-0000-4000-8000-{n:012}"),
            "event_type": "auth.login",
            "occurred_at": "2026-11-10T12:00:00Z",
            "source": "gateway",
            "actor_sub": format!("user-{n}"),
            "payload": {}
        }))
        .unwrap()
    }

    struct Harness {
        source: Arc<FakeSource>,
        aggregator: Arc<AdminAggregator>,
        shutdown: CancellationToken,
        task: tokio::task::JoinHandle<()>,
    }

    fn start(source: Arc<FakeSource>) -> Harness {
        let aggregator = Arc::new(AdminAggregator::new(Arc::new(ManualClock::new(
            1_800_000_000_000,
        ))));
        let shutdown = CancellationToken::new();
        let consumer = SecurityEventConsumer::new(source.clone(), aggregator.clone());
        let task = tokio::spawn(consumer.run(shutdown.clone()));
        Harness {
            source,
            aggregator,
            shutdown,
            task,
        }
    }

    /// Deja correr el tiempo virtual `secs` segundos (el reloj está pausado y
    /// avanza solo cuando todas las tareas están inactivas).
    async fn run_for(secs: u64) {
        tokio::time::sleep(Duration::from_secs(secs)).await;
    }

    #[tokio::test(start_paused = true)]
    async fn starts_at_latest_follows_the_next_iterator_and_feeds_the_aggregator() {
        let source = FakeSource::with_shards(&["shard-1"]);
        source.push(batch(vec![login_record(1), login_record(2)], "it-2"));
        let h = start(source);

        run_for(3).await;

        let names = h.source.names();
        assert_eq!(
            &names[..4],
            ["list", "latest:shard-1", "get:latest-1", "get:it-2"]
        );
        let snapshot = h.aggregator.snapshot();
        assert_eq!(snapshot.kpis.active_users, 2);
        assert_eq!(snapshot.recent_events.len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn polls_about_once_per_second() {
        let h = start(FakeSource::with_shards(&["shard-1"]));

        run_for(5).await;

        let polls = h.source.times_of("get:");
        assert!((5..=6).contains(&polls.len()), "sondeos: {}", polls.len());
        for pair in polls.windows(2) {
            assert_eq!(pair[1] - pair[0], POLL_INTERVAL);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn malformed_and_out_of_contract_records_are_skipped_and_counted() {
        let source = FakeSource::with_shards(&["shard-1"]);
        let mut extra_property: serde_json::Value =
            serde_json::from_slice(&login_record(9)).unwrap();
        extra_property["leak"] = serde_json::json!("x");
        source.push(batch(
            vec![
                b"not json at all".to_vec(),
                serde_json::to_vec(&extra_property).unwrap(),
                login_record(1),
                b"{}".to_vec(),
            ],
            "it-2",
        ));
        let h = start(source);

        run_for(2).await;

        let snapshot = h.aggregator.snapshot();
        assert_eq!(snapshot.kpis.malformed_records, 3);
        assert_eq!(
            snapshot.recent_events.len(),
            1,
            "solo el registro válido se agrega"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_expired_iterator_reacquires_latest() {
        let source = FakeSource::with_shards(&["shard-1"]);
        source.push(Err(SourceError::IteratorExpired));
        source.push(batch(vec![login_record(1)], "it-after"));
        let h = start(source);

        run_for(3).await;

        let names = h.source.names();
        assert_eq!(
            &names[..5],
            [
                "list",
                "latest:shard-1",
                "get:latest-1",
                "latest:shard-1",
                "get:latest-2"
            ]
        );
        assert!(names.contains(&"get:it-after".to_string()));
        assert_eq!(h.aggregator.snapshot().recent_events.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn errors_back_off_exponentially_and_reset_after_a_success() {
        let source = FakeSource::with_shards(&["shard-1"]);
        for _ in 0..4 {
            source.push(Err(SourceError::Failed("boom".into())));
        }
        source.push(batch(vec![], "it-ok"));
        source.push(Err(SourceError::Failed("boom".into())));
        let h = start(source);

        run_for(40).await;

        let polls = h.source.times_of("get:");
        let gaps: Vec<u64> = polls.windows(2).map(|p| (p[1] - p[0]).as_secs()).collect();
        // 4 errores seguidos: 1 s, 2 s, 4 s, 8 s; tras el éxito, la espera
        // normal de sondeo (1 s); el error siguiente vuelve a esperar 1 s.
        assert_eq!(&gaps[..7], [1, 2, 4, 8, 1, 1, 1]);
    }

    #[test]
    fn backoff_caps_at_thirty_seconds() {
        let mut d = BACKOFF_INITIAL;
        for _ in 0..10 {
            d = next_backoff(d);
        }
        assert_eq!(d, BACKOFF_MAX);
    }

    #[tokio::test(start_paused = true)]
    async fn a_closed_shard_stops_its_worker_and_is_picked_up_again_on_refresh() {
        let source = FakeSource::with_shards(&["shard-1"]);
        source.push(Ok(RecordsBatch {
            records: vec![login_record(1)],
            next_iterator: None,
        }));
        let h = start(source);

        run_for(SHARD_REFRESH.as_secs() + 5).await;

        let latest = h
            .source
            .names()
            .iter()
            .filter(|n| n.starts_with("latest:"))
            .count();
        assert_eq!(
            latest, 2,
            "tras cerrarse, el refresco vuelve a tomar LATEST"
        );
        assert_eq!(h.aggregator.snapshot().recent_events.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn shards_discovered_on_refresh_get_their_own_worker() {
        let source = FakeSource::with_shards(&["shard-1"]);
        let h = start(source);
        run_for(2).await;
        h.source.shards.lock().unwrap().push("shard-2".to_string());

        run_for(SHARD_REFRESH.as_secs() + 2).await;

        let names = h.source.names();
        assert_eq!(names.iter().filter(|n| *n == "latest:shard-1").count(), 1);
        assert_eq!(names.iter().filter(|n| *n == "latest:shard-2").count(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_failing_shard_listing_is_retried_with_backoff() {
        let source = FakeSource::with_shards(&["shard-1"]);
        *source.list_errors.lock().unwrap() = 2;
        let h = start(source);

        run_for(10).await;

        let lists = h.source.times_of("list");
        assert_eq!((lists[1] - lists[0]).as_secs(), 1);
        assert_eq!((lists[2] - lists[1]).as_secs(), 2);
        assert!(h.source.names().contains(&"latest:shard-1".to_string()));
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_stops_the_consumer_and_its_workers_promptly() {
        let h = start(FakeSource::with_shards(&["shard-1", "shard-2"]));
        run_for(2).await;

        h.shutdown.cancel();

        tokio::time::timeout(Duration::from_secs(1), h.task)
            .await
            .expect("debe terminar sin esperar al sondeo")
            .expect("sin panic");
    }
}
