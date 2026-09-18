# CHECKPOINTS — Evaluación del estado final

> En sistemas multi-agente no se evalúa el camino, se evalúa el destino.
> Estos son los checkpoints objetivos que un juez (humano o IA) puede usar
> para decidir si el proyecto está sano.

## C1 — El arnés está completo

- [ ] Existen los 4 archivos base: `AGENTS.md`, `init.sh`, `feature_list.json`,
      `progress/current.md`.
- [ ] Existen los 4 docs: `docs/architecture.md`, `docs/conventions.md`,
      `docs/verification.md`, `docs/security-scope.md`.
- [ ] `./init.sh` termina con exit code 0.

## C2 — El estado es coherente

- [ ] Como mucho una feature en `in_progress` en `feature_list.json`.
- [ ] Toda feature `done` tiene tests asociados que pasan.
- [ ] `progress/current.md` está vacío o describe la sesión activa
      (no contiene basura de sesiones anteriores).

## C3 — El código respeta la arquitectura

- [ ] `src/` solo contiene los módulos previstos en `docs/architecture.md`
      (`config`, `domain`, `auth`, `usuarios_client`, `broker`, `realtime`,
      `api`, `wiring`).
- [ ] Toda dependencia en `Cargo.toml` está justificada por una feature de
      `feature_list.json` o por `docs/architecture.md`.
- [ ] No hay `println!`/`dbg!` sueltos para debug, ni `unwrap()`/`panic!()`
      fuera de tests sin justificar, ni TODOs sin contexto.
- [ ] `cargo doc --no-deps` genera sin warnings (todo ítem público tiene
      rustdoc).
- [ ] Ninguna feature inventó el shape de una API pendiente (ver
      `docs/architecture.md` §"Dependencia pendiente") en vez de
      documentar el bloqueo/error explícito.

## C4 — La verificación es real

- [ ] `tests/` tiene al menos un test de integración por módulo que cruza
      IO (`auth`, `usuarios_client`, `broker`, `api`).
- [ ] Los tests de `broker` corren contra un contenedor RabbitMQ real vía
      `testcontainers`, con la topología copiada de
      `broker/rabbitmq/definitions.json`, nunca contra el Broker de
      producción ni con un mock del protocolo AMQP.
- [ ] `cargo test` muestra > 0 tests y todos verdes.
- [ ] `cargo clippy --all-targets -- -D warnings` no muestra advertencias.

## C5 — La sesión se cerró bien

- [ ] No hay archivos sin trackear sospechosos (`*.tmp`, `target/` fuera del
      `.gitignore`).
- [ ] `progress/history.md` tiene una entrada por la última sesión.
- [ ] La última feature trabajada está reflejada en su estado correcto.

---

**Cómo usar este archivo:** un agente revisor (`.claude/agents/reviewer.md`)
recorre cada checkbox, marca `[x]` o `[ ]`, y rechaza el cierre de sesión
si quedan boxes vacíos en C1-C5.
