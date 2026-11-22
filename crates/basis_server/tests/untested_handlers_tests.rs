//! Coverage for the HTTP handlers that no existing test exercised.
//!
//! Verified by grep that neither the handler names nor the route paths appeared in any test
//! file before this one:
//!
//! | Route | Handler |
//! |---|---|
//! | `GET /tracker/proof` | `get_tracker_proof` |
//! | `GET /reserve/proof` | `get_reserve_proof` |
//! | `POST /redemption/submit` | `submit_redemption` |
//! | `GET /config/reserve-token` | `get_reserve_token_config` |
//! | `GET /config/reserve-contract-p2s` | `get_basis_reserve_contract_p2s` |
//! | `GET /tracker/latest-box-id` | `get_latest_tracker_box_id` |
//! | `POST /reserves/create` | `create_reserve_payload` |
//!
//! (`POST /reserves/submit` was removed in PR #16 B4: it forwarded the payload to the
//! tracker's node, so the tracker's wallet funded arbitrary reserves. The owner now submits
//! the `/reserves/create` payload to their own node.)
//!
//! `POST /redemption/submit` is bound to server-side build state (PR #16 B6): the echoed
//! `unsigned_tx` must hash to a live, single-use pending entry recorded by
//! `/redemption/build`, the signed transaction must spend the entry's reserve box, and the
//! tracker state advance uses the STORED entry values — caller-supplied amounts on the wire
//! are ignored.

mod untested_handlers {
    use axum::http::StatusCode;
    use basis_server::{
        api::{
            create_reserve_payload, get_basis_reserve_contract_p2s, get_latest_tracker_box_id,
            get_reserve_proof, get_reserve_token_config, get_tracker_proof,
        },
        models::CreateReserveRequest,
        redemption_build::submit_redemption,
        AppState, TrackerCommand,
    };
    use basis_store::{schnorr::generate_keypair, IouNote};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    /// Fjall keyspace creation can race when several databases open concurrently in one
    /// process, so serialise storage initialisation.
    static STORAGE_INIT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    const ISSUER_HEX: &str = "010101010101010101010101010101010101010101010101010101010101010101";
    const RECIPIENT_HEX: &str =
        "020202020202020202020202020202020202020202020202020202020202020202";

    /// Mock state whose tracker thread understands the commands these handlers issue.
    async fn mock_state() -> AppState {
        mock_state_with_config("http://localhost:9053").await
    }

    async fn mock_state_with_config(node_url: &str) -> AppState {
        let (tx, mut rx) = mpsc::channel(100);
        let event_store = Arc::new(basis_server::store::EventStore::new().await.unwrap());

        let temp_dir = tempfile::tempdir().unwrap();
        let data_dir = temp_dir.path();

        let scanner_config = basis_store::ergo_scanner::NodeConfig {
            node_url: node_url.to_string(),
            ..Default::default()
        };
        let ergo_scanner = Arc::new(tokio::sync::Mutex::new(
            basis_store::ergo_scanner::ServerState::new(scanner_config, data_dir).unwrap(),
        ));
        let reserve_tracker = Arc::new(tokio::sync::Mutex::new(basis_store::ReserveTracker::new()));

        tokio::task::spawn_blocking(move || {
            use basis_store::{RedemptionManager, TrackerStateManager};

            let tracker = TrackerStateManager::new_with_temp_storage();
            let mut redemption_manager = RedemptionManager::new(tracker);

            while let Some(cmd) = rx.blocking_recv() {
                match cmd {
                    TrackerCommand::AddNote {
                        issuer_pubkey,
                        note,
                        response_tx,
                    } => {
                        let r = redemption_manager.tracker.add_note(&issuer_pubkey, &note);
                        let _ = response_tx.send(r);
                    }
                    TrackerCommand::GetNoteByIssuerAndRecipient {
                        issuer_pubkey,
                        recipient_pubkey,
                        denomination,
                        response_tx,
                    } => {
                        let r = redemption_manager.tracker.get_note_optional(
                            &issuer_pubkey,
                            &recipient_pubkey,
                            &denomination,
                        );
                        let _ = response_tx.send(r);
                    }
                    TrackerCommand::CompleteRedemption {
                        issuer_pubkey,
                        recipient_pubkey,
                        redeemed_amount,
                        new_already_redeemed,
                        denomination,
                        response_tx,
                    } => {
                        let r = redemption_manager.complete_redemption(
                            &issuer_pubkey,
                            &recipient_pubkey,
                            &basis_store::DenomKey::Erg,
                            redeemed_amount,
                            new_already_redeemed,
                        );
                        let _ = response_tx.send(r);
                    }
                    other => {
                        // Commands these tests do not exercise.
                        let _ = other;
                    }
                }
            }
        });

        let config = Arc::new(basis_server::config::AppConfig {
            server: basis_server::config::ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 3048,
                data_dir: Some(data_dir.to_string_lossy().to_string()),
                database_url: Some("sqlite::memory:".to_string()),
                tls_cert_path: None,
                tls_key_path: None,
                auth: basis_server::config::AuthConfig::default(),
                reserve_creation_max_erg_nano: 10_000_000_000,
                reserve_creation_max_token_amount: 1_000_000_000,
                redemption_build_max_per_pair_per_hour: 60,
                redemption_build_max_per_recipient_per_hour: 30,
                notes_require_reserve: false,
                notes_max_recipients_per_issuer: 50,
                notes_max_updates_per_issuer_per_hour: 120,
                notes_max_new_edges_per_hour: 1000,
                notes_max_new_edges_per_issuer_per_hour: 10,
                redemption_build_max_per_issuer_per_hour: 6,
                redemption_build_max_per_hour: 30,
            },
            ergo: basis_server::config::ErgoConfig {
                scanner: basis_store::ergo_scanner::NodeConfig {
                    node_url: node_url.to_string(),
                    ..Default::default()
                },
                wallet: Default::default(),
                basis_reserve_contract_p2s: "9testReserveP2SAddress".to_string(),
                basis_token_reserve_contract_p2s: "9testTokenReserveP2S".to_string(),
                tracker_nft_id: Some(
                    "1af23d4e5f6a7b8c9daebfc0d1e2f30415263748596a7b8c9daebfc0d1e2f304".to_string(),
                ),
                reserve_tokens: Default::default(),
                tracker_public_key: Some(
                    "9fRusAarL1KkrWQVsxSRVYnvWxaAT2A96cKtNn9tvPh5XUyCisr33".to_string(),
                ),
                tracker_secret_key: None,
            },
            transaction: basis_server::config::TransactionConfig {
                fee: 1_000_000,
                change_address: None,
                heartbeat_blocks: 720,
                commit_reserve_nano: 100_000_000,
            },
            acceptance: basis_server::acceptance::config::AcceptanceConfig::empty(),
            redemption: basis_server::config::RedemptionConfig {
                enforce_acceptance_policy: true,
            },
            confirmation: basis_server::config::ConfirmationConfig::default(),
        });

        let storage_dir = std::env::temp_dir().join(format!(
            "basis_untested_handlers_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&storage_dir).expect("create temp dir");

        let (tracker_storage, policy_storage) = {
            let _guard = STORAGE_INIT_LOCK.lock().unwrap();
            let ts = basis_store::persistence::TrackerStorage::open(&storage_dir)
                .expect("tracker storage");
            let ps = basis_store::persistence::AcceptancePolicyStorage::open(
                storage_dir.join("policies"),
            )
            .expect("policy storage");
            (ts, ps)
        };

        AppState {
            tx,
            event_store,
            ergo_scanner,
            reserve_tracker,
            config,
            shared_tracker_state: Arc::new(tokio::sync::Mutex::new(
                basis_server::tracker_box_updater::SharedTrackerState::new(),
            )),
            tracker_storage,
            acceptance_predicate: None,
            policy_storage,
            pending_redemptions: std::sync::Arc::new(
                basis_server::redemption_build::PendingRedemptionRegistry::new(),
            ),
            redemption_build_rate: std::sync::Arc::new(
                basis_server::redemption_build::BuildRateLimiter::new(),
            ),
            note_limits: std::sync::Arc::new(basis_server::note_limits::NoteLimiter::new()),
        }
    }

    fn params(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    // ========================================================================
    // GET /config/reserve-token
    // ========================================================================

    #[tokio::test]
    async fn test_get_reserve_token_config_returns_erg_backed_defaults() {
        let state = mock_state().await;

        let (status, body) = get_reserve_token_config(axum::extract::State(state)).await;

        assert_eq!(status, StatusCode::OK);
        assert!(body.success);
        assert!(
            body.data.is_some(),
            "a successful config response must carry a payload"
        );
        let data = body.data.clone().unwrap();
        assert_eq!(
            data.basis_token_reserve_contract_p2s, "9testTokenReserveP2S",
            "the configured token-reserve P2S must be surfaced verbatim"
        );
    }

    // ========================================================================
    // GET /config/reserve-contract-p2s
    // ========================================================================

    #[tokio::test]
    async fn test_get_basis_reserve_contract_p2s_comes_from_the_running_config() {
        // Round 4 (C10): the handler used to re-read AppConfig from disk, so its answer depended
        // on the working directory and could differ from the config the server runs with. It
        // now answers from the injected AppState.
        let state = mock_state().await;

        let (status, body) = get_basis_reserve_contract_p2s(axum::extract::State(state)).await;

        assert_eq!(status, StatusCode::OK, "{body:?}");
        assert_eq!(body.data.as_deref(), Some("9testReserveP2SAddress"));
    }

    // ========================================================================
    // GET /tracker/latest-box-id
    // ========================================================================

    #[tokio::test]
    async fn test_get_latest_tracker_box_id_returns_404_before_first_update() {
        let state = mock_state().await;

        let (status, body) = get_latest_tracker_box_id(axum::extract::State(state)).await;

        // Before the background updater has observed a confirmed tracker box there is nothing
        // to report, and 404 is the correct answer. Returning 200 with an empty or invented id
        // would be worse: clients use this to locate the tracker data-input box.
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "no tracker box observed yet, body: {:?}",
            body
        );
        assert!(!body.success);
        assert!(body.error.is_some());
    }

    #[tokio::test]
    async fn test_get_latest_tracker_box_id_reflects_shared_state() {
        // With a box id present in shared state the handler must report exactly that id.
        let state = mock_state().await;
        {
            let shared = state.shared_tracker_state.lock().await;
            shared.set_tracker_box_id("box_from_updater_123".to_string());
        }

        let (status, body) = get_latest_tracker_box_id(axum::extract::State(state)).await;

        assert_eq!(status, StatusCode::OK, "body: {:?}", body);
        assert!(body.success);
        let data = body
            .data
            .as_ref()
            .expect("latest-box-id response should carry data");
        assert_eq!(
            data.tracker_box_id, "box_from_updater_123",
            "the handler must surface the box id recorded by the updater"
        );
    }

    // ========================================================================
    // GET /tracker/proof
    // ========================================================================

    #[tokio::test]
    async fn test_get_tracker_proof_missing_params_is_bad_request() {
        let state = mock_state().await;

        let (status, body) = get_tracker_proof(
            axum::extract::State(state),
            axum::extract::Query(params(&[])),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(!body.success);
        assert!(body.error.is_some());
    }

    #[tokio::test]
    async fn test_get_tracker_proof_invalid_hex_is_bad_request() {
        let state = mock_state().await;

        let (status, body) = get_tracker_proof(
            axum::extract::State(state),
            axum::extract::Query(params(&[
                ("issuer_pubkey", "not-hex"),
                ("recipient_pubkey", RECIPIENT_HEX),
            ])),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {:?}", body);
        assert!(!body.success);
    }

    #[tokio::test]
    async fn test_get_tracker_proof_unknown_note_is_not_ok() {
        let state = mock_state().await;

        let (status, body) = get_tracker_proof(
            axum::extract::State(state),
            axum::extract::Query(params(&[
                ("issuer_pubkey", ISSUER_HEX),
                ("recipient_pubkey", RECIPIENT_HEX),
            ])),
        )
        .await;

        assert_ne!(
            status,
            StatusCode::OK,
            "a proof for a note that was never added must not succeed"
        );
        assert!(!body.success);
    }

    // ========================================================================
    // GET /reserve/proof
    // ========================================================================

    #[tokio::test]
    async fn test_get_reserve_proof_missing_params_is_bad_request() {
        let state = mock_state().await;

        let (status, body) = get_reserve_proof(
            axum::extract::State(state),
            axum::extract::Query(params(&[])),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(!body.success);
    }

    #[tokio::test]
    async fn test_get_reserve_proof_invalid_hex_is_bad_request() {
        let state = mock_state().await;

        let (status, body) = get_reserve_proof(
            axum::extract::State(state),
            axum::extract::Query(params(&[("issuer_pubkey", "zzz")])),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {:?}", body);
        assert!(!body.success);
    }

    #[tokio::test]
    async fn test_get_reserve_proof_unknown_reserve_is_not_ok() {
        let state = mock_state().await;

        let (status, body) = get_reserve_proof(
            axum::extract::State(state),
            axum::extract::Query(params(&[
                ("issuer_pubkey", ISSUER_HEX),
                ("recipient_pubkey", RECIPIENT_HEX),
                ("amount", "1000"),
                ("timestamp", "1700000000000"),
            ])),
        )
        .await;

        assert_ne!(
            status,
            StatusCode::OK,
            "a reserve proof for an unknown reserve must not succeed"
        );
        assert!(!body.success);
    }

    // ========================================================================
    // POST /reserves/create
    // ========================================================================

    #[tokio::test]
    async fn test_create_reserve_payload_rejects_invalid_owner_hex() {
        let state = mock_state().await;

        let (status, body) = create_reserve_payload(
            axum::extract::State(state),
            axum::extract::Json(CreateReserveRequest {
                owner_pubkey: "not-hex".to_string(),
                nft_id: "abc".to_string(),
                erg_amount: 1_000_000,
                token_amount: 0,
                token_id: String::new(),
            }),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {:?}", body);
        assert!(!body.success);
        assert!(body.error.is_some());
    }

    #[tokio::test]
    async fn test_create_reserve_payload_rejects_wrong_length_owner_key() {
        let state = mock_state().await;

        // 32 bytes, not 33.
        let short = "01".repeat(32);
        let (status, body) = create_reserve_payload(
            axum::extract::State(state),
            axum::extract::Json(CreateReserveRequest {
                owner_pubkey: short,
                nft_id: "abc".to_string(),
                erg_amount: 1_000_000,
                token_amount: 0,
                token_id: String::new(),
            }),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {:?}", body);
        assert!(!body.success);
    }

    // ========================================================================
    // POST /redemption/submit
    //
    // Since PR #16 B6 the submit endpoint is bound to server-side state recorded by
    // /redemption/build: the echoed `unsigned_tx` must hash to a live, single-use pending
    // entry, the signed transaction must be the built transaction (same tx id), and the
    // tracker state advance uses the STORED entry values. These tests pin that behaviour.
    // ========================================================================

    /// Reserve box id the pending entries below are recorded against.
    const RESERVE_BOX_ID: &str = "abcd0123abcd0123abcd0123abcd0123abcd0123abcd0123abcd0123abcd0123";

    /// Node stub that accepts any broadcast and answers with another transaction's id.
    async fn spawn_accepting_node() -> String {
        spawn_node(|_| (200, format!("{{\"id\":\"{}\"}}", "ab".repeat(32)))).await
    }

    /// Node stub on 127.0.0.1 that answers each request with `answer(request line)`
    /// (`(status, body)`, the body sent as JSON).
    async fn spawn_node(answer: impl Fn(&str) -> (u16, String) + Send + Sync + 'static) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock node");
        let addr = listener.local_addr().unwrap();
        let answer = Arc::new(answer);
        tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let answer = answer.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 8192];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    let request = String::from_utf8_lossy(&buf[..n]);
                    let line = request.lines().next().unwrap_or_default().to_string();
                    let (status, body) = answer(&line);
                    let response = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        });
        format!("http://{}", addr)
    }

    /// An unsigned transaction spending `box_id` whose first output carries the R5 digest the
    /// pending entries below are recorded with (`0x11` x 33), plus the same transaction with
    /// empty proofs standing in for the client's signed copy.
    fn tx_pair(box_id: &str) -> (serde_json::Value, serde_json::Value) {
        use ergo_lib::chain::transaction::unsigned::UnsignedTransaction;
        use ergo_lib::chain::transaction::Transaction;
        use ergo_lib::ergotree_interpreter::sigma_protocol::prover::ProofBytes;
        let unsigned_tx = serde_json::json!({
            "inputs": [{ "boxId": box_id, "extension": {} }],
            "dataInputs": [],
            "outputs": [{
                "value": 1_000_000_000u64,
                "ergoTree": "0008cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                "assets": [],
                "additionalRegisters": {
                    "R4": "070279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                    "R5": format!("64{}032000", "11".repeat(33))
                },
                "creationHeight": 1_000
            }]
        });
        let unsigned: UnsignedTransaction =
            serde_json::from_value(unsigned_tx.clone()).expect("valid unsigned tx");
        let signed =
            Transaction::from_unsigned_tx(unsigned, vec![ProofBytes::Empty]).expect("signed tx");
        (unsigned_tx, serde_json::to_value(&signed).unwrap())
    }

    /// Record a pending redemption entry the way `POST /redemption/build` would, returning
    /// the unsigned transaction JSON whose fingerprint keys the entry and its signed copy.
    fn record_pending(
        state: &basis_server::AppState,
        issuer_pubkey: &str,
        recipient_pubkey: &str,
        redeemed_amount: u64,
    ) -> (serde_json::Value, serde_json::Value) {
        use basis_server::redemption_build::{
            unsigned_tx_fingerprint, unsigned_tx_id, PendingRedemption,
        };
        let (unsigned_tx, signed_tx) = tx_pair(RESERVE_BOX_ID);
        let entry = PendingRedemption::new(
            unsigned_tx_id(&unsigned_tx).expect("tx id"),
            RESERVE_BOX_ID.to_string(),
            issuer_pubkey.to_string(),
            recipient_pubkey.to_string(),
            redeemed_amount,
            redeemed_amount,
            vec![0x11; 33],
            basis_store::DenomKey::Erg,
        );
        let fingerprint = unsigned_tx_fingerprint(&unsigned_tx).expect("fingerprint");
        assert!(
            state.pending_redemptions.record(fingerprint, entry),
            "pending entry should be recorded"
        );
        (unsigned_tx, signed_tx)
    }

    fn submit_request(
        unsigned_tx: serde_json::Value,
        signed_tx: serde_json::Value,
    ) -> basis_server::redemption_build::RedemptionSubmitRequest {
        basis_server::redemption_build::RedemptionSubmitRequest {
            signed_tx,
            unsigned_tx,
            issuer_pubkey: ISSUER_HEX.to_string(),
            recipient_pubkey: RECIPIENT_HEX.to_string(),
            redeemed_amount: 1_000,
            new_already_redeemed: 1_000,
        }
    }

    #[tokio::test]
    async fn test_submit_redemption_rejects_unknown_unsigned_tx() {
        let state = mock_state().await;

        // No /redemption/build ever happened, so there is no pending entry for this tx.
        let req = submit_request(
            serde_json::json!({ "inputs": [], "outputs": [] }),
            tx_pair(RESERVE_BOX_ID).1,
        );
        let (status, body) =
            submit_redemption(axum::extract::State(state), axum::extract::Json(req)).await;

        assert_eq!(status, StatusCode::CONFLICT, "body: {:?}", body);
        assert!(!body.success);
    }

    #[tokio::test]
    async fn test_submit_redemption_rejects_signed_tx_spending_a_different_box() {
        let node_url = spawn_accepting_node().await;
        let state = mock_state_with_config(&node_url).await;

        let (unsigned_tx, _) = record_pending(&state, ISSUER_HEX, RECIPIENT_HEX, 1_000);
        // The signed transaction spends a box the build never selected.
        let other_box = "ef".repeat(32);
        let req = submit_request(unsigned_tx, tx_pair(&other_box).1);
        let (status, body) =
            submit_redemption(axum::extract::State(state), axum::extract::Json(req)).await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {:?}", body);
        assert!(!body.success);
    }

    #[tokio::test]
    async fn test_submit_redemption_advances_state_from_stored_entry() {
        // The wire issuer/recipient/amounts are DEPRECATED and ignored: state must advance by
        // the values recorded at build time. Proven by sending wildly different wire amounts.
        let node_url = spawn_accepting_node().await;
        let state = mock_state_with_config(&node_url).await;

        let (secret, issuer) = generate_keypair();
        let (_, recipient) = generate_keypair();
        let note = IouNote::create_and_sign(
            recipient,
            10_000,
            1_700_000_000_000,
            &secret,
            &[0x42; 32],
            basis_store::DenomKey::Erg,
        )
        .unwrap();
        state
            .tx
            .send(TrackerCommand::AddNote {
                issuer_pubkey: issuer,
                note,
                response_tx: tokio::sync::oneshot::channel().0,
            })
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let (unsigned_tx, signed_tx) =
            record_pending(&state, &hex::encode(issuer), &hex::encode(recipient), 1_000);

        let mut req = submit_request(unsigned_tx, signed_tx);
        // Deliberately wrong wire values: the stored entry (redeemed_amount = 1_000) must win.
        req.redeemed_amount = 20_000;
        req.new_already_redeemed = 999_999;

        let (status, body) = submit_redemption(
            axum::extract::State(state.clone()),
            axum::extract::Json(req),
        )
        .await;

        assert_eq!(status, StatusCode::OK, "body: {:?}", body);
        assert!(body.success, "error: {:?}", body.error);

        // Round 5 (C8): the submit journals the stored values and applies nothing; the note
        // changes once the redemption confirmer finds the transaction in a block.
        let journaled = state.tracker_storage.journaled_redemptions().unwrap();
        assert_eq!(journaled.len(), 1);
        assert_eq!(journaled[0].tx_id, body.data.as_ref().unwrap().tx_id);
        assert_eq!(
            (journaled[0].redeemed_amount, journaled[0].new_already_redeemed),
            (1_000, 1_000),
            "the stored entry's amounts, not the wire values"
        );
        assert_eq!(note_redeemed(&state, issuer, recipient).await, 0);
        let shared = state.shared_tracker_state.lock().await.clone();
        assert_eq!(shared.get_submitted_redemptions().len(), 1);

        basis_server::redemption_confirmer::apply_journaled(
            &state.tracker_storage,
            &shared,
            &state.tx,
            &journaled[0],
        )
        .await
        .unwrap();
        assert!(state.tracker_storage.journaled_redemptions().unwrap().is_empty());
        assert!(shared.get_submitted_redemptions().is_empty());
        assert_eq!(
            note_redeemed(&state, issuer, recipient).await,
            1_000,
            "state must advance by the stored entry amount, not the wire value"
        );
    }

    /// Round 5b (F2): the redemption is journaled, followed and reported under the signed
    /// transaction's id whatever id the node's answer names: another id, an empty answer, or
    /// garbage longer than a storage key can be.
    #[tokio::test]
    async fn test_submit_redemption_keeps_the_signed_id_whatever_the_node_answers() {
        for answer in [
            format!("\"{}\"", "ab".repeat(32)),
            String::new(),
            "x".repeat(70_000),
        ] {
            let reply = answer.clone();
            let node_url = spawn_node(move |_| (200, reply.clone())).await;
            let state = mock_state_with_config(&node_url).await;
            let (unsigned_tx, signed_tx) =
                record_pending(&state, ISSUER_HEX, RECIPIENT_HEX, 1_000);
            let built = basis_server::redemption_build::unsigned_tx_id(&unsigned_tx).unwrap();
            let (status, body) = submit_redemption(
                axum::extract::State(state.clone()),
                axum::extract::Json(submit_request(unsigned_tx, signed_tx)),
            )
            .await;
            let shown: String = answer.chars().take(20).collect();
            assert_eq!(status, StatusCode::OK, "{shown}: {body:?}");
            assert_eq!(body.data.as_ref().unwrap().tx_id, built, "{shown}");
            let journaled = state.tracker_storage.journaled_redemptions().unwrap();
            assert_eq!(journaled.len(), 1, "{shown}");
            assert_eq!(journaled[0].tx_id, built, "{shown}");
            let submitted = state
                .shared_tracker_state
                .lock()
                .await
                .get_submitted_redemptions();
            assert_eq!(submitted.len(), 1, "{shown}");
            assert_eq!(submitted[0].tx_id, built, "{shown}");
        }
    }

    async fn note_redeemed(
        state: &basis_server::AppState,
        issuer: basis_store::PubKey,
        recipient: basis_store::PubKey,
    ) -> u64 {
        let (tx, rx) = tokio::sync::oneshot::channel();
        state
            .tx
            .send(TrackerCommand::GetNoteByIssuerAndRecipient {
                denomination: basis_store::DenomKey::Erg,
                issuer_pubkey: issuer,
                recipient_pubkey: recipient,
                response_tx: tx,
            })
            .await
            .unwrap();
        rx.await
            .expect("tracker should answer the note lookup")
            .expect("note lookup should succeed")
            .expect("note should exist")
            .amount_redeemed
    }

    /// Round 5 (C8): a broadcast whose answer is lost (the node may have the transaction)
    /// keeps the redemption journaled, so the confirmer follows it, and says so.
    #[tokio::test]
    async fn test_submit_redemption_without_an_answer_stays_journaled() {
        // Accepts the request, then closes the connection without answering.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let node_url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                use tokio::io::AsyncReadExt;
                let mut buf = vec![0u8; 8192];
                let _ = socket.read(&mut buf).await;
                drop(socket);
            }
        });
        let state = mock_state_with_config(&node_url).await;
        let (unsigned_tx, signed_tx) = record_pending(&state, ISSUER_HEX, RECIPIENT_HEX, 1_000);
        let req = submit_request(unsigned_tx, signed_tx);
        let (status, body) = submit_redemption(
            axum::extract::State(state.clone()),
            axum::extract::Json(req),
        )
        .await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "body: {:?}", body);
        let msg = body.error.clone().unwrap_or_default();
        assert!(msg.contains("did not answer"), "{msg}");
        assert!(!msg.contains("127.0.0.1"), "{msg}");
        assert_eq!(state.tracker_storage.journaled_redemptions().unwrap().len(), 1);
        assert_eq!(
            state
                .shared_tracker_state
                .lock()
                .await
                .get_submitted_redemptions()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn test_submit_redemption_entry_is_single_use() {
        let node_url = spawn_accepting_node().await;
        let state = mock_state_with_config(&node_url).await;

        let (unsigned_tx, signed_tx) = record_pending(&state, ISSUER_HEX, RECIPIENT_HEX, 1_000);
        let req = submit_request(unsigned_tx, signed_tx);

        let (first_status, first_body) = submit_redemption(
            axum::extract::State(state.clone()),
            axum::extract::Json(req.clone()),
        )
        .await;
        assert_eq!(first_status, StatusCode::OK, "body: {:?}", first_body);

        let (second_status, second_body) =
            submit_redemption(axum::extract::State(state), axum::extract::Json(req)).await;
        assert_eq!(
            second_status,
            StatusCode::CONFLICT,
            "a replayed unsigned_tx must be refused: body: {:?}",
            second_body
        );
    }

    /// Round 5b (F7): a node that cannot be reached may still get the transaction from the
    /// client, so the redemption stays journaled and the client is told so.
    #[tokio::test]
    async fn test_submit_redemption_unreachable_node_keeps_it_journaled() {
        // Port 1 is reserved and refuses connections.
        let state = mock_state_with_config("http://127.0.0.1:1").await;

        let (unsigned_tx, signed_tx) = record_pending(&state, ISSUER_HEX, RECIPIENT_HEX, 1_000);
        let req = submit_request(unsigned_tx, signed_tx);
        let (status, body) = submit_redemption(
            axum::extract::State(state.clone()),
            axum::extract::Json(req),
        )
        .await;

        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "body: {:?}",
            body
        );
        assert_eq!(state.tracker_storage.journaled_redemptions().unwrap().len(), 1);
        assert!(!body.success);
        let msg = body.error.clone().unwrap_or_default();
        assert!(msg.contains("did not answer"), "got: {}", msg);
        // Round 4 (C2): the node's URL and answer are logged, never returned.
        assert!(
            !msg.contains("127.0.0.1") && !msg.contains("http"),
            "the client error must not carry the node URL, got: {}",
            msg
        );
    }

    /// Round 5b (F7): only a definite refusal forgets the redemption: a 4xx from a node whose
    /// pool does not have it, while its reserve box is unspent. A 5xx says nothing; a refusal
    /// that says the pool has it already, or from a node whose pool has it, means the node took
    /// it; a refusal while the reserve box is spent may mean it is in a block already.
    #[tokio::test]
    async fn test_submit_redemption_forgets_only_a_definite_refusal() {
        struct Case {
            name: &'static str,
            broadcast: (u16, &'static str),
            in_pool: bool,
            reserve_unspent: bool,
            status: StatusCode,
            journaled: usize,
            says: &'static str,
        }
        let malformed = r#"{"error":400,"reason":"bad.request","detail":"Malformed transaction"}"#;
        let cases = [
            Case {
                name: "a definite refusal",
                broadcast: (400, malformed),
                in_pool: false,
                reserve_unspent: true,
                status: StatusCode::INTERNAL_SERVER_ERROR,
                journaled: 0,
                says: "did not accept",
            },
            Case {
                name: "a 5xx",
                broadcast: (503, "{}"),
                in_pool: false,
                reserve_unspent: true,
                status: StatusCode::INTERNAL_SERVER_ERROR,
                journaled: 1,
                says: "did not answer",
            },
            Case {
                name: "a refusal that says it is in the pool already",
                broadcast: (400, r#"{"detail":"transaction is already in the pool"}"#),
                in_pool: false,
                reserve_unspent: true,
                status: StatusCode::OK,
                journaled: 1,
                says: "",
            },
            Case {
                name: "a refusal from a node whose pool has it",
                broadcast: (400, malformed),
                in_pool: true,
                reserve_unspent: true,
                status: StatusCode::OK,
                journaled: 1,
                says: "",
            },
            Case {
                name: "a refusal while the reserve box is spent",
                broadcast: (400, malformed),
                in_pool: false,
                reserve_unspent: false,
                status: StatusCode::INTERNAL_SERVER_ERROR,
                journaled: 1,
                says: "did not answer",
            },
        ];
        for case in cases {
            let Case {
                broadcast,
                in_pool,
                reserve_unspent,
                ..
            } = case;
            let node_url = spawn_node(move |line| {
                let found = |yes: bool| {
                    if yes {
                        (200, "{}".to_string())
                    } else {
                        (404, r#"{"error":404}"#.to_string())
                    }
                };
                if line.starts_with("POST /transactions ") {
                    (broadcast.0, broadcast.1.to_string())
                } else if line.starts_with("GET /transactions/unconfirmed/byTransactionId/") {
                    found(in_pool)
                } else if line.starts_with(&format!("GET /utxo/byId/{RESERVE_BOX_ID} ")) {
                    found(reserve_unspent)
                } else {
                    (500, format!(r#"{{"unexpected":"{line}"}}"#))
                }
            })
            .await;
            let state = mock_state_with_config(&node_url).await;
            let (unsigned_tx, signed_tx) =
                record_pending(&state, ISSUER_HEX, RECIPIENT_HEX, 1_000);
            let built = basis_server::redemption_build::unsigned_tx_id(&unsigned_tx).unwrap();
            let (status, body) = submit_redemption(
                axum::extract::State(state.clone()),
                axum::extract::Json(submit_request(unsigned_tx, signed_tx)),
            )
            .await;
            assert_eq!(status, case.status, "{}: {:?}", case.name, body);
            let journaled = state.tracker_storage.journaled_redemptions().unwrap();
            assert_eq!(journaled.len(), case.journaled, "{}", case.name);
            let followed = state
                .shared_tracker_state
                .lock()
                .await
                .get_submitted_redemptions();
            assert_eq!(followed.len(), case.journaled, "{}", case.name);
            if status == StatusCode::OK {
                assert_eq!(body.data.as_ref().unwrap().tx_id, built, "{}", case.name);
            } else {
                let msg = body.error.clone().unwrap_or_default();
                assert!(msg.contains(case.says), "{}: {msg}", case.name);
                assert!(!msg.contains("127.0.0.1"), "{}: {msg}", case.name);
            }
        }
    }
}
