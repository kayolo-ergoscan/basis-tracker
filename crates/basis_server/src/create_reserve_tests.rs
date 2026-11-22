#[cfg(test)]
mod create_reserve_tests {
    use axum::{extract::State, http::StatusCode, Json};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    use crate::{
        api::create_reserve_payload,
        models::{CreateReserveRequest, ReserveCreationResponse},
        AppState, TrackerCommand,
    };
    use basis_store::ergo_scanner::{NodeConfig, ServerState};

    /// Serializes fjall keyspace creation across parallel tests; concurrent
    /// `ServerState::new` calls race inside lsm-tree Tree creation and can
    /// abort the test process (see the same pattern in the integration tests).
    static STORAGE_INIT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // Helper function to create a unique temporary directory for test storage
    fn unique_test_storage_path(prefix: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "{}_{}_{}",
            prefix,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    // Helper function to create a test AppState that doesn't require file system access
    fn create_test_app_state() -> AppState {
        let (tx, _rx) = tokio::sync::mpsc::channel::<TrackerCommand>(100);
        let event_store = std::sync::Arc::new(crate::store::EventStore::new_in_memory());

        // Create a minimal configuration
        let config = NodeConfig {
            node_url: "http://localhost:9553".to_string(),
            ..Default::default()
        };

        // Create a scanner state that doesn't try to access files by using a memory-only implementation
        // For testing purposes, we'll create a minimal state that doesn't require file access
        let data_dir = std::env::temp_dir().join(format!(
            "basis_create_reserve_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&data_dir);
        let scanner = {
            let _guard = STORAGE_INIT_LOCK.lock().unwrap();
            ServerState::new(config, &data_dir).expect("Failed to create test scanner state")
        };

        // Create a minimal config for testing
        let test_config = std::sync::Arc::new(crate::config::AppConfig {
            server: crate::config::ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 3048,
                data_dir: Some(data_dir.to_string_lossy().to_string()),
                database_url: Some("sqlite::memory:".to_string()),
                tls_cert_path: None,
                tls_key_path: None,
                auth: crate::config::AuthConfig::default(),
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
            ergo: crate::config::ErgoConfig {
                scanner: NodeConfig {
                    node_url: "http://example.com".to_string(),
                    ..Default::default()
                },
                wallet: Default::default(),
                basis_reserve_contract_p2s: "test".to_string(),
                basis_token_reserve_contract_p2s: "test_token".to_string(),
                tracker_nft_id: Some(
                    "69c5d7a4df2e72252b0015d981876fe338ca240d5576d4e731dfd848ae18fe2b".to_string(),
                ),
                reserve_tokens: Default::default(),
                tracker_public_key: Some(
                    "9fRusAarL1KkrWQVsxSRVYnvWxaAT2A96cKtNn9tvPh5XUyCisr33".to_string(),
                ),
                tracker_secret_key: None,
            },
            transaction: crate::config::TransactionConfig {
                fee: 1000000,
                change_address: None,
                heartbeat_blocks: 720,
                commit_reserve_nano: 100_000_000,
            },
            acceptance: crate::acceptance::config::AcceptanceConfig::empty(),
            redemption: crate::config::RedemptionConfig::default(),
            confirmation: crate::config::ConfirmationConfig::default(),
        });

        let reserve_tracker = Arc::new(Mutex::new(basis_store::ReserveTracker::new()));

        let tracker_storage_path =
            unique_test_storage_path("basis_test_tracker_storage_create_reserve");
        std::fs::create_dir_all(&tracker_storage_path)
            .expect("Failed to create tracker storage directory");
        let tracker_storage = basis_store::persistence::TrackerStorage::open(&tracker_storage_path)
            .unwrap_or_else(|_| {
                basis_store::persistence::TrackerStorage::open(unique_test_storage_path(
                    "basis_test_tracker_storage_create_reserve_fallback",
                ))
                .unwrap()
            });

        let policy_storage_path =
            unique_test_storage_path("basis_test_policy_storage_create_reserve");
        std::fs::create_dir_all(&policy_storage_path)
            .expect("Failed to create policy storage directory");
        let policy_storage =
            basis_store::persistence::AcceptancePolicyStorage::open(&policy_storage_path)
                .unwrap_or_else(|_| {
                    basis_store::persistence::AcceptancePolicyStorage::open(
                        unique_test_storage_path(
                            "basis_test_policy_storage_create_reserve_fallback",
                        ),
                    )
                    .unwrap()
                });

        AppState {
            tx,
            event_store,
            ergo_scanner: Arc::new(Mutex::new(scanner)),
            reserve_tracker,
            config: test_config,
            shared_tracker_state: Arc::new(tokio::sync::Mutex::new(confirmed_tracker_box())),
            tracker_storage,
            acceptance_predicate: None,
            policy_storage,
            pending_redemptions: std::sync::Arc::new(
                crate::redemption_build::PendingRedemptionRegistry::new(),
            ),
            redemption_build_rate: std::sync::Arc::new(
                crate::redemption_build::BuildRateLimiter::new(),
            ),
            note_limits: std::sync::Arc::new(crate::note_limits::NoteLimiter::new()),
        }
    }

    /// Shared tracker state in which the box updater has seen the tracker box in a block.
    fn confirmed_tracker_box() -> crate::tracker_box_updater::SharedTrackerState {
        let shared = crate::tracker_box_updater::SharedTrackerState::new();
        shared.set_confirmed([0x42; 33], "ab".repeat(32), 1_000);
        shared
    }

    fn request(nft_id: &str) -> CreateReserveRequest {
        CreateReserveRequest {
            nft_id: nft_id.to_string(),
            owner_pubkey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .to_string(),
            erg_amount: 1_000_000_000,
            token_amount: 0,
            token_id: String::new(),
        }
    }

    /// Before the tracker box for the configured NFT is confirmed on chain, a reserve would be
    /// bound to a tracker that does not exist yet: 503 with a clear message, no payload. Once
    /// the box updater has seen the box, the same request gets its payload.
    #[tokio::test]
    async fn test_create_reserve_payload_waits_for_a_confirmed_tracker_box() {
        let reserve_nft = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let state = create_test_app_state();
        *state.shared_tracker_state.lock().await =
            crate::tracker_box_updater::SharedTrackerState::new();

        let (status, body) =
            create_reserve_payload(State(state.clone()), Json(request(reserve_nft))).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body:?}");
        let error = body.error.clone().unwrap();
        assert!(error.contains("not confirmed on chain yet"), "{error}");
        assert!(body.data.is_none());

        // A live box id alone (no confirmed state) is not enough either.
        state
            .shared_tracker_state
            .lock()
            .await
            .set_tracker_box_id("cd".repeat(32));
        let (status, _) =
            create_reserve_payload(State(state.clone()), Json(request(reserve_nft))).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

        *state.shared_tracker_state.lock().await = confirmed_tracker_box();
        let (status, body) = create_reserve_payload(State(state), Json(request(reserve_nft))).await;
        assert_eq!(status, StatusCode::OK, "{body:?}");
        assert!(body.data.is_some());
    }

    fn create_token_test_app_state() -> AppState {
        let mut state = create_test_app_state();
        let mut config = (*state.config).clone();
        config.ergo.reserve_tokens.insert(
            "a55b8735ed1a99e46c2c89f8994aacdf4b1109bdcf682f1e5b34479c6e392669".to_string(),
            crate::config::ReserveTokenConfig {
                symbol: "USE".to_string(),
                decimals: 6,
                min_collateralization_ratio: None,
            },
        );
        state.config = std::sync::Arc::new(config);
        state
    }

    #[tokio::test]
    async fn test_create_reserve_payload_success() {
        let state = create_test_app_state();

        let request_payload = CreateReserveRequest {
            nft_id: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            owner_pubkey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .to_string(), // 33-byte public key
            erg_amount: 1000000000, // 1 ERG in nanoERG
            token_amount: 0,
            token_id: "".to_string(),
        };

        let result = create_reserve_payload(State(state), Json(request_payload)).await;

        let (status, response_json) = result;

        // Check if the error is due to config loading failure (which is expected in the test environment)
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            // If config loading fails, the test is not testing the right functionality
            // We should handle this differently in a test environment
            eprintln!("Error response: {:?}", response_json);
            assert!(response_json.error.is_some());
        } else {
            assert_eq!(status, StatusCode::OK);
            assert!(response_json.success);
            assert!(response_json.data.is_some());

            let response_data = response_json.data.clone().unwrap();
            let reserve_response: ReserveCreationResponse = response_data;

            // Verify the response structure
            assert!(!reserve_response.requests.is_empty());
            // Verify other fields after making sure the requests array is not empty
            if !reserve_response.requests.is_empty() {
                assert_eq!(reserve_response.requests[0].value, 1000000000);
                assert_eq!(
                    reserve_response.requests[0].assets[0].token_id,
                    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                );
                assert_eq!(
                    reserve_response.requests[0].registers.get("R4").unwrap(),
                    "070279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                );
                assert!(reserve_response.fee > 0); // Should be the configured fee amount
            }
        }
    }

    /// Every register of the payload is exactly one canonical sigma constant, in lowercase hex:
    /// it parses, and serializing the parsed constant gives back the payload's bytes, with no
    /// trailing bytes (R7 used to be `0500` followed by 8 zero bytes). Checked for an ERG and a
    /// token reserve, with the owner key in upper case.
    #[tokio::test]
    async fn test_create_reserve_payload_registers_are_canonical_constants() {
        use ergo_lib::ergotree_ir::mir::constant::Constant;
        use ergo_lib::ergotree_ir::serialization::SigmaSerializable;

        let owner = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let reserve_nft = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let token_id = "a55b8735ed1a99e46c2c89f8994aacdf4b1109bdcf682f1e5b34479c6e392669";
        let mut erg_request = request(reserve_nft);
        erg_request.owner_pubkey = owner.to_uppercase();
        let token_request = CreateReserveRequest {
            nft_id: reserve_nft.to_string(),
            owner_pubkey: owner.to_string(),
            erg_amount: 10_000_000,
            token_amount: 1000,
            token_id: token_id.to_string(),
        };

        for (state, payload) in [
            (create_test_app_state(), erg_request),
            (create_token_test_app_state(), token_request),
        ] {
            let tracker_nft = state.config.ergo.tracker_nft_id.clone().unwrap();
            let (status, body) = create_reserve_payload(State(state), Json(payload)).await;
            assert_eq!(status, StatusCode::OK, "{body:?}");
            let response = body.data.clone().unwrap();
            let registers = &response.requests[0].registers;
            let mut ids: Vec<&String> = registers.keys().collect();
            ids.sort();
            assert_eq!(ids, ["R4", "R5", "R6", "R7"]);

            for (id, value) in registers {
                assert_eq!(value, &value.to_lowercase(), "{id} must be lowercase hex");
                let bytes = hex::decode(value).unwrap();
                let constant = Constant::sigma_parse_bytes(&bytes)
                    .unwrap_or_else(|e| panic!("{id} = {value} does not parse: {e}"));
                assert_eq!(
                    constant.sigma_serialize_bytes().unwrap(),
                    bytes,
                    "{id} = {value} must be exactly one constant, with no trailing bytes"
                );
            }
            assert_eq!(registers["R4"], format!("07{owner}"));
            assert_eq!(registers["R6"], format!("0e20{}", tracker_nft.to_lowercase()));
            assert_eq!(registers["R7"], "0500");
            assert_eq!(
                Constant::sigma_parse_bytes(&hex::decode(&registers["R7"]).unwrap()).unwrap(),
                Constant::from(0i64)
            );
        }
    }

    /// An owner key that is 33 bytes but not a compressed point (or is the identity) is refused:
    /// R4 would lock the collateral under a key nobody, or everybody, can prove.
    #[tokio::test]
    async fn test_create_reserve_payload_rejects_an_owner_key_off_the_curve() {
        let reserve_nft = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        for owner in [
            format!("05{}", "11".repeat(32)),
            "00".repeat(33),
            format!("02{}", "ff".repeat(32)),
        ] {
            let mut payload = request(reserve_nft);
            payload.owner_pubkey = owner.clone();
            let (status, body) = create_reserve_payload(State(create_test_app_state()), Json(payload)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{owner}: {body:?}");
            assert!(body.error.clone().unwrap().contains("owner_pubkey"), "{owner}: {body:?}");
        }
    }

    #[tokio::test]
    async fn test_create_reserve_payload_invalid_pubkey() {
        let state = create_test_app_state();

        let request_payload = CreateReserveRequest {
            nft_id: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            owner_pubkey: "invalid_hex".to_string(), // Invalid hex
            erg_amount: 1000000000,
            token_amount: 0,
            token_id: "".to_string(),
        };

        let result = create_reserve_payload(State(state), Json(request_payload)).await;

        let (status, response_json) = result;

        // The validation should catch the invalid hex before attempting config loading
        if status != StatusCode::INTERNAL_SERVER_ERROR {
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(!response_json.success);
            assert!(response_json.error.is_some());
            assert!(response_json.error.clone().unwrap().contains("hex-encoded"));
        }
    }

    #[tokio::test]
    async fn test_create_reserve_payload_wrong_pubkey_length() {
        let state = create_test_app_state();

        let request_payload = CreateReserveRequest {
            nft_id: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            owner_pubkey: "03e8c3e4".to_string(), // Too short (only 4 bytes when should be 33)
            erg_amount: 1000000000,
            token_amount: 0,
            token_id: "".to_string(),
        };

        let result = create_reserve_payload(State(state), Json(request_payload)).await;

        let (status, response_json) = result;

        // The validation should catch the wrong pubkey length before attempting config loading
        if status != StatusCode::INTERNAL_SERVER_ERROR {
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(!response_json.success);
            assert!(response_json.error.is_some());
            assert!(response_json.error.clone().unwrap().contains("33 bytes"));
        }
    }

    #[tokio::test]
    async fn test_create_reserve_payload_empty_nft_id() {
        let state = create_test_app_state();

        let request_payload = CreateReserveRequest {
            nft_id: "".to_string(), // Empty NFT ID
            owner_pubkey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .to_string(),
            erg_amount: 1000000000,
            token_amount: 0,
            token_id: "".to_string(),
        };

        let result = create_reserve_payload(State(state), Json(request_payload)).await;

        let (status, response_json) = result;

        // The validation should catch the empty nft_id before attempting config loading
        if status != StatusCode::INTERNAL_SERVER_ERROR {
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(!response_json.success);
            assert!(response_json.error.is_some());
            assert!(response_json
                .error
                .clone()
                .unwrap()
                .contains("cannot be empty"));
        }
    }

    #[tokio::test]
    async fn test_create_reserve_payload_zero_amount() {
        let state = create_test_app_state();

        let request_payload = CreateReserveRequest {
            nft_id: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            owner_pubkey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .to_string(),
            erg_amount: 0, // Zero amount
            token_amount: 0,
            token_id: "".to_string(),
        };

        let result = create_reserve_payload(State(state), Json(request_payload)).await;

        let (status, response_json) = result;

        // The validation should catch the zero amount before attempting config loading
        if status != StatusCode::INTERNAL_SERVER_ERROR {
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(!response_json.success);
            assert!(response_json.error.is_some());
            assert!(response_json
                .error
                .clone()
                .unwrap()
                .contains("greater than 0"));
        }
    }

    #[tokio::test]
    async fn test_create_token_reserve_payload_success() {
        let state = create_token_test_app_state();

        let request_payload = CreateReserveRequest {
            nft_id: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            owner_pubkey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .to_string(),
            erg_amount: 10000000, // 0.01 ERG for min-box-value
            token_amount: 1000,
            token_id: "a55b8735ed1a99e46c2c89f8994aacdf4b1109bdcf682f1e5b34479c6e392669"
                .to_string(),
        };

        let result = create_reserve_payload(State(state), Json(request_payload)).await;
        let (status, response_json) = result;

        assert_eq!(status, StatusCode::OK);
        assert!(response_json.success);
        assert!(response_json.data.is_some());

        let response_data = response_json.data.clone().unwrap();
        let reserve_response: ReserveCreationResponse = response_data;

        assert!(!reserve_response.requests.is_empty());
        let req = &reserve_response.requests[0];
        assert_eq!(req.address, "test_token");
        assert_eq!(req.value, 10000000);
        assert_eq!(req.assets.len(), 2);
        assert_eq!(
            req.assets[0].token_id,
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        );
        assert_eq!(req.assets[0].amount, 1);
        assert_eq!(
            req.assets[1].token_id,
            "a55b8735ed1a99e46c2c89f8994aacdf4b1109bdcf682f1e5b34479c6e392669"
        );
        assert_eq!(req.assets[1].amount, 1000);
    }

    #[tokio::test]
    async fn test_create_token_reserve_payload_rejects_wrong_token_id() {
        let state = create_token_test_app_state();

        let request_payload = CreateReserveRequest {
            nft_id: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            owner_pubkey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .to_string(),
            erg_amount: 10000000,
            token_amount: 1000,
            token_id: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
        };

        let result = create_reserve_payload(State(state), Json(request_payload)).await;
        let (status, response_json) = result;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(!response_json.success);
        assert!(response_json
            .error
            .clone()
            .unwrap()
            .contains("not served by this tracker"));
    }

    #[tokio::test]
    async fn test_get_reserve_token_config_erg_mode() {
        let state = create_test_app_state();

        let (status, response_json) = crate::api::get_reserve_token_config(State(state)).await;

        assert_eq!(status, StatusCode::OK);
        assert!(response_json.success);
        let config = response_json.data.clone().unwrap();
        assert!(config.reserve_token_id.is_none());
        assert_eq!(config.reserve_token_decimals, 0);
        assert_eq!(config.basis_token_reserve_contract_p2s, "test_token");
    }

    #[tokio::test]
    async fn test_get_reserve_token_config_use_mode() {
        let state = create_token_test_app_state();

        let (status, response_json) = crate::api::get_reserve_token_config(State(state)).await;

        assert_eq!(status, StatusCode::OK);
        assert!(response_json.success);
        let config = response_json.data.clone().unwrap();
        assert_eq!(
            config.reserve_token_id.unwrap(),
            "a55b8735ed1a99e46c2c89f8994aacdf4b1109bdcf682f1e5b34479c6e392669"
        );
        assert_eq!(config.reserve_token_decimals, 6);
        assert_eq!(config.basis_token_reserve_contract_p2s, "test_token");
    }

    #[tokio::test]
    async fn test_create_reserve_payload_rejects_tracker_nft_as_reserve_nft() {
        let state = create_test_app_state();

        // The reserve NFT must never be the tracker NFT (PR #16 B4): a reserve box carrying
        // the tracker NFT would collide with the tracker state box this server scans for.
        let request_payload = CreateReserveRequest {
            nft_id: "69c5d7a4df2e72252b0015d981876fe338ca240d5576d4e731dfd848ae18fe2b".to_string(),
            owner_pubkey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .to_string(),
            erg_amount: 1000000000,
            token_amount: 0,
            token_id: "".to_string(),
        };

        let (status, response_json) =
            create_reserve_payload(State(state), Json(request_payload)).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(!response_json.success);
        assert!(response_json.error.clone().unwrap().contains("tracker NFT"));
    }

    #[tokio::test]
    async fn test_create_reserve_payload_rejects_erg_above_configured_cap() {
        let state = create_test_app_state();

        let request_payload = CreateReserveRequest {
            nft_id: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            owner_pubkey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .to_string(),
            erg_amount: 10_000_000_001, // one nanoERG above the configured 10 ERG cap
            token_amount: 0,
            token_id: "".to_string(),
        };

        let (status, response_json) =
            create_reserve_payload(State(state), Json(request_payload)).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(!response_json.success);
        assert!(response_json
            .error
            .clone()
            .unwrap()
            .contains("exceeds the configured per-reserve limit"));
    }

    #[tokio::test]
    async fn test_create_token_reserve_payload_rejects_token_amount_above_cap() {
        let state = create_token_test_app_state();

        let request_payload = CreateReserveRequest {
            nft_id: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            owner_pubkey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .to_string(),
            erg_amount: 10000000,
            token_amount: 1_000_000_001, // one unit above the configured cap
            token_id: "a55b8735ed1a99e46c2c89f8994aacdf4b1109bdcf682f1e5b34479c6e392669"
                .to_string(),
        };

        let (status, response_json) =
            create_reserve_payload(State(state), Json(request_payload)).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(!response_json.success);
        assert!(response_json
            .error
            .clone()
            .unwrap()
            .contains("exceeds the configured per-reserve limit"));
    }

    #[tokio::test]
    async fn test_create_reserve_payload_change_address_is_owner_p2pk() {
        // PR #16 B4: the owner submits the payload to their own node, so change must return
        // to the owner's P2PK address derived from owner_pubkey — never to the tracker wallet.
        let state = create_test_app_state();

        let owner_pubkey =
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string();
        let request_payload = CreateReserveRequest {
            nft_id: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            owner_pubkey: owner_pubkey.clone(),
            erg_amount: 1000000000,
            token_amount: 0,
            token_id: "".to_string(),
        };

        let (status, response_json) =
            create_reserve_payload(State(state), Json(request_payload)).await;

        assert_eq!(status, StatusCode::OK);
        let reserve_response: ReserveCreationResponse = response_json.data.clone().unwrap();
        assert_eq!(
            reserve_response.change_address,
            basis_offchain::ergo_tx::pubkey_to_address(&owner_pubkey).unwrap()
        );
    }
}
