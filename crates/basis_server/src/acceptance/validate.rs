//! Structural validation of acceptance policies (round 4, C1).
//!
//! A policy is a tree of named predicates. A per-recipient policy is validated before
//! `POST /acceptance/policy` stores it, and every stored policy again at startup
//! ([`recheck_stored_policies`], which moves a refused policy to the quarantine partition):
//!
//! * the JSON is at most [`MAX_POLICY_JSON_BYTES`] (8 KiB);
//! * predicate names are unique and not empty, and `root` names one of them. An empty
//!   policy (no predicates) names no root; it rejects every note;
//! * the references form a tree: each reference names a predicate of the policy, each
//!   predicate except the root is referenced exactly once, the root never, and every
//!   predicate is reachable from the root;
//! * at most [`MAX_POLICY_DEPTH`] (8) predicates on any root-to-leaf path, at most
//!   [`MAX_POLICY_PREDICATES`] (32) predicates, at most [`MAX_POLICY_REFS_PER_COMPOSITE`]
//!   (16) references per composite and at most [`MAX_POLICY_HOLDERS`] (256) whitelist and
//!   blacklist holders in all;
//! * the predicate builder accepts it (holder keys are 33-byte hex).
//!
//! The builder and the redemption-time evaluator also guard depth ([`MAX_POLICY_DEPTH`]) and
//! fail closed, so a policy that reaches them some other way cannot recurse without bound.

use std::collections::{HashMap, HashSet};

use basis_core::acceptance::{AcceptanceConfig, PredicateConfig};
use basis_store::persistence::AcceptancePolicyStorage;
use basis_store::PubKey;

/// The largest policy JSON this tracker stores, in bytes.
pub const MAX_POLICY_JSON_BYTES: usize = 8 * 1024;
/// The most predicates on any root-to-leaf path (a single leaf is depth 1).
pub const MAX_POLICY_DEPTH: usize = 8;
/// The most predicates in one policy.
pub const MAX_POLICY_PREDICATES: usize = 32;
/// The most references of one `all_of` / `any_of`.
pub const MAX_POLICY_REFS_PER_COMPOSITE: usize = 16;
/// The most whitelist and blacklist holders in one policy, all predicates together.
pub const MAX_POLICY_HOLDERS: usize = 256;

/// Why a policy is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("policy JSON is {0} bytes, the most this tracker stores is {max}", max = MAX_POLICY_JSON_BYTES)]
    TooLarge(usize),
    #[error("{0}")]
    Json(String),
    #[error("policy has {0} predicates, the most this tracker accepts is {max}", max = MAX_POLICY_PREDICATES)]
    TooManyPredicates(usize),
    #[error("policy has {0} whitelist and blacklist holders in all, the most this tracker accepts is {max}", max = MAX_POLICY_HOLDERS)]
    TooManyHolders(usize),
    #[error("a predicate has an empty name")]
    EmptyName,
    #[error("duplicate predicate name '{0}'")]
    DuplicateName(String),
    #[error("the policy has predicates but no root: set \"root\" to the name of the top predicate")]
    MissingRoot,
    #[error("an empty policy names no root, but root is '{0}'")]
    RootWithoutPredicates(String),
    #[error("root '{0}' is not a predicate of this policy")]
    UnknownRoot(String),
    #[error("predicate '{from}' references '{to}', which is not a predicate of this policy")]
    MissingReference { from: String, to: String },
    #[error("predicate '{0}' references {1} predicates, the most this tracker accepts is {max}", max = MAX_POLICY_REFS_PER_COMPOSITE)]
    TooManyReferences(String, usize),
    #[error("predicate '{0}' is referenced more than once; a policy is a tree, so define a copy under another name")]
    SharedReference(String),
    #[error("root '{0}' is referenced by a predicate of the policy")]
    RootReferenced(String),
    #[error("predicates not reachable from root '{root}': {unreachable}")]
    Unreachable { root: String, unreachable: String },
    #[error("policy is deeper than {max} levels", max = MAX_POLICY_DEPTH)]
    TooDeep,
    #[error("{0}")]
    Build(String),
}

impl PolicyError {
    /// The JSON could not be read at all (as opposed to a readable policy that is invalid).
    pub fn is_json_error(&self) -> bool {
        matches!(self, PolicyError::TooLarge(_) | PolicyError::Json(_))
    }
}

/// The names a predicate references (empty for leaves).
pub(crate) fn references(predicate: &PredicateConfig) -> &[String] {
    match predicate {
        PredicateConfig::AllOf { predicates, .. } | PredicateConfig::AnyOf { predicates, .. } => {
            predicates
        }
        PredicateConfig::Not { predicate, .. } => std::slice::from_ref(predicate),
        PredicateConfig::Whitelist { .. }
        | PredicateConfig::Blacklist { .. }
        | PredicateConfig::Collateralization { .. }
        | PredicateConfig::NoPendingRefund { .. } => &[],
    }
}

/// Parse a policy JSON string and validate it (size first, before parsing).
///
/// Parses through `serde_json::Value` for the same reason as `api::parse_acceptance_policy_json`
/// (internally tagged enums with `f64` fields and serde_json's `arbitrary_precision`).
pub fn parse_and_validate_policy_json(policy_json: &str) -> Result<AcceptanceConfig, PolicyError> {
    if policy_json.len() > MAX_POLICY_JSON_BYTES {
        return Err(PolicyError::TooLarge(policy_json.len()));
    }
    let value: serde_json::Value =
        serde_json::from_str(policy_json).map_err(|e| PolicyError::Json(e.to_string()))?;
    let config: AcceptanceConfig =
        serde_json::from_value(value).map_err(|e| PolicyError::Json(e.to_string()))?;
    validate_policy(&config)?;
    Ok(config)
}

/// Validate the structure of a parsed policy (see the module docs).
pub fn validate_policy(config: &AcceptanceConfig) -> Result<(), PolicyError> {
    let predicates = &config.predicates;
    if predicates.is_empty() {
        return match &config.root {
            Some(root) => Err(PolicyError::RootWithoutPredicates(root.clone())),
            None => Ok(()),
        };
    }
    if predicates.len() > MAX_POLICY_PREDICATES {
        return Err(PolicyError::TooManyPredicates(predicates.len()));
    }
    let holders: usize = predicates
        .iter()
        .map(|p| match p {
            PredicateConfig::Whitelist { holders, .. }
            | PredicateConfig::Blacklist { holders, .. } => holders.len(),
            _ => 0,
        })
        .sum();
    if holders > MAX_POLICY_HOLDERS {
        return Err(PolicyError::TooManyHolders(holders));
    }

    let mut by_name: HashMap<&str, &PredicateConfig> = HashMap::with_capacity(predicates.len());
    for predicate in predicates {
        let name = predicate.name();
        if name.is_empty() {
            return Err(PolicyError::EmptyName);
        }
        if by_name.insert(name, predicate).is_some() {
            return Err(PolicyError::DuplicateName(name.to_string()));
        }
    }
    let root = config.root.as_deref().ok_or(PolicyError::MissingRoot)?;
    if !by_name.contains_key(root) {
        return Err(PolicyError::UnknownRoot(root.to_string()));
    }

    let mut referenced: HashSet<&str> = HashSet::with_capacity(predicates.len());
    for predicate in predicates {
        let refs = references(predicate);
        if refs.len() > MAX_POLICY_REFS_PER_COMPOSITE {
            return Err(PolicyError::TooManyReferences(
                predicate.name().to_string(),
                refs.len(),
            ));
        }
        for to in refs {
            if !by_name.contains_key(to.as_str()) {
                return Err(PolicyError::MissingReference {
                    from: predicate.name().to_string(),
                    to: to.clone(),
                });
            }
            if to == root {
                return Err(PolicyError::RootReferenced(root.to_string()));
            }
            if !referenced.insert(to.as_str()) {
                return Err(PolicyError::SharedReference(to.clone()));
            }
        }
    }

    // Every predicate has at most one parent and the root none, so this walk visits each
    // reachable predicate once and ends: it is a tree walk, whatever the input.
    let mut reached: HashSet<&str> = HashSet::with_capacity(predicates.len());
    let mut stack: Vec<(&str, usize)> = vec![(root, 1)];
    while let Some((name, depth)) = stack.pop() {
        if depth > MAX_POLICY_DEPTH {
            return Err(PolicyError::TooDeep);
        }
        reached.insert(name);
        for child in references(by_name[name]) {
            stack.push((child.as_str(), depth + 1));
        }
    }
    if reached.len() != predicates.len() {
        let mut unreachable: Vec<&str> = predicates
            .iter()
            .map(|p| p.name())
            .filter(|name| !reached.contains(name))
            .collect();
        unreachable.sort_unstable();
        return Err(PolicyError::Unreachable {
            root: root.to_string(),
            unreachable: unreachable.join(", "),
        });
    }

    // Leaf contents (holder keys) are the builder's to check.
    super::builder::build_predicate_tree(config.clone())
        .map(|_| ())
        .map_err(|e| PolicyError::Build(e.to_string()))
}

/// Re-check every stored per-recipient policy and take the ones that fail validation or
/// cannot be read out of service, each with a warning (round 4, C1; run at startup, before the
/// routes serve). A refused policy is moved, byte for byte and with its reason, to the
/// quarantine partition (`basis_store::persistence::POLICY_QUARANTINE_PARTITION`) instead of
/// being deleted (round 5, review 6). A recipient whose policy is quarantined falls back to the
/// global policy until they upload a valid one.
///
/// Returns `(kept, quarantined)`.
pub fn recheck_stored_policies(storage: &AcceptancePolicyStorage) -> (usize, usize) {
    let listed = match storage.list_policies() {
        Ok(listed) => listed,
        Err(e) => {
            tracing::warn!("Could not list stored acceptance policies to re-check them: {e:?}");
            return (0, 0);
        }
    };
    let (mut kept, mut quarantined) = (0, 0);
    for (recipient_hex, _uploaded_at) in listed {
        let Some(recipient) = hex::decode(&recipient_hex)
            .ok()
            .and_then(|bytes| PubKey::try_from(bytes.as_slice()).ok())
        else {
            continue;
        };
        let reason = match storage.get_policy(&recipient) {
            Ok(Some(stored)) => match parse_and_validate_policy_json(&stored.policy_json) {
                Ok(_) => {
                    kept += 1;
                    continue;
                }
                Err(e) => e.to_string(),
            },
            Ok(None) => continue,
            Err(e) => format!("unreadable record: {e:?}"),
        };
        match storage.quarantine_policy(&recipient, &reason) {
            Ok(true) => {
                quarantined += 1;
                tracing::warn!(
                    "Moved the stored acceptance policy of {recipient_hex} to quarantine \
                     (partition {}): {reason}. The recipient falls back to the global policy \
                     until they upload a valid one.",
                    basis_store::persistence::POLICY_QUARANTINE_PARTITION
                );
            }
            Ok(false) => {}
            Err(e) => tracing::warn!(
                "Stored acceptance policy of {recipient_hex} is invalid ({reason}) but could not \
                 be moved to quarantine: {e:?}"
            ),
        }
    }
    (kept, quarantined)
}

#[cfg(test)]
mod tests {
    use super::*;
    use basis_core::acceptance::DefaultPolicy;

    fn key(n: u8) -> String {
        let mut key = [0u8; 33];
        key[0] = 0x02;
        key[1] = n;
        hex::encode(key)
    }

    fn leaf(name: &str) -> PredicateConfig {
        PredicateConfig::NoPendingRefund {
            name: name.to_string(),
        }
    }

    fn all_of(name: &str, refs: &[&str]) -> PredicateConfig {
        PredicateConfig::AllOf {
            name: name.to_string(),
            predicates: refs.iter().map(|r| r.to_string()).collect(),
        }
    }

    fn not(name: &str, inner: &str) -> PredicateConfig {
        PredicateConfig::Not {
            name: name.to_string(),
            predicate: inner.to_string(),
        }
    }

    fn policy(root: Option<&str>, predicates: Vec<PredicateConfig>) -> AcceptanceConfig {
        AcceptanceConfig {
            default: DefaultPolicy::Reject,
            root: root.map(str::to_string),
            predicates,
        }
    }

    /// A chain of `depth` predicates: `n0 = not(n1)`, ..., the last a leaf.
    fn chain(depth: usize) -> AcceptanceConfig {
        let mut predicates = Vec::new();
        for i in 0..depth - 1 {
            predicates.push(not(&format!("n{i}"), &format!("n{}", i + 1)));
        }
        predicates.push(leaf(&format!("n{}", depth - 1)));
        policy(Some("n0"), predicates)
    }

    #[test]
    fn a_tree_with_an_explicit_root_is_valid() {
        let config = policy(
            Some("top"),
            vec![
                PredicateConfig::Whitelist {
                    name: "friends".to_string(),
                    holders: vec![key(1), key(2)],
                    max_debt: Some(10),
                },
                PredicateConfig::Collateralization {
                    name: "collateral".to_string(),
                    min_ratio: 1.0,
                },
                all_of("top", &["friends", "collateral"]),
            ],
        );
        assert_eq!(validate_policy(&config), Ok(()));
        // The empty policy is valid too (it rejects every note).
        assert_eq!(validate_policy(&AcceptanceConfig::default()), Ok(()));
    }

    #[test]
    fn the_root_must_be_explicit_and_exist() {
        let config = policy(None, vec![leaf("a")]);
        assert_eq!(validate_policy(&config), Err(PolicyError::MissingRoot));
        let config = policy(Some("b"), vec![leaf("a")]);
        assert_eq!(
            validate_policy(&config),
            Err(PolicyError::UnknownRoot("b".to_string()))
        );
        let config = policy(Some("a"), vec![]);
        assert_eq!(
            validate_policy(&config),
            Err(PolicyError::RootWithoutPredicates("a".to_string()))
        );
    }

    #[test]
    fn names_are_unique_and_not_empty() {
        let config = policy(Some("a"), vec![all_of("a", &[]), leaf("a")]);
        assert_eq!(
            validate_policy(&config),
            Err(PolicyError::DuplicateName("a".to_string()))
        );
        let config = policy(Some("a"), vec![all_of("a", &[""]), leaf("")]);
        assert_eq!(validate_policy(&config), Err(PolicyError::EmptyName));
    }

    #[test]
    fn references_form_a_tree_reachable_from_the_root() {
        // Missing.
        let config = policy(Some("a"), vec![all_of("a", &["b"])]);
        assert!(matches!(
            validate_policy(&config),
            Err(PolicyError::MissingReference { .. })
        ));
        // Shared: a diamond, which also costs exponential time to evaluate when stacked.
        let config = policy(
            Some("a"),
            vec![all_of("a", &["b", "c"]), not("b", "d"), not("c", "d"), leaf("d")],
        );
        assert_eq!(
            validate_policy(&config),
            Err(PolicyError::SharedReference("d".to_string()))
        );
        let config = policy(Some("a"), vec![all_of("a", &["b", "b"]), leaf("b")]);
        assert_eq!(
            validate_policy(&config),
            Err(PolicyError::SharedReference("b".to_string()))
        );
        // A cycle through the root.
        let config = policy(Some("a"), vec![not("a", "b"), not("b", "a")]);
        assert_eq!(
            validate_policy(&config),
            Err(PolicyError::RootReferenced("a".to_string()))
        );
        // A cycle beside the root, and a forgotten leaf: unreachable.
        let config = policy(
            Some("a"),
            vec![leaf("a"), not("b", "c"), not("c", "b"), leaf("d")],
        );
        assert_eq!(
            validate_policy(&config),
            Err(PolicyError::Unreachable {
                root: "a".to_string(),
                unreachable: "b, c, d".to_string()
            })
        );
        let config = policy(Some("s"), vec![not("s", "s")]);
        assert_eq!(
            validate_policy(&config),
            Err(PolicyError::RootReferenced("s".to_string()))
        );
    }

    #[test]
    fn size_limits() {
        assert_eq!(validate_policy(&chain(MAX_POLICY_DEPTH)), Ok(()));
        assert_eq!(
            validate_policy(&chain(MAX_POLICY_DEPTH + 1)),
            Err(PolicyError::TooDeep)
        );

        let names: Vec<String> = (0..MAX_POLICY_REFS_PER_COMPOSITE + 1)
            .map(|i| format!("l{i}"))
            .collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let mut predicates = vec![all_of("top", &refs)];
        predicates.extend(names.iter().map(|n| leaf(n)));
        assert_eq!(
            validate_policy(&policy(Some("top"), predicates)),
            Err(PolicyError::TooManyReferences(
                "top".to_string(),
                MAX_POLICY_REFS_PER_COMPOSITE + 1
            ))
        );

        let predicates: Vec<PredicateConfig> = (0..=MAX_POLICY_PREDICATES)
            .map(|i| leaf(&format!("p{i}")))
            .collect();
        assert_eq!(
            validate_policy(&policy(Some("p0"), predicates)),
            Err(PolicyError::TooManyPredicates(MAX_POLICY_PREDICATES + 1))
        );

        let config = policy(
            Some("w"),
            vec![PredicateConfig::Whitelist {
                name: "w".to_string(),
                holders: (0..=MAX_POLICY_HOLDERS).map(|i| key(i as u8)).collect(),
                max_debt: None,
            }],
        );
        assert_eq!(
            validate_policy(&config),
            Err(PolicyError::TooManyHolders(MAX_POLICY_HOLDERS + 1))
        );

        let big = format!("{{\"padding\":\"{}\"}}", "x".repeat(MAX_POLICY_JSON_BYTES));
        assert_eq!(
            parse_and_validate_policy_json(&big),
            Err(PolicyError::TooLarge(big.len()))
        );
    }

    #[test]
    fn leaf_contents_are_checked_by_the_builder() {
        let config = policy(
            Some("w"),
            vec![PredicateConfig::Whitelist {
                name: "w".to_string(),
                holders: vec!["zz".to_string()],
                max_debt: None,
            }],
        );
        assert!(matches!(
            validate_policy(&config),
            Err(PolicyError::Build(_))
        ));
    }

    #[test]
    fn json_errors_are_told_apart() {
        let err = parse_and_validate_policy_json("not json").unwrap_err();
        assert!(err.is_json_error());
        let err = parse_and_validate_policy_json(r#"{"predicates":[{"type":"no_pending_refund","name":"a"}]}"#)
            .unwrap_err();
        assert_eq!(err, PolicyError::MissingRoot);
        assert!(!err.is_json_error());
    }

    #[test]
    fn startup_recheck_quarantines_invalid_stored_policies() {
        let dir = tempfile::tempdir().unwrap();
        let storage = AcceptancePolicyStorage::open(dir.path()).unwrap();
        let good: PubKey = [0x02; 33];
        let bad: PubKey = [0x03; 33];
        let cyclic: PubKey = {
            let mut k = [0x02; 33];
            k[1] = 9;
            k
        };
        storage
            .store_policy(
                &good,
                r#"{"root":"a","predicates":[{"type":"no_pending_refund","name":"a"}]}"#,
                "sig",
            )
            .unwrap();
        storage
            .store_policy(
                &bad,
                r#"{"predicates":[{"type":"no_pending_refund","name":"a"}]}"#,
                "sig",
            )
            .unwrap();
        storage
            .store_policy(
                &cyclic,
                r#"{"root":"a","predicates":[{"type":"not","name":"a","predicate":"a"}]}"#,
                "sig",
            )
            .unwrap();

        assert_eq!(recheck_stored_policies(&storage), (1, 2));
        assert!(storage.get_policy(&good).unwrap().is_some());
        assert!(storage.get_policy(&bad).unwrap().is_none());
        assert!(storage.get_policy(&cyclic).unwrap().is_none());
        // Round 5 (review 6): the refused policies are kept in quarantine, with their reason.
        let quarantined = storage.list_quarantined_policies().unwrap();
        let mut recipients: Vec<PubKey> =
            quarantined.iter().map(|q| q.recipient_pubkey).collect();
        recipients.sort_unstable();
        let mut expected = vec![bad, cyclic];
        expected.sort_unstable();
        assert_eq!(recipients, expected);
        assert!(quarantined.iter().all(|q| !q.reason.is_empty() && !q.record.is_empty()));
        // A second run finds nothing more to move.
        assert_eq!(recheck_stored_policies(&storage), (1, 0));
        assert_eq!(storage.list_quarantined_policies().unwrap().len(), 2);
    }
}
