//! Named network presets (issue #54).
//!
//! The presets match the repository README's endpoint table, and resolving one
//! is pure string work — no probe, no round trip. Together with
//! [`crate::strkey`] this is everything `agent-tx` does *before* it touches the
//! network, which is what makes "malformed input never reaches an RPC" testable.
//!
//! A preset answers two questions at once, because they must not diverge: the
//! RPC endpoint *and* the network passphrase. The passphrase is the input to
//! the `network_id` the signed `SorobanAuthorizationEntry` commits to, so
//! choosing an endpoint silently (a stale `--rpc-url` with a testnet
//! passphrase, or the other way round) does not fail loudly — it signs a
//! payload for a different network. Pairing them is the point.

/// A named Soroban network, so operators choose an endpoint instead of typing
/// one. Endpoints and passphrases match the README's endpoint table.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Network {
    Testnet,
    Futurenet,
    Mainnet,
}

/// The network used when neither `--network` nor `--rpc-url` is given: a
/// submission must never default to mainnet by accident.
pub const DEFAULT_NETWORK: Network = Network::Testnet;

impl Network {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Testnet => "testnet",
            Self::Futurenet => "futurenet",
            Self::Mainnet => "mainnet",
        }
    }

    pub const NAMES: [&'static str; 3] = ["testnet", "futurenet", "mainnet"];

    pub fn parse(value: &str) -> Result<Self, String> {
        match value.to_ascii_lowercase().as_str() {
            "testnet" => Ok(Self::Testnet),
            "futurenet" => Ok(Self::Futurenet),
            "mainnet" => Ok(Self::Mainnet),
            other => Err(format!(
                "invalid --network '{other}': not a named network; expected one of {}",
                Self::NAMES.join(", ")
            )),
        }
    }

    pub const fn rpc_url(self) -> &'static str {
        match self {
            Self::Testnet => "https://soroban-testnet.stellar.org",
            Self::Futurenet => "https://rpc-futurenet.stellar.org",
            Self::Mainnet => "https://soroban.stellar.org",
        }
    }

    pub const fn passphrase(self) -> &'static str {
        match self {
            Self::Testnet => "Test SDF Network ; September 2015",
            Self::Futurenet => "Test SDF Future Network ; October 2022",
            Self::Mainnet => "Public Global Stellar Network ; September 2015",
        }
    }

    /// Which preset an `--rpc-url` points at, compared by host so a trailing
    /// slash or `http://` cannot hide a mainnet endpoint.
    pub fn from_rpc_url(url: &str) -> Option<Self> {
        let host = url
            .split_once("://")
            .map_or(url, |(_, rest)| rest)
            .split(['/', '?', '#'])
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        if host == Self::Testnet.rpc_url().trim_start_matches("https://") {
            Some(Self::Testnet)
        } else if host == Self::Futurenet.rpc_url().trim_start_matches("https://") {
            Some(Self::Futurenet)
        } else if host == Self::Mainnet.rpc_url().trim_start_matches("https://") {
            Some(Self::Mainnet)
        } else {
            None
        }
    }

    /// The reminder to print when this network is selected. SECURITY.md: the
    /// contract is unaudited, and mainnet is where that distinction is paid
    /// for in real funds.
    pub fn notice(self) -> Option<&'static str> {
        match self {
            Self::Mainnet => Some(
                "warning: mainnet selected — this contract is unaudited and gates fund \
                 movement; do not use it with real funds (see SECURITY.md)",
            ),
            Self::Testnet | Self::Futurenet => None,
        }
    }
}

/// An endpoint resolved from `--network` / `--rpc-url` / `--network-passphrase`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// `None` when the endpoint matches no preset (a custom `--rpc-url`).
    pub network: Option<Network>,
    pub rpc_url: String,
    pub passphrase: String,
}

/// Turn the three endpoint flags into one answer, kept apart from argument
/// collection so the subcommand flags and `guards add` share one rule set.
pub fn resolve_endpoint(
    network: Option<&str>,
    rpc_url: Option<&str>,
    passphrase: Option<&str>,
) -> Result<Endpoint, String> {
    match (network, rpc_url) {
        (Some(name), Some(url)) => {
            let preset = Network::parse(name)?;
            Err(format!(
                "conflicting network selection: --network '{}' and --rpc-url '{url}' both name an \
                 endpoint; use --network alone for its preset URL, or drop --network to connect \
                 to '{url}'",
                preset.name()
            ))
        }
        (Some(name), None) => {
            let preset = Network::parse(name)?;
            Ok(Endpoint {
                network: Some(preset),
                rpc_url: preset.rpc_url().to_string(),
                passphrase: passphrase
                    .unwrap_or_else(|| preset.passphrase())
                    .to_string(),
            })
        }
        (None, Some(url)) => {
            // A URL that *is* a preset endpoint gets that preset's passphrase:
            // `--rpc-url https://soroban.stellar.org` must not sign a testnet
            // payload. A custom node keeps the default.
            let preset = Network::from_rpc_url(url);
            let fallback = preset.unwrap_or(DEFAULT_NETWORK);
            Ok(Endpoint {
                network: preset,
                rpc_url: url.to_string(),
                passphrase: passphrase
                    .unwrap_or_else(|| fallback.passphrase())
                    .to_string(),
            })
        }
        (None, None) => Ok(Endpoint {
            network: Some(DEFAULT_NETWORK),
            rpc_url: DEFAULT_NETWORK.rpc_url().to_string(),
            passphrase: passphrase
                .unwrap_or_else(|| DEFAULT_NETWORK.passphrase())
                .to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_match_the_readme_endpoint_table() {
        assert_eq!(
            Network::Testnet.rpc_url(),
            "https://soroban-testnet.stellar.org"
        );
        assert_eq!(
            Network::Futurenet.rpc_url(),
            "https://rpc-futurenet.stellar.org"
        );
        assert_eq!(Network::Mainnet.rpc_url(), "https://soroban.stellar.org");
        assert_eq!(
            Network::Mainnet.passphrase(),
            "Public Global Stellar Network ; September 2015"
        );
        assert_eq!(
            Network::Futurenet.passphrase(),
            "Test SDF Future Network ; October 2022"
        );
    }

    #[test]
    fn endpoint_defaults_to_testnet_and_presets_resolve_both_url_and_passphrase() {
        let default = resolve_endpoint(None, None, None).unwrap();
        assert_eq!(default.network, Some(Network::Testnet));
        assert_eq!(default.rpc_url, Network::Testnet.rpc_url());
        assert_eq!(default.passphrase, Network::Testnet.passphrase());

        let futurenet = resolve_endpoint(Some("futurenet"), None, None).unwrap();
        assert_eq!(futurenet.rpc_url, "https://rpc-futurenet.stellar.org");
        assert_eq!(
            futurenet.passphrase,
            "Test SDF Future Network ; October 2022"
        );

        let mainnet = resolve_endpoint(Some("mainnet"), None, None).unwrap();
        assert_eq!(mainnet.network, Some(Network::Mainnet));
        assert_eq!(mainnet.rpc_url, "https://soroban.stellar.org");
    }

    #[test]
    fn rpc_url_overrides_the_default_but_not_an_explicit_network() {
        let custom = "http://127.0.0.1:8000/soroban/rpc";
        let overridden = resolve_endpoint(None, Some(custom), None).unwrap();
        assert_eq!(overridden.rpc_url, custom);
        assert_eq!(overridden.network, None, "a private node is not a preset");
        assert_eq!(
            overridden.passphrase,
            Network::Testnet.passphrase(),
            "an unrecognised URL keeps the documented default passphrase"
        );

        // A preset endpoint passed as a URL is still that network: signing the
        // wrong payload because the passphrase came from the default would be
        // the exact "simulated against mainnet by accident" mistake #54 exists
        // to remove.
        let by_url = resolve_endpoint(None, Some(Network::Mainnet.rpc_url()), None).unwrap();
        assert_eq!(by_url.network, Some(Network::Mainnet));
        assert_eq!(by_url.passphrase, Network::Mainnet.passphrase());

        let err = resolve_endpoint(Some("testnet"), Some(custom), None).unwrap_err();
        assert!(err.starts_with("conflicting network selection"), "{err}");
        assert!(
            err.contains("--network") && err.contains("--rpc-url"),
            "{err}"
        );
    }

    #[test]
    fn network_names_are_case_insensitive_and_unknown_ones_list_the_choices() {
        assert_eq!(Network::parse("MainNet").unwrap(), Network::Mainnet);
        let err = Network::parse("local").unwrap_err();
        assert!(err.contains("invalid --network 'local'"), "{err}");
        assert!(err.contains("testnet, futurenet, mainnet"), "{err}");
    }

    #[test]
    fn mainnet_is_recognised_from_its_url_and_warns_others_do_not() {
        assert_eq!(
            Network::from_rpc_url("https://soroban.stellar.org/"),
            Some(Network::Mainnet)
        );
        assert_eq!(
            Network::from_rpc_url("http://soroban.stellar.org"),
            Some(Network::Mainnet)
        );
        assert_eq!(
            Network::from_rpc_url("https://rpc-futurenet.stellar.org/some/path"),
            Some(Network::Futurenet)
        );
        assert_eq!(Network::from_rpc_url("http://127.0.0.1:8000"), None);

        assert!(Network::Mainnet.notice().is_some());
        assert!(Network::Mainnet.notice().unwrap().contains("unaudited"));
        assert!(Network::Testnet.notice().is_none());
        assert!(Network::Futurenet.notice().is_none());
    }

    #[test]
    fn explicit_passphrase_override_wins_over_the_preset() {
        let endpoint =
            resolve_endpoint(Some("futurenet"), None, Some("Some Local Network ; 2026")).unwrap();
        assert_eq!(endpoint.rpc_url, Network::Futurenet.rpc_url());
        assert_eq!(endpoint.passphrase, "Some Local Network ; 2026");
    }
}
