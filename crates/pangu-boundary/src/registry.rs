//! B4: built-in provider registry.
//!
//! The registry is **static, version-controlled configuration data** for
//! OpenAI-compatible endpoints: per-provider defaults (endpoint, key
//! variable), per-model capability declarations, and a price table with an
//! explicit as-of date. It never adds a new wire protocol — BOUNDARY §5 keeps
//! "no dedicated Anthropic provider" as a non-goal.
//!
//! Honesty rules:
//! - Registry prices are only applied when the operator names the provider in
//!   config (`model.provider`). Naming a provider IS the human decision to use
//!   its table; explicit TOML values always win.
//! - Every preset carries `prices_as_of`. Price tables go stale; `pangu models
//!   list` prints the date and the docs require verification before relying.
//! - A model without registry prices still runs fail-closed under G4: the cost
//!   gate treats a missing price as unknown cost, never as free.

use serde::Serialize;

use pangu_core::{Error, Result};

/// Version of the built-in registry schema. Bump when a preset's shape (not
/// just its data) changes.
pub const REGISTRY_VERSION: &str = "pangu-provider-registry/1";

#[derive(Debug, Clone, Serialize)]
pub struct RegistryModel {
    pub name: &'static str,
    pub context_window_tokens: u64,
    pub max_output_tokens: u64,
    pub supports_tools: bool,
    pub input_usd_per_mtok: f64,
    pub output_usd_per_mtok: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProviderPreset {
    pub name: &'static str,
    /// Wire protocol the preset speaks. All current presets speak the
    /// OpenAI-compatible chat completions API.
    pub protocol: &'static str,
    pub base_url: &'static str,
    pub api_key_env: Option<&'static str>,
    /// Some local endpoints need no key at all; a keyed preset without
    /// `model.api_key_env` fails at config time, not mid-run.
    pub requires_api_key: bool,
    /// Month the price table was last verified, e.g. `"2025-06"`.
    pub prices_as_of: &'static str,
    pub models: &'static [RegistryModel],
}

/// Where a resolved field came from. Reported by `doctor`/`explain` so the
/// operator can tell their own config from a registry default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldSource {
    /// Set explicitly in the operator's config.
    Explicit,
    /// Filled from the named registry preset.
    Preset,
    /// Built-in fallback for configs that name no provider.
    Default,
}

impl FieldSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::Preset => "registry preset",
            Self::Default => "built-in default",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PriceSource {
    Explicit,
    /// Registry table, with its as-of month.
    Registry(&'static str),
    /// No price known: the cost gate fails closed (unknown cost is not free).
    Absent,
}

/// The effective provider endpoint, key variable, prices, and capabilities,
/// resolved from config + registry. Pure data: nothing here mutates the
/// config or performs I/O.
#[derive(Debug, Clone, Serialize)]
pub struct ResolvedProvider {
    /// `Some` only when the operator named the provider explicitly.
    pub preset: Option<&'static ProviderPreset>,
    pub model: Option<String>,
    pub base_url: String,
    pub base_url_source: FieldSource,
    pub api_key_env: Option<String>,
    pub api_key_env_source: FieldSource,
    pub input_usd_per_mtok: Option<f64>,
    pub output_usd_per_mtok: Option<f64>,
    pub price_source: PriceSource,
    /// Registry capability declaration for the configured model, when the
    /// provider is named and the model is known to the registry.
    pub capabilities: Option<&'static RegistryModel>,
}

const OPENAI: ProviderPreset = ProviderPreset {
    name: "openai",
    protocol: "openai-compatible",
    base_url: "https://api.openai.com/v1",
    api_key_env: Some("OPENAI_API_KEY"),
    requires_api_key: true,
    prices_as_of: "2025-06",
    models: &[
        RegistryModel {
            name: "gpt-4o",
            context_window_tokens: 128_000,
            max_output_tokens: 16_384,
            supports_tools: true,
            input_usd_per_mtok: 2.50,
            output_usd_per_mtok: 10.00,
        },
        RegistryModel {
            name: "gpt-4o-mini",
            context_window_tokens: 128_000,
            max_output_tokens: 16_384,
            supports_tools: true,
            input_usd_per_mtok: 0.15,
            output_usd_per_mtok: 0.60,
        },
        RegistryModel {
            name: "gpt-4.1",
            context_window_tokens: 1_000_000,
            max_output_tokens: 32_768,
            supports_tools: true,
            input_usd_per_mtok: 2.00,
            output_usd_per_mtok: 8.00,
        },
        RegistryModel {
            name: "gpt-4.1-mini",
            context_window_tokens: 1_000_000,
            max_output_tokens: 32_768,
            supports_tools: true,
            input_usd_per_mtok: 0.40,
            output_usd_per_mtok: 1.60,
        },
        RegistryModel {
            name: "gpt-4.1-nano",
            context_window_tokens: 1_000_000,
            max_output_tokens: 32_768,
            supports_tools: true,
            input_usd_per_mtok: 0.10,
            output_usd_per_mtok: 0.40,
        },
        RegistryModel {
            name: "o3",
            context_window_tokens: 200_000,
            max_output_tokens: 100_000,
            supports_tools: true,
            input_usd_per_mtok: 2.00,
            output_usd_per_mtok: 8.00,
        },
        RegistryModel {
            name: "o4-mini",
            context_window_tokens: 200_000,
            max_output_tokens: 100_000,
            supports_tools: true,
            input_usd_per_mtok: 1.10,
            output_usd_per_mtok: 4.40,
        },
    ],
};

const DEEPSEEK: ProviderPreset = ProviderPreset {
    name: "deepseek",
    protocol: "openai-compatible",
    base_url: "https://api.deepseek.com/v1",
    api_key_env: Some("DEEPSEEK_API_KEY"),
    requires_api_key: true,
    prices_as_of: "2025-02",
    models: &[
        RegistryModel {
            name: "deepseek-chat",
            context_window_tokens: 64_000,
            max_output_tokens: 8_192,
            supports_tools: true,
            input_usd_per_mtok: 0.27,
            output_usd_per_mtok: 1.10,
        },
        RegistryModel {
            name: "deepseek-reasoner",
            context_window_tokens: 64_000,
            max_output_tokens: 8_192,
            // As of 2025-02 the reasoner endpoint did not accept function
            // calls; Pangu requires them, so selecting it fails at config
            // time instead of mid-run.
            supports_tools: false,
            input_usd_per_mtok: 0.55,
            output_usd_per_mtok: 2.19,
        },
    ],
};

const OLLAMA: ProviderPreset = ProviderPreset {
    name: "ollama",
    protocol: "openai-compatible",
    base_url: "http://localhost:11434/v1",
    api_key_env: None,
    requires_api_key: false,
    prices_as_of: "n/a (local)",
    // Local pulls vary by machine; there is no honest built-in table. Prices
    // stay unset, so the cost gate fails closed until the operator declares
    // them.
    models: &[],
};

/// Built-in presets, in listing order.
pub fn presets() -> &'static [ProviderPreset] {
    &[OPENAI, DEEPSEEK, OLLAMA]
}

pub fn preset(name: &str) -> Option<&'static ProviderPreset> {
    presets().iter().find(|preset| preset.name == name)
}

pub fn preset_model<'a>(preset: &'a ProviderPreset, model: &str) -> Option<&'a RegistryModel> {
    preset.models.iter().find(|entry| entry.name == model)
}

/// Resolve the effective provider fields from operator config + registry.
///
/// Precedence: explicit config > named preset > built-in default. Registry
/// prices are only consulted when a provider is named; a config that names no
/// provider keeps today's behavior exactly (default endpoint, no capabilities,
/// prices only from config).
#[allow(clippy::too_many_arguments)]
pub fn resolve(
    provider: Option<&str>,
    model: Option<&str>,
    protocol: Option<&str>,
    base_url: Option<&str>,
    api_key_env: Option<&str>,
    input_usd_per_mtok: Option<f64>,
    output_usd_per_mtok: Option<f64>,
) -> Result<ResolvedProvider> {
    if input_usd_per_mtok.is_some() != output_usd_per_mtok.is_some() {
        return Err(Error::Config(
            "model.input_usd_per_mtok and model.output_usd_per_mtok must be set together".into(),
        ));
    }
    let preset = match provider {
        Some(name) => Some(preset(name).ok_or_else(|| {
            Error::Config(format!(
                "unknown model.provider `{name}`; known providers: {}",
                presets()
                    .iter()
                    .map(|preset| preset.name)
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })?),
        None => None,
    };

    let (base_url, base_url_source) = match (base_url, preset) {
        (Some(url), _) => (url.to_string(), FieldSource::Explicit),
        (None, Some(preset)) => (preset.base_url.to_string(), FieldSource::Preset),
        (None, None) => match protocol {
            Some("ollama") => (
                "http://localhost:11434/v1".to_string(),
                FieldSource::Default,
            ),
            _ => (
                "https://api.openai.com/v1".to_string(),
                FieldSource::Default,
            ),
        },
    };

    let (api_key_env, api_key_env_source) = match (api_key_env, preset) {
        (Some(name), _) => (Some(name.to_string()), FieldSource::Explicit),
        (None, Some(preset)) => (
            preset.api_key_env.map(str::to_string),
            if preset.api_key_env.is_some() {
                FieldSource::Preset
            } else {
                FieldSource::Default
            },
        ),
        (None, None) => (None, FieldSource::Default),
    };
    if let Some(preset) = preset {
        if preset.requires_api_key && api_key_env.is_none() {
            return Err(Error::Config(format!(
                "provider `{}` requires model.api_key_env",
                preset.name
            )));
        }
    }

    let (input_usd_per_mtok, output_usd_per_mtok, price_source) =
        match (input_usd_per_mtok, output_usd_per_mtok) {
            (Some(input), Some(output)) => (Some(input), Some(output), PriceSource::Explicit),
            (None, None) => {
                let from_registry = preset
                    .as_ref()
                    .and_then(|preset| model.and_then(|model| preset_model(preset, model)))
                    .map(|entry| {
                        (
                            Some(entry.input_usd_per_mtok),
                            Some(entry.output_usd_per_mtok),
                            PriceSource::Registry(preset.as_ref().expect("preset").prices_as_of),
                        )
                    });
                match from_registry {
                    Some((input, output, source)) => (input, output, source),
                    None => (None, None, PriceSource::Absent),
                }
            }
            // The mixed case is rejected above; this arm cannot be reached.
            _ => (None, None, PriceSource::Absent),
        };

    let capabilities = preset
        .as_ref()
        .and_then(|preset| model.and_then(|model| preset_model(preset, model)));
    if let Some(capabilities) = capabilities {
        if !capabilities.supports_tools {
            return Err(Error::Config(format!(
                "model `{}` on provider `{}` does not support tool calling; Pangu requires it",
                capabilities.name,
                preset.as_ref().expect("preset").name
            )));
        }
    }

    Ok(ResolvedProvider {
        preset,
        model: model.map(str::to_string),
        base_url,
        base_url_source,
        api_key_env,
        api_key_env_source,
        input_usd_per_mtok,
        output_usd_per_mtok,
        price_source,
        capabilities,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_data_is_well_formed() {
        assert!(!REGISTRY_VERSION.is_empty());
        let mut names = Vec::new();
        for preset in presets() {
            assert!(
                preset.protocol == "openai-compatible",
                "no new wire protocols"
            );
            assert!(!preset.base_url.is_empty());
            assert!(!preset.prices_as_of.is_empty());
            assert!(
                preset.requires_api_key == preset.api_key_env.is_some(),
                "requires_api_key must match api_key_env presence"
            );
            assert!(!names.contains(&preset.name), "duplicate preset name");
            names.push(preset.name);
            let mut model_names = Vec::new();
            for model in preset.models {
                assert!(!model_names.contains(&model.name), "duplicate model name");
                model_names.push(model.name);
                assert!(model.context_window_tokens > 0);
                assert!(model.max_output_tokens > 0);
                assert!(
                    model.input_usd_per_mtok > 0.0 && model.output_usd_per_mtok > 0.0,
                    "a zero price would silently disable the cost gate"
                );
            }
        }
    }

    #[test]
    fn explicit_config_wins_over_preset() {
        let resolved = resolve(
            Some("deepseek"),
            Some("deepseek-chat"),
            None,
            Some("https://example.invalid/v1"),
            Some("MY_KEY"),
            Some(9.0),
            Some(9.0),
        )
        .expect("resolve");
        assert_eq!(resolved.base_url, "https://example.invalid/v1");
        assert_eq!(resolved.base_url_source, FieldSource::Explicit);
        assert_eq!(resolved.api_key_env.as_deref(), Some("MY_KEY"));
        assert_eq!(resolved.input_usd_per_mtok, Some(9.0));
        assert_eq!(resolved.price_source, PriceSource::Explicit);
    }

    #[test]
    fn named_preset_fills_absent_fields_and_prices() {
        let resolved = resolve(
            Some("openai"),
            Some("gpt-4o-mini"),
            None,
            None,
            None,
            None,
            None,
        )
        .expect("resolve");
        assert_eq!(resolved.base_url, "https://api.openai.com/v1");
        assert_eq!(resolved.base_url_source, FieldSource::Preset);
        assert_eq!(resolved.api_key_env.as_deref(), Some("OPENAI_API_KEY"));
        assert_eq!(resolved.input_usd_per_mtok, Some(0.15));
        assert_eq!(resolved.output_usd_per_mtok, Some(0.60));
        assert_eq!(resolved.price_source, PriceSource::Registry("2025-06"));
        let capabilities = resolved.capabilities.expect("known model");
        assert_eq!(capabilities.context_window_tokens, 128_000);
        assert!(capabilities.supports_tools);
    }

    #[test]
    fn unnamed_provider_keeps_legacy_behavior() {
        // No provider named: today's defaults, no registry prices even for a
        // known model name, no capabilities.
        let resolved =
            resolve(None, Some("gpt-4o-mini"), None, None, None, None, None).expect("resolve");
        assert!(resolved.preset.is_none());
        assert_eq!(resolved.base_url, "https://api.openai.com/v1");
        assert_eq!(resolved.input_usd_per_mtok, None);
        assert!(resolved.capabilities.is_none());

        let ollama = resolve(None, None, Some("ollama"), None, None, None, None).expect("resolve");
        assert_eq!(ollama.base_url, "http://localhost:11434/v1");
        assert!(ollama.api_key_env.is_none());
    }

    #[test]
    fn unknown_provider_and_unknown_model_fail_closed() {
        let error = resolve(Some("nope"), None, None, None, None, None, None)
            .expect_err("unknown provider");
        assert!(error.to_string().contains("known providers"));

        // Known provider, unknown model: allowed, but no registry prices —
        // the run then fails closed under G4 unless prices are explicit.
        let resolved = resolve(
            Some("openai"),
            Some("gpt-9x-future"),
            None,
            None,
            None,
            None,
            None,
        )
        .expect("unknown model is allowed");
        assert!(resolved.capabilities.is_none());
        assert_eq!(resolved.price_source, PriceSource::Absent);
    }

    #[test]
    fn mixed_prices_and_missing_keys_fail_at_config_time() {
        let error = resolve(Some("openai"), None, None, None, None, Some(1.0), None)
            .expect_err("mixed prices");
        assert!(error.to_string().contains("must be set together"));

        // A keyed preset fills its own key variable, so this resolves — the
        // requires_api_key defense only fires for inconsistent preset data.
        let resolved = resolve(Some("openai"), None, None, None, None, None, None)
            .expect("preset key variable fills in");
        assert_eq!(resolved.api_key_env.as_deref(), Some("OPENAI_API_KEY"));

        // Ollama needs no key.
        resolve(Some("ollama"), None, None, None, None, None, None).expect("ollama needs no key");
    }

    #[test]
    fn toolless_model_is_rejected_for_this_agent() {
        let error = resolve(
            Some("deepseek"),
            Some("deepseek-reasoner"),
            None,
            None,
            None,
            None,
            None,
        )
        .expect_err("reasoner had no tool support as of the table date");
        assert!(error.to_string().contains("does not support tool calling"));
    }
}
