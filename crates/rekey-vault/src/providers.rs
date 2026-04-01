pub struct ProviderConfig {
    pub host_pattern: &'static str,
    pub header_name: &'static str,
    pub value_format: &'static str,
    pub path_pattern: &'static str,
}

pub fn get_provider(name: &str) -> Option<ProviderConfig> {
    match name {
        "anthropic" => Some(ProviderConfig {
            host_pattern: "api.anthropic.com",
            header_name: "x-api-key",
            value_format: "{value}",
            path_pattern: "*",
        }),
        "openai" => Some(ProviderConfig {
            host_pattern: "api.openai.com",
            header_name: "authorization",
            value_format: "Bearer {value}",
            path_pattern: "*",
        }),
        "github" => Some(ProviderConfig {
            host_pattern: "api.github.com",
            header_name: "authorization",
            value_format: "Bearer {value}",
            path_pattern: "*",
        }),
        _ => None,
    }
}

pub fn all_provider_names() -> &'static [&'static str] {
    &["anthropic", "openai", "github"]
}
