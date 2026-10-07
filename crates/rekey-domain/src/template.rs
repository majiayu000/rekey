//! Pure provider-template foundation for v3. Signature verification, persistence,
//! body-schema loading, policy signing and execution belong to their owning layers.
//! A rendered request includes its normalized path parameters and sorted query so
//! the approval layer can include both in its existing JCS envelope.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::DomainError;
use crate::action::{
    ActionName, ExactPath, FixedMethod, HeaderCredentialUse, HeaderName, HeaderPrefix, HttpsOrigin,
};
use crate::credential::CredentialKind;

pub type TemplateValues = BTreeMap<String, String>;

fn invalid(message: &str) -> DomainError {
    DomainError::InvalidActionDefinition(message.to_owned())
}

// Unreserved ASCII needs no URL escaping and cannot introduce a new segment or
// query key. In particular, do not decode percent escapes before this check.
fn safe_value(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Shared ASCII slug grammar for declaration names and individual path segments.
pub fn slug(value: &str, max: usize) -> bool {
    safe_value(value) && value.len() <= max && value.as_bytes()[0].is_ascii_alphanumeric()
}

/// Closed grammar from the template declaration, serialized as `slug`,
/// `int:a..b`, or `enum:a,b`. Integers use signed decimal i64 bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueRule {
    Slug,
    Int { min: i64, max: i64 },
    Enum(Vec<String>),
}

impl ValueRule {
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        let rule = if raw == "slug" {
            Self::Slug
        } else if let Some(range) = raw.strip_prefix("int:") {
            let (min, max) = range
                .split_once("..")
                .ok_or_else(|| invalid("invalid integer rule"))?;
            Self::Int {
                min: decimal(min)?,
                max: decimal(max)?,
            }
        } else if let Some(values) = raw.strip_prefix("enum:") {
            Self::Enum(values.split(',').map(str::to_owned).collect())
        } else {
            return Err(invalid("unsupported template value rule"));
        };
        rule.validate()?;
        Ok(rule)
    }

    fn validate(&self) -> Result<(), DomainError> {
        match self {
            Self::Int { min, max } if min > max => Err(invalid("reversed integer bounds")),
            Self::Enum(values)
                if values.is_empty()
                    || values.iter().any(|v| !safe_value(v))
                    || values.iter().collect::<BTreeSet<_>>().len() != values.len() =>
            {
                Err(invalid("enum values must be unique safe segments"))
            }
            _ => Ok(()),
        }
    }

    fn normalize(&self, value: &str) -> Result<String, DomainError> {
        if !safe_value(value) {
            return Err(invalid("template value is not a safe ASCII segment"));
        }
        match self {
            Self::Slug if slug(value, 100) => Ok(value.to_owned()),
            Self::Int { min, max } => {
                let number = decimal(value)?;
                if number < *min || number > *max {
                    return Err(invalid("template integer is outside its bounds"));
                }
                Ok(number.to_string())
            }
            Self::Enum(values) if values.iter().any(|v| v == value) => Ok(value.to_owned()),
            _ => Err(invalid("template value violates its rule")),
        }
    }
}

fn decimal(raw: &str) -> Result<i64, DomainError> {
    let digits = raw.strip_prefix('-').unwrap_or(raw);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid("integer must contain only decimal ASCII digits"));
    }
    raw.parse().map_err(|_| invalid("integer is out of range"))
}

impl Serialize for ValueRule {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let text = match self {
            Self::Slug => "slug".to_owned(),
            Self::Int { min, max } => format!("int:{min}..{max}"),
            Self::Enum(values) => format!("enum:{}", values.join(",")),
        };
        serializer.serialize_str(&text)
    }
}

impl<'de> Deserialize<'de> for ValueRule {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingRule {
    #[serde(rename = "type")]
    pub rule: ValueRule,
    /// Optional tighter slug bound, e.g. GitHub owner=39; never above 100.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateInjection {
    pub header: HeaderName,
    pub prefix: HeaderPrefix,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateCredential {
    pub kind: CredentialKind,
    pub inject: TemplateInjection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DefaultRule {
    Allow,
    RequireApproval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TemplateApprover {
    LocalPresence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefaultPolicy {
    pub rule: DefaultRule,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approver: Option<TemplateApprover>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateAction {
    pub method: FixedMethod,
    pub path: String,
    #[serde(default)]
    pub params: BTreeMap<String, ValueRule>,
    /// Query keys are optional; supplied keys must be declared and valid.
    #[serde(default)]
    pub query: BTreeMap<String, ValueRule>,
    /// A declaration only: this pure module does not load a schema or inspect a body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_schema: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateCapability {
    pub id: String,
    pub risk: Risk,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_rule: Option<DefaultRule>,
    pub actions: Vec<TemplateAction>,
}

impl TemplateCapability {
    pub fn default_policy(&self) -> DefaultPolicy {
        let rule = self.default_rule.unwrap_or(match self.risk {
            Risk::Low | Risk::Medium => DefaultRule::Allow,
            Risk::High => DefaultRule::RequireApproval,
        });
        DefaultPolicy {
            rule,
            approver: (rule == DefaultRule::RequireApproval)
                .then_some(TemplateApprover::LocalPresence),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateDefinition {
    pub template: String,
    pub display: ActionName,
    pub credential: TemplateCredential,
    pub origin: HttpsOrigin,
    #[serde(default)]
    pub fixed_headers: BTreeMap<HeaderName, String>,
    #[serde(default)]
    pub bindings: BTreeMap<String, BindingRule>,
    pub capabilities: Vec<TemplateCapability>,
}

/// Validated declaration. Mutation requires constructing and validating a new one.
#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
pub struct ProviderTemplate(TemplateDefinition);

impl<'de> Deserialize<'de> for ProviderTemplate {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::try_from(TemplateDefinition::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}

impl TryFrom<TemplateDefinition> for ProviderTemplate {
    type Error = DomainError;

    fn try_from(value: TemplateDefinition) -> Result<Self, Self::Error> {
        validate_template_id(&value.template)?;
        if value.capabilities.is_empty() {
            return Err(invalid("invalid template name, version, or capabilities"));
        }
        validate_headers(&value.credential, &value.fixed_headers)?;
        for (name, binding) in &value.bindings {
            if !slug(name, 100)
                || binding
                    .max
                    .is_some_and(|max| binding.rule != ValueRule::Slug || !(1..=100).contains(&max))
            {
                return Err(invalid("invalid binding name or slug bound"));
            }
            binding.rule.validate()?;
        }
        let mut ids = BTreeSet::new();
        let mut action_count = 0;
        for capability in &value.capabilities {
            if !slug(&capability.id, 100)
                || !ids.insert(&capability.id)
                || capability.actions.is_empty()
            {
                return Err(invalid("capabilities must have unique ids and actions"));
            }
            for action in &capability.actions {
                action_count += 1;
                if action
                    .params
                    .keys()
                    .any(|key| value.bindings.contains_key(key))
                {
                    return Err(invalid("agent parameters cannot shadow admin bindings"));
                }
                validate_target(&action.path, &action.params, &action.query, |name| {
                    value.bindings.contains_key(name)
                })?;
            }
        }
        if value.template == "generic-bearer@1"
            && (action_count > 20
                || !value.bindings.is_empty()
                || value.capabilities.iter().flat_map(|c| &c.actions).any(|a| {
                    !a.params.is_empty() || !a.query.is_empty() || a.path.contains(['{', '}'])
                }))
        {
            return Err(invalid(
                "generic-bearer requires 1-20 fixed actions without parameters",
            ));
        }
        Ok(Self(value))
    }
}

fn placeholder(segment: &str) -> Option<&str> {
    segment.strip_prefix('{')?.strip_suffix('}')
}

pub(crate) fn validate_template_id(id: &str) -> Result<(), DomainError> {
    let (name, version) = id
        .split_once('@')
        .ok_or_else(|| invalid("template must have a version"))?;
    if !slug(name, 100) || decimal(version)? < 1 {
        return Err(invalid("invalid template name, version, or capabilities"));
    }
    Ok(())
}

pub(crate) fn validate_headers(
    credential: &TemplateCredential,
    headers: &BTreeMap<HeaderName, String>,
) -> Result<(), DomainError> {
    if credential.kind != CredentialKind::OpaqueToken {
        return Err(invalid(
            "provider templates require opaque-token credentials",
        ));
    }
    let injection = &credential.inject;
    HeaderCredentialUse::new(injection.header.clone(), injection.prefix.clone())?;
    for (header, content) in headers {
        if header.is_forbidden()
            || *header == injection.header
            || header.as_str() == "authorization"
            || !content.bytes().all(|b| (0x20..=0x7e).contains(&b))
        {
            return Err(invalid("invalid fixed template header"));
        }
    }
    Ok(())
}

fn validate_target(
    path: &str,
    params: &BTreeMap<String, ValueRule>,
    query: &BTreeMap<String, ValueRule>,
    is_binding: impl Fn(&str) -> bool,
) -> Result<(), DomainError> {
    for (name, rule) in params.iter().chain(query) {
        if !slug(name, 100) {
            return Err(invalid("invalid parameter or query name"));
        }
        rule.validate()?;
    }
    let mut used = BTreeSet::new();
    let mut skeleton = Vec::new();
    for segment in path.split('/') {
        if let Some(name) = placeholder(segment) {
            if !params.contains_key(name) && !is_binding(name) {
                return Err(invalid("undeclared path placeholder"));
            }
            used.insert(name);
            skeleton.push("x");
        } else {
            if !segment.is_ascii() || segment.contains(['{', '}', '*', '%']) {
                return Err(invalid(
                    "path contains a wildcard, escape, or invalid placeholder",
                ));
            }
            skeleton.push(segment);
        }
    }
    if params.keys().any(|name| !used.contains(name.as_str())) {
        return Err(invalid("path parameter is not used in the path"));
    }
    ExactPath::parse(&skeleton.join("/"))?;
    Ok(())
}

impl ProviderTemplate {
    pub fn definition(&self) -> &TemplateDefinition {
        &self.0
    }

    /// Call once per administrator-supplied binding group. All bindings are required.
    pub fn bind(&self, values: &TemplateValues) -> Result<BoundTemplate, DomainError> {
        if values.len() != self.0.bindings.len() {
            return Err(invalid("missing or undeclared admin binding"));
        }
        let mut bindings = BTreeMap::new();
        for (name, value) in values {
            let rule = self
                .0
                .bindings
                .get(name)
                .ok_or_else(|| invalid("undeclared admin binding"))?;
            let normalized = rule.rule.normalize(value)?;
            if rule.max.is_some_and(|max| normalized.len() > max) {
                return Err(invalid("admin binding exceeds its slug bound"));
            }
            bindings.insert(name.clone(), normalized);
        }
        Ok(BoundTemplate {
            template: self.clone(),
            bindings,
        })
    }
}

/// Immutable administrator bindings; rendering cannot override these values.
#[derive(Debug, Clone)]
pub struct BoundTemplate {
    template: ProviderTemplate,
    bindings: TemplateValues,
}

/// One persisted path pattern after administrator bindings have become literals.
/// Only the declared per-call parameters and query keys remain variable.
#[derive(Debug, Clone, Serialize)]
pub struct TemplateTarget {
    path: String,
    params: BTreeMap<String, ValueRule>,
    query: BTreeMap<String, ValueRule>,
}

impl<'de> Deserialize<'de> for TemplateTarget {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Target {
            path: String,
            params: BTreeMap<String, ValueRule>,
            query: BTreeMap<String, ValueRule>,
        }
        let target = Target::deserialize(deserializer)?;
        Self::new(target.path, target.params, target.query).map_err(serde::de::Error::custom)
    }
}

impl TemplateTarget {
    fn new(
        path: String,
        params: BTreeMap<String, ValueRule>,
        query: BTreeMap<String, ValueRule>,
    ) -> Result<Self, DomainError> {
        validate_target(&path, &params, &query, |_| false)?;
        Ok(Self {
            path,
            params,
            query,
        })
    }

    pub fn path_pattern(&self) -> &str {
        &self.path
    }

    pub fn params(&self) -> &BTreeMap<String, ValueRule> {
        &self.params
    }

    pub fn query(&self) -> &BTreeMap<String, ValueRule> {
        &self.query
    }

    /// Every path parameter is required. Query keys are optional. No bindings,
    /// headers, origin or method can be supplied through this rendering API.
    pub fn render(
        &self,
        params: &TemplateValues,
        query: &TemplateValues,
    ) -> Result<RenderedTarget, DomainError> {
        if params.len() != self.params.len() {
            return Err(invalid("missing or undeclared path parameter"));
        }
        let normalize = |values: &TemplateValues, rules: &BTreeMap<String, ValueRule>| {
            values
                .iter()
                .map(|(name, value)| {
                    let rule = rules
                        .get(name)
                        .ok_or_else(|| invalid("undeclared parameter or query key"))?;
                    Ok((name.clone(), rule.normalize(value)?))
                })
                .collect::<Result<TemplateValues, DomainError>>()
        };
        let params = normalize(params, &self.params)?;
        let query = normalize(query, &self.query)?;
        let path = self
            .path
            .split('/')
            .map(|segment| {
                placeholder(segment).map_or(segment, |name| {
                    params
                        .get(name)
                        .expect("validated target has complete parameters")
                })
            })
            .collect::<Vec<_>>()
            .join("/");
        // Retain the existing final-path bound after expanding validated values.
        let path = ExactPath::parse(&path)?;
        Ok(RenderedTarget {
            path,
            params,
            query,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RenderedTarget {
    pub path: ExactPath,
    pub params: TemplateValues,
    pub query: TemplateValues,
}

impl RenderedTarget {
    pub fn request_target(&self) -> String {
        request_target(&self.path, &self.query)
    }
}

/// Data for a single Action adapter. This is neither a signature nor a source
/// digest: the installing layer must authenticate the template/schema package.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializedActionDefinition {
    pub template: String,
    pub capability: String,
    pub action_index: usize,
    pub origin: HttpsOrigin,
    pub method: FixedMethod,
    pub target: TemplateTarget,
    pub fixed_headers: BTreeMap<HeaderName, String>,
    pub credential: TemplateCredential,
    pub default_policy: DefaultPolicy,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_schema: Option<String>,
}

/// Validated single-action materialization, independent of the original template.
#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
pub struct MaterializedAction(MaterializedActionDefinition);

impl<'de> Deserialize<'de> for MaterializedAction {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::try_from(MaterializedActionDefinition::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}

impl TryFrom<MaterializedActionDefinition> for MaterializedAction {
    type Error = DomainError;

    fn try_from(value: MaterializedActionDefinition) -> Result<Self, Self::Error> {
        validate_template_id(&value.template)?;
        if !slug(&value.capability, 100) {
            return Err(invalid("invalid template capability"));
        }
        validate_headers(&value.credential, &value.fixed_headers)?;
        let approver = (value.default_policy.rule == DefaultRule::RequireApproval)
            .then_some(TemplateApprover::LocalPresence);
        if value.default_policy.approver != approver {
            return Err(invalid("invalid template default policy"));
        }
        Ok(Self(value))
    }
}

impl MaterializedAction {
    pub fn definition(&self) -> &MaterializedActionDefinition {
        &self.0
    }

    pub fn render(
        &self,
        params: &TemplateValues,
        query: &TemplateValues,
    ) -> Result<RenderedRequest, DomainError> {
        let definition = &self.0;
        let target = definition.target.render(params, query)?;
        Ok(RenderedRequest {
            template: definition.template.clone(),
            capability: definition.capability.clone(),
            action_index: definition.action_index,
            origin: definition.origin.clone(),
            method: definition.method,
            path: target.path,
            fixed_headers: definition.fixed_headers.clone(),
            credential: definition.credential.clone(),
            params: target.params,
            query: target.query,
            default_policy: definition.default_policy.clone(),
            body_schema: definition.body_schema.clone(),
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RenderedRequest {
    pub template: String,
    pub capability: String,
    pub action_index: usize,
    pub origin: HttpsOrigin,
    pub method: FixedMethod,
    pub path: ExactPath,
    pub fixed_headers: BTreeMap<HeaderName, String>,
    pub credential: TemplateCredential,
    pub params: TemplateValues,
    pub query: TemplateValues,
    pub default_policy: DefaultPolicy,
    pub body_schema: Option<String>,
}

impl RenderedRequest {
    /// Values and keys are already validated unreserved ASCII. Sorting is the
    /// same BTreeMap order serialized into the approval request object.
    pub fn request_target(&self) -> String {
        request_target(&self.path, &self.query)
    }
}

fn request_target(path: &ExactPath, query: &TemplateValues) -> String {
    if query.is_empty() {
        path.as_str().to_owned()
    } else {
        format!(
            "{}?{}",
            path.as_str(),
            query
                .iter()
                .map(|(key, value)| format!("{key}={}", encode_query_value(value)))
                .collect::<Vec<_>>()
                .join("&")
        )
    }
}

// RFC3986 unreserved bytes retain the existing template rendering. Other bytes
// cannot introduce query keys, delimiters, or a fragment in local CALL values.
fn encode_query_value(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    const HEX: &[u8] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(byte));
        } else {
            output.push('%');
            output.push(char::from(HEX[(byte >> 4) as usize]));
            output.push(char::from(HEX[(byte & 15) as usize]));
        }
    }
    output
}

impl BoundTemplate {
    /// Select exactly one action and permanently substitute administrator bindings.
    /// No unrelated capabilities or unbound template are retained in the result.
    pub fn materialize(
        &self,
        capability_id: &str,
        action_index: usize,
    ) -> Result<MaterializedAction, DomainError> {
        let definition = &self.template.0;
        let capability = definition
            .capabilities
            .iter()
            .find(|c| c.id == capability_id)
            .ok_or_else(|| invalid("unknown template capability"))?;
        let action = capability
            .actions
            .get(action_index)
            .ok_or_else(|| invalid("unknown template action"))?;
        let path = action
            .path
            .split('/')
            .map(|segment| {
                placeholder(segment).map_or(segment, |name| {
                    self.bindings.get(name).map_or(segment, String::as_str)
                })
            })
            .collect::<Vec<_>>()
            .join("/");
        let target = TemplateTarget::new(path, action.params.clone(), action.query.clone())?;
        Ok(MaterializedAction(MaterializedActionDefinition {
            template: definition.template.clone(),
            capability: capability.id.clone(),
            action_index,
            origin: definition.origin.clone(),
            method: action.method,
            target,
            fixed_headers: definition.fixed_headers.clone(),
            credential: definition.credential.clone(),
            default_policy: capability.default_policy(),
            body_schema: action.body_schema.clone(),
        }))
    }

    /// Render through the same validated target used by persisted materializations.
    pub fn render(
        &self,
        capability_id: &str,
        action_index: usize,
        params: &TemplateValues,
        query: &TemplateValues,
    ) -> Result<RenderedRequest, DomainError> {
        self.materialize(capability_id, action_index)?
            .render(params, query)
    }
}

fn builtin(json: &str) -> Result<ProviderTemplate, DomainError> {
    serde_json::from_str(json).map_err(|_| invalid("invalid built-in provider template"))
}

pub fn anthropic() -> Result<ProviderTemplate, DomainError> {
    builtin(
        r#"{
      "template":"anthropic@1","display":"Anthropic",
      "credential":{"kind":"opaque-token","inject":{"header":"x-api-key","prefix":""}},
      "origin":"https://api.anthropic.com","fixed_headers":{"anthropic-version":"2023-06-01"},
      "capabilities":[
        {"id":"messages","risk":"medium","actions":[{"method":"POST","path":"/v1/messages","query":{"beta":"enum:true"}}]},
        {"id":"count-tokens","risk":"low","actions":[{"method":"POST","path":"/v1/messages/count_tokens","query":{"beta":"enum:true"}}]},
        {"id":"models","risk":"low","actions":[{"method":"GET","path":"/v1/models"}]}
      ]}"#,
    )
}

pub fn glm() -> Result<ProviderTemplate, DomainError> {
    builtin(
        r#"{
      "template":"glm@1","display":"GLM",
      "credential":{"kind":"opaque-token","inject":{"header":"x-api-key","prefix":""}},
      "origin":"https://open.bigmodel.cn","fixed_headers":{"anthropic-version":"2023-06-01"},
      "capabilities":[
        {"id":"messages","risk":"medium","actions":[{"method":"POST","path":"/api/anthropic/v1/messages","query":{"beta":"enum:true"}}]}
      ]}"#,
    )
}

pub fn glm_responses() -> Result<ProviderTemplate, DomainError> {
    builtin(
        r#"{
      "template":"glm-responses@1","display":"GLM（Responses）",
      "credential":{"kind":"opaque-token","inject":{"header":"authorization","prefix":"Bearer "}},
      "origin":"https://open.bigmodel.cn",
      "capabilities":[
        {"id":"responses","risk":"medium","actions":[{"method":"POST","path":"/api/v1/responses"}]}
      ]}"#,
    )
}

pub fn openai() -> Result<ProviderTemplate, DomainError> {
    builtin(
        r#"{
      "template":"openai@1","display":"OpenAI",
      "credential":{"kind":"opaque-token","inject":{"header":"authorization","prefix":"Bearer "}},
      "origin":"https://api.openai.com",
      "capabilities":[
        {"id":"chat-completions","risk":"medium","actions":[{"method":"POST","path":"/v1/chat/completions"}]},
        {"id":"responses","risk":"medium","actions":[{"method":"POST","path":"/v1/responses"}]},
        {"id":"embeddings","risk":"medium","actions":[{"method":"POST","path":"/v1/embeddings"}]},
        {"id":"models","risk":"low","actions":[{"method":"GET","path":"/v1/models"}]}
      ]}"#,
    )
}

/// Contents uses a single slug segment; arbitrary nested repository paths are
/// deliberately outside the closed parameter grammar in §7.2.
pub fn github_pat() -> Result<ProviderTemplate, DomainError> {
    builtin(
        r#"{
      "template":"github-pat@1","display":"GitHub（个人访问令牌）",
      "credential":{"kind":"opaque-token","inject":{"header":"authorization","prefix":"Bearer "}},
      "origin":"https://api.github.com",
      "fixed_headers":{"accept":"application/vnd.github+json","x-github-api-version":"2022-11-28"},
      "bindings":{"owner":{"type":"slug","max":39},"repo":{"type":"slug","max":100}},
      "capabilities":[
        {"id":"read-repo","risk":"low","actions":[
          {"method":"GET","path":"/repos/{owner}/{repo}"},
          {"method":"GET","path":"/repos/{owner}/{repo}/issues","query":{"state":"enum:open,closed,all","per_page":"int:1..100","page":"int:1..1000"}},
          {"method":"GET","path":"/repos/{owner}/{repo}/pulls/{number}","params":{"number":"int:1..2147483647"}},
          {"method":"GET","path":"/repos/{owner}/{repo}/issues/{number}/comments","params":{"number":"int:1..2147483647"}},
          {"method":"GET","path":"/repos/{owner}/{repo}/labels"},
          {"method":"GET","path":"/repos/{owner}/{repo}/contents"},
          {"method":"GET","path":"/repos/{owner}/{repo}/contents/{path}","params":{"path":"slug"}}
        ]},
        {"id":"create-issue","risk":"medium","actions":[{"method":"POST","path":"/repos/{owner}/{repo}/issues","body_schema":"schemas/github-create-issue.json"}]},
        {"id":"merge-pr","risk":"high","default_rule":"require-approval","actions":[{"method":"PUT","path":"/repos/{owner}/{repo}/pulls/{number}/merge","params":{"number":"int:1..2147483647"}}]}
      ]}"#,
    )
}

/// User-selected origin and 1–20 exact actions are fixed at installation time.
pub fn generic_bearer(
    origin: HttpsOrigin,
    actions: Vec<(FixedMethod, ExactPath)>,
) -> Result<ProviderTemplate, DomainError> {
    ProviderTemplate::try_from(TemplateDefinition {
        template: "generic-bearer@1".to_owned(),
        display: ActionName::new("Generic Bearer")?,
        credential: TemplateCredential {
            kind: CredentialKind::OpaqueToken,
            inject: TemplateInjection {
                header: HeaderName::new("authorization")?,
                prefix: HeaderPrefix::new("Bearer ")?,
            },
        },
        origin,
        fixed_headers: BTreeMap::new(),
        bindings: BTreeMap::new(),
        capabilities: vec![TemplateCapability {
            id: "fixed-actions".to_owned(),
            risk: Risk::Medium,
            default_rule: None,
            actions: actions
                .into_iter()
                .map(|(method, path)| TemplateAction {
                    method,
                    path: path.as_str().to_owned(),
                    params: BTreeMap::new(),
                    query: BTreeMap::new(),
                    body_schema: None,
                })
                .collect(),
        }],
    })
}
