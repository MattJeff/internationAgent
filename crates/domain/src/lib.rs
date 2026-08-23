use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type EmployeeId = Uuid;
pub type TenantId = Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EmployeeStatus {
    Draft,
    Provisioning,
    Degraded,
    Online,
    Suspended,
    Failed,
    Terminated,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ProvisioningStep {
    Identity,
    Email,
    Phone,
    Whatsapp,
    Wallet,
    Browser,
    Vault,
    CompanyKnowledge,
    Mcp,
    A2a,
    Permissions,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResourceState {
    Pending,
    Provisioning,
    Ready,
    PendingExternal,
    Failed,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceStatus {
    pub step: ProvisioningStep,
    pub state: ResourceState,
    pub provider: Option<String>,
    pub external_id: Option<String>,
    pub message: Option<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Employee {
    pub id: EmployeeId,
    pub tenant_id: TenantId,
    pub display_name: String,
    pub slug: String,
    pub role: String,
    pub objective: String,
    pub status: EmployeeStatus,
    pub address: String,
    pub did: String,
    pub resources: Vec<ResourceStatus>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Employee {
    pub fn new(
        tenant_id: TenantId,
        display_name: String,
        slug: String,
        role: String,
        objective: String,
        email_domain: &str,
        public_host: &str,
    ) -> Self {
        let now = Utc::now();
        let id = Uuid::now_v7();
        let steps = [
            ProvisioningStep::Identity,
            ProvisioningStep::Email,
            ProvisioningStep::Phone,
            ProvisioningStep::Whatsapp,
            ProvisioningStep::Wallet,
            ProvisioningStep::Browser,
            ProvisioningStep::Vault,
            ProvisioningStep::CompanyKnowledge,
            ProvisioningStep::Mcp,
            ProvisioningStep::A2a,
            ProvisioningStep::Permissions,
        ];
        Self {
            id,
            tenant_id,
            display_name,
            slug: slug.clone(),
            role,
            objective,
            status: EmployeeStatus::Draft,
            address: format!("{slug}@{email_domain}"),
            did: format!("did:web:{public_host}:employees:{id}"),
            resources: steps
                .into_iter()
                .map(|step| ResourceStatus {
                    step,
                    state: ResourceState::Pending,
                    provider: None,
                    external_id: None,
                    message: None,
                    updated_at: now,
                })
                .collect(),
            created_at: now,
            updated_at: now,
        }
    }

    pub fn set_resource(
        &mut self,
        step: ProvisioningStep,
        state: ResourceState,
        provider: Option<String>,
        external_id: Option<String>,
        message: Option<String>,
    ) {
        if let Some(r) = self.resources.iter_mut().find(|r| r.step == step) {
            r.state = state;
            r.provider = provider;
            r.external_id = external_id;
            r.message = message;
            r.updated_at = Utc::now();
        }
        self.updated_at = Utc::now();
        self.recompute_status();
    }

    pub fn recompute_status(&mut self) {
        use ResourceState::*;
        let blocking = [
            ProvisioningStep::Identity,
            ProvisioningStep::Email,
            ProvisioningStep::Vault,
            ProvisioningStep::CompanyKnowledge,
            ProvisioningStep::Permissions,
            ProvisioningStep::A2a,
        ];

        let has_blocking_failure = self.resources.iter().any(|r| {
            blocking.contains(&r.step) && r.state == Failed
        });
        if has_blocking_failure {
            self.status = EmployeeStatus::Failed;
            return;
        }

        let blocking_ready = self.resources.iter().filter(|r| blocking.contains(&r.step))
            .all(|r| r.state == Ready);

        let optional_not_ready = self.resources.iter().filter(|r| !blocking.contains(&r.step))
            .any(|r| !matches!(r.state, Ready | Disabled));

        self.status = if blocking_ready && optional_not_ready {
            EmployeeStatus::Degraded
        } else if blocking_ready {
            EmployeeStatus::Online
        } else {
            EmployeeStatus::Provisioning
        };
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendPolicy {
    pub currency: String,
    pub max_per_transaction_minor: i64,
    pub max_per_day_minor: i64,
    pub approval_above_minor: i64,
    pub allowed_merchant_categories: Vec<String>,
    pub denied_merchant_categories: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunicationPolicy {
    pub allowed_countries: Vec<String>,
    pub allowed_channels: Vec<String>,
    pub allow_cold_outreach: bool,
    pub max_new_contacts_per_day: u32,
    pub require_recording_disclosure: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserPolicy {
    pub allowed_domains: Vec<String>,
    pub denied_domains: Vec<String>,
    pub allow_file_upload: bool,
    pub allow_purchase: bool,
    pub require_approval_for_auth_change: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmployeePolicy {
    pub spend: SpendPolicy,
    pub communications: CommunicationPolicy,
    pub browser: BrowserPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProposedAction {
    SendEmail { to: String },
    SendWhatsapp { to: String },
    Call { to: String, country: String },
    BrowserWrite { domain: String, operation: String },
    Payment { amount_minor: i64, currency: String, merchant: String },
    SignDocument { document_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow,
    Deny { reason: String },
    RequireApproval { reason: String },
}

pub fn evaluate(policy: &EmployeePolicy, action: &ProposedAction) -> PolicyDecision {
    match action {
        ProposedAction::Payment { amount_minor, currency, .. } => {
            if currency != &policy.spend.currency {
                return PolicyDecision::Deny { reason: "currency_not_allowed".into() };
            }
            if *amount_minor > policy.spend.max_per_transaction_minor {
                return PolicyDecision::Deny { reason: "per_transaction_limit".into() };
            }
            if *amount_minor >= policy.spend.approval_above_minor {
                return PolicyDecision::RequireApproval { reason: "payment_requires_approval".into() };
            }
            PolicyDecision::Allow
        }
        ProposedAction::Call { country, .. } => {
            if !policy.communications.allowed_countries.is_empty()
                && !policy.communications.allowed_countries.contains(country)
            {
                PolicyDecision::Deny { reason: "country_not_allowed".into() }
            } else {
                PolicyDecision::Allow
            }
        }
        ProposedAction::BrowserWrite { domain, .. } => {
            if policy.browser.denied_domains.iter().any(|d| d == domain) {
                PolicyDecision::Deny { reason: "domain_denied".into() }
            } else {
                PolicyDecision::Allow
            }
        }
        _ => PolicyDecision::Allow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lena() -> Employee {
        Employee::new(
            Uuid::now_v7(),
            "Lena".into(),
            "lena".into(),
            "international_buyer".into(),
            "source suppliers".into(),
            "agents.acme.com",
            "agents.acme.com",
        )
    }

    fn ready(e: &mut Employee, step: ProvisioningStep) {
        e.set_resource(step, ResourceState::Ready, None, None, None);
    }

    const BLOCKING: [ProvisioningStep; 6] = [
        ProvisioningStep::Identity,
        ProvisioningStep::Email,
        ProvisioningStep::Vault,
        ProvisioningStep::CompanyKnowledge,
        ProvisioningStep::Permissions,
        ProvisioningStep::A2a,
    ];

    #[test]
    fn status_reflects_resource_states() {
        let mut e = lena();
        assert_eq!(e.status, EmployeeStatus::Draft);

        // Blocking steps incomplete -> still provisioning.
        ready(&mut e, ProvisioningStep::Identity);
        assert_eq!(e.status, EmployeeStatus::Provisioning);

        // All blocking ready, WhatsApp still awaiting Meta -> degraded, Lena can work.
        for step in BLOCKING {
            ready(&mut e, step);
        }
        for step in [
            ProvisioningStep::Phone,
            ProvisioningStep::Wallet,
            ProvisioningStep::Browser,
            ProvisioningStep::Mcp,
        ] {
            ready(&mut e, step);
        }
        e.set_resource(
            ProvisioningStep::Whatsapp,
            ResourceState::PendingExternal,
            None,
            None,
            None,
        );
        assert_eq!(e.status, EmployeeStatus::Degraded);

        // Meta confirms -> online.
        ready(&mut e, ProvisioningStep::Whatsapp);
        assert_eq!(e.status, EmployeeStatus::Online);

        // A blocking failure outranks everything else.
        e.set_resource(ProvisioningStep::Vault, ResourceState::Failed, None, None, None);
        assert_eq!(e.status, EmployeeStatus::Failed);
    }

    fn policy() -> EmployeePolicy {
        EmployeePolicy {
            spend: SpendPolicy {
                currency: "USD".into(),
                max_per_transaction_minor: 50_000,
                max_per_day_minor: 200_000,
                approval_above_minor: 10_000,
                allowed_merchant_categories: vec![],
                denied_merchant_categories: vec![],
            },
            communications: CommunicationPolicy {
                allowed_countries: vec!["CN".into()],
                allowed_channels: vec!["email".into()],
                allow_cold_outreach: true,
                max_new_contacts_per_day: 20,
                require_recording_disclosure: true,
            },
            browser: BrowserPolicy {
                allowed_domains: vec![],
                denied_domains: vec!["banking.example.com".into()],
                allow_file_upload: false,
                allow_purchase: false,
                require_approval_for_auth_change: true,
            },
        }
    }

    fn pay(amount_minor: i64, currency: &str) -> ProposedAction {
        ProposedAction::Payment {
            amount_minor,
            currency: currency.into(),
            merchant: "supplier".into(),
        }
    }

    #[test]
    fn gate_guards_the_money_path() {
        let p = policy();
        assert!(matches!(evaluate(&p, &pay(5_000, "USD")), PolicyDecision::Allow));
        assert!(matches!(
            evaluate(&p, &pay(10_000, "USD")),
            PolicyDecision::RequireApproval { .. }
        ));
        assert!(matches!(evaluate(&p, &pay(60_000, "USD")), PolicyDecision::Deny { .. }));
        assert!(matches!(evaluate(&p, &pay(5_000, "EUR")), PolicyDecision::Deny { .. }));
    }

    #[test]
    fn gate_guards_calls_and_browser() {
        let p = policy();
        let call = |country: &str| ProposedAction::Call {
            to: "+8613800000000".into(),
            country: country.into(),
        };
        assert!(matches!(evaluate(&p, &call("CN")), PolicyDecision::Allow));
        assert!(matches!(evaluate(&p, &call("RU")), PolicyDecision::Deny { .. }));

        let write = |domain: &str| ProposedAction::BrowserWrite {
            domain: domain.into(),
            operation: "submit_form".into(),
        };
        assert!(matches!(evaluate(&p, &write("alibaba.com")), PolicyDecision::Allow));
        assert!(matches!(
            evaluate(&p, &write("banking.example.com")),
            PolicyDecision::Deny { .. }
        ));
    }
}
