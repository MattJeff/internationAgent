use agentos_domain::{Employee, ProvisioningStep, ResourceState};
use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct ProvisionedResource {
    pub provider: String,
    pub external_id: Option<String>,
    pub message: Option<String>,
    pub pending_external: bool,
}

#[async_trait]
pub trait Provisioner: Send + Sync {
    fn step(&self) -> ProvisioningStep;
    async fn ensure(&self, employee: &Employee) -> Result<ProvisionedResource>;
    async fn compensate(&self, _employee: &Employee, _resource: &ProvisionedResource) -> Result<()> {
        Ok(())
    }
}

pub struct ProvisioningEngine {
    providers: Vec<Arc<dyn Provisioner>>,
}

impl ProvisioningEngine {
    pub fn new(providers: Vec<Arc<dyn Provisioner>>) -> Self {
        Self { providers }
    }

    pub async fn run(&self, employee: &mut Employee) {
        for provider in &self.providers {
            let step = provider.step();
            employee.set_resource(
                step.clone(),
                ResourceState::Provisioning,
                None,
                None,
                None,
            );

            match provider.ensure(employee).await {
                Ok(r) if r.pending_external => employee.set_resource(
                    step,
                    ResourceState::PendingExternal,
                    Some(r.provider),
                    r.external_id,
                    r.message,
                ),
                Ok(r) => employee.set_resource(
                    step,
                    ResourceState::Ready,
                    Some(r.provider),
                    r.external_id,
                    r.message,
                ),
                Err(err) => employee.set_resource(
                    step,
                    ResourceState::Failed,
                    None,
                    None,
                    Some(err.to_string()),
                ),
            }
        }
    }
}

pub struct MockProvisioner {
    step: ProvisioningStep,
    provider: &'static str,
    pending_external: bool,
}

impl MockProvisioner {
    pub fn ready(step: ProvisioningStep, provider: &'static str) -> Self {
        Self { step, provider, pending_external: false }
    }
    pub fn pending(step: ProvisioningStep, provider: &'static str) -> Self {
        Self { step, provider, pending_external: true }
    }
}

#[async_trait]
impl Provisioner for MockProvisioner {
    fn step(&self) -> ProvisioningStep {
        self.step.clone()
    }

    async fn ensure(&self, employee: &Employee) -> Result<ProvisionedResource> {
        Ok(ProvisionedResource {
            provider: self.provider.to_string(),
            external_id: Some(format!("{}:{}", self.provider, employee.id)),
            message: self.pending_external.then(|| "provider/compliance confirmation required".into()),
            pending_external: self.pending_external,
        })
    }
}
