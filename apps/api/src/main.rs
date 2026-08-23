use agentos_core::{MockProvisioner, ProvisioningEngine};
use agentos_domain::{Employee, ProvisioningStep, TenantId};
use axum::{extract::State, http::StatusCode, routing::{get, post}, Json, Router};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
use tower_http::trace::TraceLayer;
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    employees: Arc<RwLock<HashMap<Uuid, Employee>>>,
    engine: Arc<ProvisioningEngine>,
    email_domain: String,
    public_host: String,
}

#[derive(Debug, Deserialize)]
struct CreateEmployee {
    tenant_id: TenantId,
    display_name: String,
    slug: String,
    role: String,
    objective: String,
}

#[derive(Debug, Serialize)]
struct CreateEmployeeResponse {
    employee: Employee,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("agentos=debug,tower_http=info")
        .json()
        .init();

    let engine = ProvisioningEngine::new(vec![
        Arc::new(MockProvisioner::ready(ProvisioningStep::Identity, "did:web+kms")),
        Arc::new(MockProvisioner::ready(ProvisioningStep::Email, "resend")),
        Arc::new(MockProvisioner::pending(ProvisioningStep::Phone, "twilio")),
        Arc::new(MockProvisioner::pending(ProvisioningStep::Whatsapp, "twilio+meta")),
        Arc::new(MockProvisioner::ready(ProvisioningStep::Wallet, "kms-wallet")),
        Arc::new(MockProvisioner::ready(ProvisioningStep::Browser, "browser-provider")),
        Arc::new(MockProvisioner::ready(ProvisioningStep::Vault, "kms+vault")),
        Arc::new(MockProvisioner::ready(ProvisioningStep::CompanyKnowledge, "pgvector")),
        Arc::new(MockProvisioner::ready(ProvisioningStep::Mcp, "rmcp")),
        Arc::new(MockProvisioner::ready(ProvisioningStep::A2a, "a2a-v1")),
        Arc::new(MockProvisioner::ready(ProvisioningStep::Permissions, "policy-engine")),
    ]);

    let state = AppState {
        employees: Arc::new(RwLock::new(HashMap::new())),
        engine: Arc::new(engine),
        email_domain: std::env::var("AGENT_EMAIL_DOMAIN").unwrap_or_else(|_| "agents.example.com".into()),
        public_host: std::env::var("PUBLIC_HOST").unwrap_or_else(|_| "agents.example.com".into()),
    };

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/employees", post(create_employee))
        .route("/v1/employees/{id}", get(get_employee))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let bind = std::env::var("APP_BIND").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let listener = tokio::net::TcpListener::bind(&bind).await.unwrap();
    tracing::info!(%bind, "agentos api listening");
    axum::serve(listener, app).await.unwrap();
}

async fn create_employee(
    State(state): State<AppState>,
    Json(input): Json<CreateEmployee>,
) -> Result<(StatusCode, Json<CreateEmployeeResponse>), (StatusCode, String)> {
    let mut employee = Employee::new(
        input.tenant_id,
        input.display_name,
        input.slug,
        input.role,
        input.objective,
        &state.email_domain,
        &state.public_host,
    );

    state.engine.run(&mut employee).await;
    state.employees.write().await.insert(employee.id, employee.clone());

    Ok((StatusCode::CREATED, Json(CreateEmployeeResponse { employee })))
}

async fn get_employee(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> Result<Json<Employee>, StatusCode> {
    state.employees.read().await
        .get(&id)
        .cloned()
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}
