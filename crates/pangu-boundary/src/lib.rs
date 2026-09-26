//! Executable boundary layer: L1 contract, L2 policy, L3 resources, and L4
//! approval. The crate owns decisions but never performs tool side effects.

pub mod approval;
pub mod budget;
pub mod config;
pub mod goal;
pub mod policy;
pub mod risk;
pub mod sandbox;

pub use approval::{
    ApprovalHandler, ApprovalMode, ApprovalRequest, ApprovalResponse, ScriptedApproval,
    StdinApproval, Unattended,
};
pub use budget::{Breach, Budget};
pub use config::{
    BoundaryConfig, BoundarySection, CheckpointBackend, CheckpointFailurePolicy, CheckpointSection,
    CliOverrides, Config, EnvSection,
};
pub use goal::{GoalContract, GoalStatus};
pub use policy::{ActionRequest, Decision, Effect, Policy, Rule};
pub use risk::Risk;
pub use sandbox::{ResolveOutcome, ResourceRequest, Sandbox, ValidatedResources};
