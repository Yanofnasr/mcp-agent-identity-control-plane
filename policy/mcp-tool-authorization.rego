package agent.mcp.authz

import rego.v1

# Reference authorization policy for MCP tool calls made by autonomous agents.
#
# Trust boundary:
# - input.request contains caller-controlled correlation and approval references.
# - input.verified is constructed by the policy enforcement point after identity,
#   delegation, token, action canonicalization, classification, and environment
#   verification.
# - data.agent_control and data.approval_records are trusted policy data.
# - evaluation time comes from OPA's clock, never from request input.
#
# The policy is the final enforcement gate after the target credential has been
# issued. A production design should also run a pre-issuance policy decision to
# derive the credential contract, then revalidate the issued credential and the
# unchanged action here before execution.

default allow := false

default requires_approval := false

default credential_profile := "none"

default credential_ttl_seconds := 0

default reason_codes := []

request_doc := object.get(input, "request", {})
verified_doc := object.get(input, "verified", {})

# P1: requesting principal
requester := object.get(verified_doc, "requester", {})

# P2: authority subject
authority_subject := object.get(verified_doc, "authority_subject", {})

# P3: agent principal
agent := object.get(verified_doc, "agent", {})

# P4: execution principal
execution := object.get(verified_doc, "execution", {})
action := object.get(verified_doc, "action", {})
context := object.get(verified_doc, "context", {})

server_config := object.get(
	data.agent_control.servers,
	object.get(action, "mcp_server", ""),
	{},
)

tool_config := object.get(
	object.get(server_config, "tools", {}),
	object.get(action, "tool", ""),
	{},
)

agent_entitlement := object.get(
	data.agent_control.entitlements,
	object.get(agent, "agent_principal", ""),
	{},
)

server_entitlement := object.get(
	object.get(agent_entitlement, "server_permissions", {}),
	object.get(action, "mcp_server", ""),
	{},
)

approval_id := object.get(request_doc, "approval_id", "")
approval_record := object.get(data.approval_records, approval_id, {})

agent_trust_config := object.get(
	object.get(data.agent_control, "trusted_agent_credentials", {}),
	object.get(agent, "agent_principal", ""),
	{},
)

now_ns := time.now_ns()

sha256_digest_valid(value) if {
	type_name(value) == "string"
	regex.match("^sha256:[a-f0-9]{64}$", value)
}

input_shape_valid if {
	input.schema_version == "1.3"
	count(request_doc) > 0
	count(verified_doc) > 0
}

request_context_valid if {
	object.get(request_doc, "session_id", "") != ""
	object.get(request_doc, "task_id", "") != ""
	object.get(request_doc, "correlation_id", "") != ""
}

context_valid if {
	context.environment in {"development", "test", "staging", "production"}
	sha256_digest_valid(context.policy_bundle_digest)
}

requester_valid if {
	requester.principal_id != ""
	requester.principal_type in {"human", "service", "workload"}
}

authority_subject_valid if {
	authority_subject.principal_id != ""
	authority_subject.principal_type in {"human", "service", "workload"}
	authority_subject.authority_basis in {
		"explicit_delegation",
		"organizational_mandate",
		"agent_own_authority",
		"service_delegation",
	}
}

agent_principal_format_valid if {
	startswith(agent.agent_principal, "spiffe://")
}

agent_principal_format_valid if {
	startswith(agent.agent_principal, "urn:")
}

agent_identity_valid if {
	agent_principal_format_valid
	agent.agent_definition_id != ""
	sha256_digest_valid(agent.agent_version)
	agent.runtime_instance_id != ""
	agent.credential_type != ""
	agent.credential_issuer != ""
	agent.attestation_profile != ""
	sha256_digest_valid(agent.credential_thumbprint)
	agent.credential_verified == true
}

agent_credential_type_trusted if {
	agent.credential_type in object.get(agent_trust_config, "credential_types", [])
}

agent_credential_issuer_trusted if {
	agent.credential_issuer in object.get(agent_trust_config, "credential_issuers", [])
}

agent_attestation_profile_trusted if {
	agent.attestation_profile in object.get(agent_trust_config, "attestation_profiles", [])
}

agent_credential_trust_valid if {
	agent_credential_type_trusted
	agent_credential_issuer_trusted
	agent_attestation_profile_trusted
}

agent_entitled if {
	count(agent_entitlement) > 0
}

authority_chain_valid if {
	execution.authority_chain_verified == true
	execution.authority_mode == "user_delegated"
	authority_subject.authority_basis == "explicit_delegation"
	authority_subject.principal_type in {"human", "service"}
	execution.authority_subject_principal_id == authority_subject.principal_id
	execution.agent_actor_principal_id == agent.agent_principal
}

authority_chain_valid if {
	execution.authority_chain_verified == true
	execution.authority_mode == "agent_own"
	authority_subject.authority_basis == "agent_own_authority"
	authority_subject.principal_type == "workload"
	authority_subject.principal_id == agent.agent_principal
	execution.authority_subject_principal_id == agent.agent_principal
	execution.agent_actor_principal_id == agent.agent_principal
}

authority_chain_valid if {
	execution.authority_chain_verified == true
	execution.authority_mode == "brokered_service"
	authority_subject.authority_basis in {"organizational_mandate", "service_delegation"}
	authority_subject.principal_type in {"service", "workload"}
	execution.authority_subject_principal_id == authority_subject.principal_id
	execution.agent_actor_principal_id == agent.agent_principal
}

canonical_action_string := concat("\n", [
	"agent-action-v1",
	sprintf("mcp_server=%s", [action.mcp_server]),
	sprintf("method=%s", [action.method]),
	sprintf("tool=%s", [action.tool]),
	sprintf("target=%s", [action.target]),
	sprintf("arguments_digest=%s", [action.arguments_digest]),
	sprintf("data_classification=%s", [action.data_classification]),
])

computed_action_hash := sprintf(
	"sha256:%s",
	[crypto.sha256(canonical_action_string)],
)

canonical_action_field_valid(value) if {
	type_name(value) == "string"
	value != ""
	not contains(value, "\n")
	not contains(value, "\r")
}

action_canonicalizable if {
	canonical_action_field_valid(action.mcp_server)
	canonical_action_field_valid(action.method)
	canonical_action_field_valid(action.tool)
	canonical_action_field_valid(action.target)
	canonical_action_field_valid(action.arguments_digest)
	sha256_digest_valid(action.arguments_digest)
	canonical_action_field_valid(action.data_classification)
	action.data_classification in {"public", "internal", "confidential", "restricted"}
}

action_hash_valid if {
	action.canonical_hash == computed_action_hash
}

method_allowed if {
	action.method in object.get(server_config, "allowed_methods", [])
}

tool_known if {
	count(tool_config) > 0
}

tool_allowed if {
	tool_known
	action.tool in object.get(server_entitlement, "allowed_tools", [])
}

target_matches(pattern, target) if {
	pattern == target
}

target_matches(pattern, target) if {
	endswith(pattern, "*")
	prefix := trim_suffix(pattern, "*")
	startswith(target, prefix)
}

target_allowed if {
	some pattern in object.get(server_entitlement, "allowed_targets", [])
	target_matches(pattern, action.target)
}

environment_allowed if {
	context.environment in object.get(agent_entitlement, "allowed_environments", [])
}

production_write_allowed if {
	context.environment != "production"
}

production_write_allowed if {
	context.environment == "production"
	object.get(tool_config, "write", false) == false
}

production_write_allowed if {
	context.environment == "production"
	object.get(tool_config, "write", false) == true
	object.get(server_entitlement, "production_write_allowed", false) == true
}

expected_audiences_for_target contains binding.audience if {
	some binding in object.get(server_config, "audience_bindings", [])
	target_matches(binding.target_pattern, action.target)
}

sole_expected_audience := audience if {
	matched_audiences := expected_audiences
	count(matched_audiences) == 1
	audience := matched_audiences[0]
}

execution_principal_allowed if {
	execution.principal_id in object.get(agent_entitlement, "allowed_execution_principals", [])
}

authority_mode_allowed if {
	execution.authority_mode in object.get(agent_entitlement, "allowed_authority_modes", [])
}

execution_issuer_trusted if {
	execution.issuer in object.get(server_config, "trusted_issuers", [])
}

execution_audience_bound_to_target if {
	count(expected_audiences) == 1
	count(execution.audiences) == 1
	execution.audiences[0] == sole_expected_audience
}

sender_constraint_allowed if {
	execution.sender_constraint in object.get(server_config, "allowed_sender_constraints", [])
}

sender_binding_present if {
	sha256_digest_valid(execution.credential_thumbprint)
}

execution_time_valid if {
	issued_at_ns := time.parse_rfc3339_ns(execution.issued_at)
	not_before_ns := time.parse_rfc3339_ns(execution.not_before)
	expires_at_ns := time.parse_rfc3339_ns(execution.expires_at)
	max_lifetime_ns := object.get(tool_config, "max_credential_ttl_seconds", 0) * 1000000000

	issued_at_ns <= now_ns
	not_before_ns <= now_ns
	now_ns < expires_at_ns
	expires_at_ns > issued_at_ns
	expires_at_ns - issued_at_ns <= max_lifetime_ns
}

selected_credential_profile := object.get(
	object.get(tool_config, "credential_profiles", {}),
	object.get(execution, "authority_mode", ""),
	"",
)

credential_profile_configured if {
	selected_credential_profile != ""
}

execution_identity_valid if {
	execution.credential_verified == true
	execution.principal_id != ""
	execution.credential_type in {
		"oauth_access_token",
		"x509_svid",
		"jwt_svid",
		"cloud_workload_token",
	}
	execution_principal_allowed
	authority_mode_allowed
	execution_issuer_trusted
	execution_audience_bound_to_target
	sender_constraint_allowed
	sender_binding_present
	execution_time_valid
	credential_profile_configured
}

requires_approval if {
	object.get(tool_config, "requires_approval", false) == true
}

requires_approval if {
	context.environment == "production"
	object.get(tool_config, "write", false) == true
}

approval_record_present if {
	count(approval_record) > 0
}

approval_binding_valid if {
	approval_record.status == "approved"
	approval_record.action_hash == action.canonical_hash
	approval_record.requester_principal_id == requester.principal_id
	approval_record.authority_subject_principal_id == authority_subject.principal_id
	approval_record.agent_principal == agent.agent_principal
	approval_record.agent_definition_id == agent.agent_definition_id
	approval_record.agent_version == agent.agent_version
	approval_record.runtime_instance_id == agent.runtime_instance_id
	approval_record.agent_credential_thumbprint == agent.credential_thumbprint
	approval_record.environment == context.environment
	approval_record.policy_bundle_digest == context.policy_bundle_digest
}

approval_contract_binding_valid if {
	approval_record.authority_mode == execution.authority_mode
	approval_record.execution_principal_id == execution.principal_id
	approval_record.expected_audience == sole_expected_audience
	approval_record.expected_audience == execution.audiences[0]
	approval_record.sender_constraint == execution.sender_constraint
	approval_record.credential_profile == selected_credential_profile
}

approval_time_valid if {
	approved_at_ns := time.parse_rfc3339_ns(approval_record.approved_at)
	expires_at_ns := time.parse_rfc3339_ns(approval_record.expires_at)
	approved_at_ns <= now_ns
	now_ns < expires_at_ns
}

approval_approver_present if {
	approval_record.approver_principal_id != ""
}

approval_separation_valid if {
	object.get(tool_config, "approval_mode", "confirmation") != "independent"
}

approval_separation_valid if {
	object.get(tool_config, "approval_mode", "confirmation") == "independent"
	approval_approver_present
	approval_record.approver_principal_id != requester.principal_id
	approval_record.approver_principal_id != authority_subject.principal_id
}

approval_single_use_valid if {
	approval_record.single_use == true
}

approval_not_consumed if {
	approval_record.consumed == false
}

approval_valid if {
	not requires_approval
}

approval_valid if {
	requires_approval
	approval_record_present
	approval_binding_valid
	approval_contract_binding_valid
	approval_time_valid
	approval_approver_present
	approval_separation_valid
	approval_single_use_valid
	approval_not_consumed
}

allow if {
	input_shape_valid
	request_context_valid
	context_valid
	requester_valid
	authority_subject_valid
	agent_identity_valid
	agent_credential_trust_valid
	agent_entitled
	authority_chain_valid
	action_canonicalizable
	action_hash_valid
	method_allowed
	tool_allowed
	target_allowed
	environment_allowed
	production_write_allowed
	execution_identity_valid
	approval_valid
}

deny_reasons contains "INPUT_SHAPE_INVALID" if {
	not input_shape_valid
}

deny_reasons contains "REQUEST_CONTEXT_INVALID" if {
	not request_context_valid
}

deny_reasons contains "VERIFIED_CONTEXT_INVALID" if {
	not context_valid
}

deny_reasons contains "REQUESTER_INVALID" if {
	not requester_valid
}

deny_reasons contains "AUTHORITY_SUBJECT_INVALID" if {
	not authority_subject_valid
}

deny_reasons contains "AGENT_IDENTITY_INVALID" if {
	not agent_identity_valid
}

deny_reasons contains "AGENT_CREDENTIAL_TYPE_NOT_TRUSTED" if {
	not agent_credential_type_trusted
}

deny_reasons contains "AGENT_CREDENTIAL_ISSUER_NOT_TRUSTED" if {
	not agent_credential_issuer_trusted
}

deny_reasons contains "AGENT_ATTESTATION_PROFILE_NOT_TRUSTED" if {
	not agent_attestation_profile_trusted
}

deny_reasons contains "AGENT_NOT_ENTITLED" if {
	not agent_entitled
}

deny_reasons contains "AUTHORITY_CHAIN_INVALID" if {
	not authority_chain_valid
}

deny_reasons contains "ACTION_HASH_INVALID" if {
	not action_hash_valid
}

deny_reasons contains "ACTION_CANONICALIZATION_INVALID" if {
	not action_canonicalizable
}

deny_reasons contains "METHOD_NOT_ALLOWED" if {
	not method_allowed
}

deny_reasons contains "TOOL_NOT_ALLOWED" if {
	not tool_allowed
}

deny_reasons contains "TARGET_NOT_ALLOWED" if {
	not target_allowed
}

deny_reasons contains "ENVIRONMENT_NOT_ALLOWED" if {
	not environment_allowed
}

deny_reasons contains "PRODUCTION_WRITE_NOT_ALLOWED" if {
	not production_write_allowed
}

deny_reasons contains "EXECUTION_PRINCIPAL_NOT_ALLOWED" if {
	not execution_principal_allowed
}

deny_reasons contains "EXECUTION_AUTHORITY_MODE_NOT_ALLOWED" if {
	not authority_mode_allowed
}

deny_reasons contains "EXECUTION_ISSUER_NOT_TRUSTED" if {
	not execution_issuer_trusted
}

deny_reasons contains "EXECUTION_AUDIENCE_MISMATCH" if {
	not execution_audience_bound_to_target
}

deny_reasons contains "EXECUTION_SENDER_CONSTRAINT_INVALID" if {
	not sender_constraint_allowed
}

deny_reasons contains "EXECUTION_SENDER_BINDING_MISSING" if {
	not sender_binding_present
}

deny_reasons contains "EXECUTION_CREDENTIAL_EXPIRED_OR_INVALID" if {
	not execution_time_valid
}

deny_reasons contains "CREDENTIAL_PROFILE_NOT_CONFIGURED" if {
	not credential_profile_configured
}

deny_reasons contains "EXECUTION_IDENTITY_INVALID" if {
	not execution_identity_valid
}

deny_reasons contains "APPROVAL_INVALID_OR_MISSING" if {
	requires_approval
	not approval_record_present
}

deny_reasons contains "APPROVAL_BINDING_MISMATCH" if {
	requires_approval
	approval_record_present
	not approval_binding_valid
}

deny_reasons contains "APPROVAL_CONTRACT_MISMATCH" if {
	requires_approval
	approval_record_present
	not approval_contract_binding_valid
}

deny_reasons contains "APPROVAL_EXPIRED_OR_INVALID" if {
	requires_approval
	approval_record_present
	not approval_time_valid
}

deny_reasons contains "APPROVAL_APPROVER_IDENTITY_MISSING" if {
	requires_approval
	approval_record_present
	not approval_approver_present
}

deny_reasons contains "APPROVAL_SEPARATION_INVALID" if {
	requires_approval
	approval_record_present
	not approval_separation_valid
}

deny_reasons contains "APPROVAL_NOT_SINGLE_USE" if {
	requires_approval
	approval_record_present
	not approval_single_use_valid
}

deny_reasons contains "APPROVAL_ALREADY_CONSUMED" if {
	requires_approval
	approval_record_present
	not approval_not_consumed
}

approval_reason_code := "APPROVAL_VALID" if {
	allow
	requires_approval
}

approval_reason_code := "APPROVAL_NOT_REQUIRED" if {
	allow
	not requires_approval
}

allow_reason_codes contains "ACTION_HASH_VALID" if {
	allow
}

allow_reason_codes contains "AGENT_CREDENTIAL_TRUSTED" if {
	allow
}

allow_reason_codes contains "AGENT_ENTITLED" if {
	allow
}

allow_reason_codes contains approval_reason_code if {
	allow
}

allow_reason_codes contains "AUTHORITY_CHAIN_VALID" if {
	allow
}

allow_reason_codes contains "EXECUTION_IDENTITY_VALID" if {
	allow
}

allow_reason_codes contains "IDENTITY_CONTEXT_VALID" if {
	allow
}

allow_reason_codes contains "REQUEST_CONTEXT_VALID" if {
	allow
}

allow_reason_codes contains "TOOL_ACCESS_ALLOWED" if {
	allow
}

allow_reason_codes contains "VERIFIED_CONTEXT_VALID" if {
	allow
}

reason_codes := sort([code | allow_reason_codes[code]]) if {
	allow
}

credential_profile := selected_credential_profile if {
	allow
}

credential_ttl_seconds := object.get(
	tool_config,
	"max_credential_ttl_seconds",
	0,
) if {
	allow
}

risk_tier := object.get(tool_config, "risk_tier", "unknown")

expected_audiences := sort([
audience |
	expected_audiences_for_target[audience]
])

decision := {
	"allow": allow,
	"authority_mode": object.get(execution, "authority_mode", "unknown"),
	"requires_approval": requires_approval,
	"deny_reasons": sort([reason | deny_reasons[reason]]),
	"reason_codes": reason_codes,
	"risk_tier": risk_tier,
	"credential_profile": credential_profile,
	"credential_ttl_seconds": credential_ttl_seconds,
	"expected_audiences": expected_audiences,
	"policy_id": object.get(data.agent_control, "policy_id", "unknown"),
	"policy_version": object.get(data.agent_control, "policy_version", "unknown"),
}
