package agent.mcp.authz_test

import data.agent.mcp.authz
import rego.v1

base_input := data.test_fixtures.valid_input

mock_now_ns := 1785241230000000000
mock_after_approval_expiry_ns := 1785241860000000000
mock_after_execution_expiry_ns := 1785242160000000000

patch_request(patch) := object.union(base_input, {
	"request": object.union(base_input.request, patch),
})

patch_agent(patch) := object.union(base_input, {
	"verified": object.union(base_input.verified, {
		"agent": object.union(base_input.verified.agent, patch),
	}),
})

patch_authority_subject(patch) := object.union(base_input, {
	"verified": object.union(base_input.verified, {
		"authority_subject": object.union(base_input.verified.authority_subject, patch),
	}),
})

patch_execution(patch) := object.union(base_input, {
	"verified": object.union(base_input.verified, {
		"execution": object.union(base_input.verified.execution, patch),
	}),
})

patch_action(patch) := object.union(base_input, {
	"verified": object.union(base_input.verified, {
		"action": object.union(base_input.verified.action, patch),
	}),
})

valid_decision := decision if {
	decision := authz.decision
		with input as base_input
		with time.now_ns as mock_now_ns
}

test_valid_production_merge if {
	valid_decision.allow == true
	valid_decision.requires_approval == true
	valid_decision.deny_reasons == []
	valid_decision.risk_tier == "critical"
	valid_decision.credential_profile == "source-control-user-delegated-critical"
	valid_decision.credential_ttl_seconds == 900
	valid_decision.expected_audiences == ["https://source-control.example.internal"]
}

test_wrong_audience_is_denied if {
	test_input := patch_execution({
		"audiences": ["https://unrelated-api.example.internal"],
	})

	result := authz.decision
		with input as test_input
		with time.now_ns as mock_now_ns

	result.allow == false
	"EXECUTION_AUDIENCE_MISMATCH" in result.deny_reasons
}

test_multiple_audiences_are_denied if {
	test_input := patch_execution({
		"audiences": [
			"https://source-control.example.internal",
			"https://unrelated-api.example.internal",
		],
	})

	result := authz.decision
		with input as test_input
		with time.now_ns as mock_now_ns

	result.allow == false
	"EXECUTION_AUDIENCE_MISMATCH" in result.deny_reasons
}

test_missing_sender_binding_is_denied if {
	test_input := patch_execution({
		"credential_thumbprint": "",
	})

	result := authz.decision
		with input as test_input
		with time.now_ns as mock_now_ns

	result.allow == false
	"EXECUTION_SENDER_BINDING_MISSING" in result.deny_reasons
}

test_expired_approval_is_denied if {
	result := authz.decision
		with input as base_input
		with time.now_ns as mock_after_approval_expiry_ns

	result.allow == false
	"APPROVAL_INVALID_OR_MISSING" in result.deny_reasons
}

test_expired_execution_credential_is_denied if {
	result := authz.decision
		with input as base_input
		with time.now_ns as mock_after_execution_expiry_ns

	result.allow == false
	"EXECUTION_CREDENTIAL_EXPIRED_OR_INVALID" in result.deny_reasons
}

test_missing_correlation_context_is_denied if {
	test_input := patch_request({
		"correlation_id": "",
	})

	result := authz.decision
		with input as test_input
		with time.now_ns as mock_now_ns

	result.allow == false
	"REQUEST_CONTEXT_INVALID" in result.deny_reasons
}

test_unknown_approval_reference_is_denied if {
	test_input := patch_request({
		"approval_id": "approval_unknown",
	})

	result := authz.decision
		with input as test_input
		with time.now_ns as mock_now_ns

	result.allow == false
	"APPROVAL_INVALID_OR_MISSING" in result.deny_reasons
}

test_authority_chain_mismatch_is_denied if {
	test_input := patch_authority_subject({
		"authority_basis": "agent_own_authority",
	})

	result := authz.decision
		with input as test_input
		with time.now_ns as mock_now_ns

	result.allow == false
	"AUTHORITY_CHAIN_INVALID" in result.deny_reasons
}

test_delegated_subject_mismatch_is_denied if {
	test_input := patch_execution({
		"authority_subject_principal_id": "urn:example:principal:subject:other",
	})

	result := authz.decision
		with input as test_input
		with time.now_ns as mock_now_ns

	result.allow == false
	"AUTHORITY_CHAIN_INVALID" in result.deny_reasons
}

test_agent_actor_mismatch_is_denied if {
	test_input := patch_execution({
		"agent_actor_principal_id": "spiffe://agents.example.internal/prod/other-agent",
	})

	result := authz.decision
		with input as test_input
		with time.now_ns as mock_now_ns

	result.allow == false
	"AUTHORITY_CHAIN_INVALID" in result.deny_reasons
}

test_action_hash_mismatch_is_denied if {
	test_input := patch_action({
		"canonical_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})

	result := authz.decision
		with input as test_input
		with time.now_ns as mock_now_ns

	result.allow == false
	"ACTION_HASH_INVALID" in result.deny_reasons
}

test_unauthorized_target_is_denied if {
	test_input := patch_action({
		"target": "scm://finance/example-service/pull/482",
		"canonical_hash": "sha256:7fcee49d6da4453fd100057b7468fd4685a3be86941d5bba90f304a04a395a14",
	})

	result := authz.decision
		with input as test_input
		with time.now_ns as mock_now_ns

	result.allow == false
	"TARGET_NOT_ALLOWED" in result.deny_reasons
}

test_untrusted_issuer_is_denied if {
	test_input := patch_execution({
		"issuer": "https://untrusted.example.internal",
	})

	result := authz.decision
		with input as test_input
		with time.now_ns as mock_now_ns

	result.allow == false
	"EXECUTION_ISSUER_NOT_TRUSTED" in result.deny_reasons
}

test_independent_approval_cannot_be_self_approved if {
	approval := object.union(
		data.approval_records.approval_01J8Y4Q63H,
		{"approver_principal_id": base_input.verified.requester.principal_id},
	)
	records := object.union(data.approval_records, {"approval_01J8Y4Q63H": approval})

	result := authz.decision
		with input as base_input
		with data.approval_records as records
		with time.now_ns as mock_now_ns

	result.allow == false
	"APPROVAL_INVALID_OR_MISSING" in result.deny_reasons
}

test_approval_policy_bundle_mismatch_is_denied if {
	approval := object.union(
		data.approval_records.approval_01J8Y4Q63H,
		{"policy_bundle_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
	)
	records := object.union(data.approval_records, {"approval_01J8Y4Q63H": approval})

	result := authz.decision
		with input as base_input
		with data.approval_records as records
		with time.now_ns as mock_now_ns

	result.allow == false
	"APPROVAL_INVALID_OR_MISSING" in result.deny_reasons
}

test_missing_credential_profile_is_denied if {
	server := data.agent_control.servers["source-control"]
	tool := server.tools.merge_pull_request
	patched_tool := {
		"write": tool.write,
		"requires_approval": tool.requires_approval,
		"approval_mode": tool.approval_mode,
		"risk_tier": tool.risk_tier,
		"max_credential_ttl_seconds": tool.max_credential_ttl_seconds,
	}
	patched_tools := object.union(
		object.remove(server.tools, ["merge_pull_request"]),
		{"merge_pull_request": patched_tool},
	)
	patched_server := object.union(
		object.remove(server, ["tools"]),
		{"tools": patched_tools},
	)
	patched_servers := object.union(
		object.remove(data.agent_control.servers, ["source-control"]),
		{"source-control": patched_server},
	)
	patched_control := object.union(
		object.remove(data.agent_control, ["servers"]),
		{"servers": patched_servers},
	)

	result := authz.decision
		with input as base_input
		with data.agent_control as patched_control
		with time.now_ns as mock_now_ns

	result.allow == false
	"CREDENTIAL_PROFILE_NOT_CONFIGURED" in result.deny_reasons
}

test_production_write_entitlement_cannot_be_self_asserted if {
	agent_id := base_input.verified.agent.agent_principal
	entitlement := data.agent_control.entitlements[agent_id]
	permission := entitlement.server_permissions["source-control"]
	patched_permission := object.union(permission, {"production_write_allowed": false})
	patched_permissions := object.union(entitlement.server_permissions, {"source-control": patched_permission})
	patched_entitlement := object.union(entitlement, {"server_permissions": patched_permissions})
	patched_entitlements := object.union(data.agent_control.entitlements, {agent_id: patched_entitlement})
	patched_control := object.union(data.agent_control, {"entitlements": patched_entitlements})

	result := authz.decision
		with input as base_input
		with data.agent_control as patched_control
		with time.now_ns as mock_now_ns

	result.allow == false
	"PRODUCTION_WRITE_NOT_ALLOWED" in result.deny_reasons
}
