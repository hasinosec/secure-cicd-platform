package workflow

import rego.v1

sha := "@11bd71901bbe5b1630ceea73d27597364c9af683"

pinned_workflow := {
	"permissions": {},
	"jobs": {"build": {"steps": [{"uses": concat("", ["actions/checkout", sha])}]}},
}

test_pinned_action_allowed if {
	count(deny) == 0 with input as pinned_workflow
}

test_tag_pinned_action_denied if {
	count(deny) == 1 with input as {
		"permissions": {},
		"jobs": {"build": {"steps": [{"uses": "actions/checkout@v4"}]}},
	}
}

test_short_sha_denied if {
	count(deny) == 1 with input as {
		"permissions": {},
		"jobs": {"build": {"steps": [{"uses": "actions/checkout@11bd719"}]}},
	}
}

test_local_reusable_workflow_allowed if {
	count(deny) == 0 with input as {
		"permissions": {},
		"jobs": {"security": {"uses": "./.github/workflows/security.yml"}},
	}
}

test_remote_unpinned_reusable_workflow_denied if {
	count(deny) == 1 with input as {
		"permissions": {},
		"jobs": {"security": {"uses": "org/repo/.github/workflows/security.yml@main"}},
	}
}

test_missing_permissions_denied if {
	count(deny) == 1 with input as {"jobs": {"build": {"steps": [{"uses": concat("", ["actions/checkout", sha])}]}}}
}
