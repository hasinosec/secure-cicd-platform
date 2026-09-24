package dockerfile

import rego.v1

hardened := [
	{"Cmd": "from", "Value": ["python:3.13-slim"]},
	{"Cmd": "user", "Value": ["10001"]},
	{"Cmd": "copy", "Value": ["app/", "./app/"]},
	{"Cmd": "healthcheck", "Value": ["CMD", "true"]},
]

test_hardened_passes if {
	count(deny) == 0 with input as hardened
}

test_missing_user_denied if {
	count(deny) == 1 with input as [{"Cmd": "from", "Value": ["python:3.13-slim"]}]
}

test_root_user_denied if {
	count(deny) > 0 with input as array.concat(hardened, [{"Cmd": "user", "Value": ["root"]}])
}

test_latest_tag_denied if {
	count(deny) > 0 with input as [
		{"Cmd": "from", "Value": ["python:latest"]},
		{"Cmd": "user", "Value": ["10001"]},
	]
}

test_untagged_base_denied if {
	count(deny) > 0 with input as [
		{"Cmd": "from", "Value": ["python"]},
		{"Cmd": "user", "Value": ["10001"]},
	]
}

test_secret_env_denied if {
	count(deny) > 0 with input as array.concat(
		hardened,
		[{"Cmd": "env", "Value": ["DB_PASSWORD", "hunter2"]}],
	)
}

test_non_secret_env_allowed if {
	count(deny) == 0 with input as array.concat(
		hardened,
		[{"Cmd": "env", "Value": ["APP_VERSION", "1.2.3"]}],
	)
}

test_env_value_containing_secret_word_is_not_flagged if {
	# only the KEY is a credential name; the value must not trigger the rule
	count(deny) == 0 with input as array.concat(
		hardened,
		[{"Cmd": "env", "Value": ["APP_MODE", "password-reset"]}],
	)
}

test_add_denied if {
	count(deny) > 0 with input as array.concat(
		hardened,
		[{"Cmd": "add", "Value": ["https://example.com/x.tar.gz", "/tmp/"]}],
	)
}

test_missing_healthcheck_warns if {
	count(warn) == 1 with input as [
		{"Cmd": "from", "Value": ["python:3.13-slim"]},
		{"Cmd": "user", "Value": ["10001"]},
	]
}
