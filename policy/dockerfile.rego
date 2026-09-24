# Dockerfile guardrails enforced in CI.
#
# conftest test --policy policy --namespace dockerfile Dockerfile
package dockerfile

import rego.v1

# --- helpers ---------------------------------------------------------------

instructions(name) := [i | some i in input; lower(i.Cmd) == name]

secret_key(k) if contains(lower(k), "password")
secret_key(k) if contains(lower(k), "secret")
secret_key(k) if contains(lower(k), "token")
secret_key(k) if contains(lower(k), "api_key")
secret_key(k) if contains(lower(k), "access_key")

# --- rules -----------------------------------------------------------------

deny contains msg if {
	count(instructions("user")) == 0
	msg := "Dockerfile must declare a non-root USER; containers must not run as root"
}

deny contains msg if {
	some u in instructions("user")
	some v in u.Value
	lower(v) == "root"
	msg := "Dockerfile must not set USER root"
}

deny contains msg if {
	some f in instructions("from")
	some v in f.Value
	endswith(lower(v), ":latest")
	msg := sprintf("base image '%s' uses the :latest tag; pin an explicit version", [v])
}

deny contains msg if {
	some f in instructions("from")
	count(f.Value) == 1
	not contains(f.Value[0], ":")
	not contains(f.Value[0], "@")
	msg := sprintf("base image '%s' has no tag or digest; pin an explicit version", [f.Value[0]])
}

deny contains msg if {
	some e in instructions("env")
	some i
	secret_key(e.Value[i])
	i % 2 == 0
	msg := sprintf("ENV '%s' looks like a credential; use a secrets manager, not a build-time ENV", [e.Value[i]])
}

deny contains msg if {
	count(instructions("add")) > 0
	msg := "use COPY instead of ADD; ADD silently fetches URLs and unpacks archives"
}

warn contains msg if {
	count(instructions("healthcheck")) == 0
	msg := "Dockerfile has no HEALTHCHECK; orchestrators cannot tell a hung container from a healthy one"
}
