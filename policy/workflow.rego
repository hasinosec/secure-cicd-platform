# GitHub Actions supply-chain guardrails.
#
# A tag like @v4 is mutable: whoever controls the action repository can move it
# and run arbitrary code in this pipeline. Only a full 40-character commit SHA
# is immutable, so that is what CI requires.
#
# conftest test --policy policy --namespace workflow .github/workflows/*.yml
package workflow

import rego.v1

pinned(ref) if regex.match(`@[0-9a-f]{40}$`, ref)

local_ref(ref) if startswith(ref, "./")

deny contains msg if {
	some job_name, job in input.jobs
	some step in job.steps
	ref := step.uses
	not pinned(ref)
	not local_ref(ref)
	msg := sprintf("job '%s' uses '%s' which is not pinned to a full commit SHA", [job_name, ref])
}

deny contains msg if {
	some job_name, job in input.jobs
	ref := job.uses
	not pinned(ref)
	not local_ref(ref)
	msg := sprintf("job '%s' calls workflow '%s' which is not pinned to a full commit SHA", [job_name, ref])
}

deny contains msg if {
	not input.permissions
	msg := "workflow must declare a top-level 'permissions' block; the default token is too broad"
}
