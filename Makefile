# Local development targets for the jomrr.samba collection. Run from the repo
# root (the collection directory; the ansible_collections/jomrr/samba layout
# ansible-test needs is provided by the existing path/symlink on this host).
#
# ansible-test runs against Podman here (docker is real Moby on this host), so
# the calls set ANSIBLE_TEST_PREFER_PODMAN=1 and target Python 3.12 — the same
# invocation that works manually. CI uses plain --docker instead (.github/).

PYTHON_VERSION := 3.12
AT := ANSIBLE_TEST_PREFER_PODMAN=1 ansible-test
# The directory that contains ansible_collections/ (three levels up from this
# collection dir), so antsibull-docs' `--use-current` can resolve jomrr.samba.
COLLECTIONS_ROOT := $(CURDIR)/../../..

.DEFAULT_GOAL := help

.PHONY: help lint sanity units test molecule molecule-provision molecule-join-dc molecule-join-member build changelog promote release release-dry docs docs-clean clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-13s\033[0m %s\n", $$1, $$2}'

lint: ## Run ansible-lint (profile production)
	ansible-lint

sanity: ## Run ansible-test sanity (Podman, py3.12)
	$(AT) sanity --docker --python $(PYTHON_VERSION)

units: ## Run ansible-test units (Podman, py3.12)
	$(AT) units --docker --python $(PYTHON_VERSION)

test: lint sanity units ## Run the fast gates together (lint + sanity + units)

molecule: ## Run the full Molecule integration suite (four distros; slow)
	molecule test

molecule-provision: ## Run the samba_provision Molecule scenario (four distros; slow)
	molecule test -s provision

molecule-join-dc: ## Run the samba_join_dc multi-host Molecule scenario (four pairs; slow)
	molecule test -s join_dc

molecule-join-member: ## Run the samba_join_member multi-host Molecule scenario (four pairs; slow)
	molecule test -s join_member

build: ## Build the collection tarball into dist/ (overwrites existing)
	ansible-galaxy collection build --output-path dist/ --force

changelog: ## Generate the Galaxy changelog from fragments (antsibull-changelog)
	antsibull-changelog release

docs: ## Build the Sphinx HTML docsite into docs/build/html (antsibull-docs)
	ANSIBLE_COLLECTIONS_PATH=$(COLLECTIONS_ROOT) bash docs/build.sh

docs-clean: ## Remove the generated docsite output (docs/rst, docs/build)
	rm -rf docs/rst docs/build

# Linear dev -> main promote. --ff-only fails (instead of making a merge commit)
# if dev and main have diverged, so a divergence is surfaced, not hidden. Merges
# origin/dev (the pushed dev state) after the fetch, not a stale local dev.
# Kept separate from `release`: after `make promote` the main CI runs (incl.
# molecule); once it is green, check out main and run `make release` separately.
promote: ## Merge dev into main, push, and return to dev
	git fetch origin
	git checkout main
	git merge --ff-only origin/dev
	git push origin main
	git checkout dev

# Requires GH_TOKEN in the environment and being on the main branch (PSR only
# releases from the main/master group). PSR bumps galaxy.yml, builds, tags and
# creates the GitHub release; CHANGELOG.rst stays antsibull-changelog's.
release: ## Cut a release locally (semantic-release; needs GH_TOKEN, on main)
	semantic-release version --no-changelog && semantic-release publish

release-dry: ## Compute the next version without committing, tagging or releasing
	semantic-release --noop version --no-changelog

clean: ## Remove build artifacts (dist/)
	rm -rf dist/
