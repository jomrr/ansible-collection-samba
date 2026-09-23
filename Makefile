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
# Pinned via uvx; mypy gets ansible-core to resolve ansible.module_utils.
RUFF := uvx ruff@0.16.8
MYPY := uvx --with 'ansible-core==2.20.*' mypy@2.3.1

.DEFAULT_GOAL := help

.PHONY: help lint sanity units molecule molecule-provision molecule-join-dc molecule-join-member molecule-join-sssd build promote release release-dry galaxy docs docs-clean clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-13s\033[0m %s\n", $$1, $$2}'

lint: ## Run ansible-lint (profile production)
	ansible-lint

sanity: ## Run ansible-test sanity (Podman, py3.12)
	$(AT) sanity --docker --python $(PYTHON_VERSION)

units: ## Run ansible-test units (Podman, py3.12)
	$(AT) units --docker --python $(PYTHON_VERSION)

.PHONY: ruff
ruff: ## Run ruff on the plugins and unit tests
	$(RUFF) check plugins tests/unit

.PHONY: mypy
mypy: ## Run mypy on the collection plugins
	$(MYPY) -p ansible_collections.jomrr.samba.plugins

.PHONY: test
test: lint ruff mypy sanity units ## Run the fast gates together (lint + ruff + mypy + sanity + units)

molecule: ## Run the full Molecule integration suite (four distros; slow)
	molecule test

molecule-provision: ## Run the samba_provision Molecule scenario (four distros; slow)
	molecule test -s provision

molecule-join-dc: ## Run the samba_join_dc multi-host Molecule scenario (four pairs; slow)
	molecule test -s join_dc

molecule-join-member: ## Run the samba_join_member multi-host Molecule scenario (four pairs; slow)
	molecule test -s join_member

molecule-join-sssd: ## Run the samba_join_sssd multi-host Molecule scenario (four pairs; slow)
	molecule test -s join_sssd

build: ## Build the collection tarball into dist/ (overwrites existing)
	ansible-galaxy collection build --output-path dist/ --force

docs: ## Build the Sphinx HTML docsite into docs/build/html (antsibull-docs)
	ANSIBLE_COLLECTIONS_PATH=$(COLLECTIONS_ROOT) bash docs/build.sh

docs-clean: ## Remove the generated docsite output (docs/rst, docs/build)
	rm -rf docs/rst docs/build

# Linear dev -> main promote. --ff-only fails (instead of making a merge commit)
# if dev and main have diverged, so a divergence is surfaced, not hidden. Merges
# origin/dev (the pushed dev state) after the fetch, not a stale local dev.
# Kept separate from `release`: after `make promote` the main CI runs (incl.
# molecule); once it is green, run `make release` (it switches to main itself).
promote: ## Merge dev into main, push, and return to dev
	git fetch origin
	git checkout main
	git merge --ff-only origin/dev
	git push origin main
	git checkout dev

# Requires GH_TOKEN in the environment. PSR only releases from the main/master
# group, so the target checks out main itself (promote leaves the tree on dev).
# PSR bumps galaxy.yml, cuts the antsibull changelog and builds the tarball
# (build_command in pyproject.toml), commits, tags and creates the GitHub
# release. The release commit lands on main
# only, so dev is fast-forwarded to main afterwards; otherwise the next
# `make promote` cannot fast-forward. Right after a promote dev has no commits
# of its own, so --ff-only succeeds; if work continued on dev meanwhile it
# fails and the divergence is surfaced, as in promote (the release itself is
# complete at that point).
# The release runs locally under the maintainer's identity, so the release
# commit and tag carry it too (PSR reads GIT_COMMIT_AUTHOR; without it the
# author is the bot identity semantic-release <semantic-release>, which has no
# account behind it). The commit message still marks the commit as generated.
# Also set for release-dry, so the dry run shows the author the release uses.
release release-dry: export GIT_COMMIT_AUTHOR = $(shell git config user.name) <$(shell git config user.email)>
release: ## Cut a release from main, then fast-forward dev to it (needs GH_TOKEN)
	git checkout main
	semantic-release version --no-changelog && semantic-release publish
	git checkout dev
	git merge --ff-only main
	git push origin dev

# Same branch rule as release: the next version is computed from main, i.e.
# from what promote has pushed, not from unpromoted dev commits.
release-dry: ## Compute the next version from main, without committing, tagging or releasing
	git checkout main
	semantic-release --noop version --no-changelog
	git checkout dev

# The version galaxy.yml carries, resolved when the recipe runs (not at parse
# time), so `make release galaxy` publishes the version release just bumped.
VERSION = $(shell sed -n 's/^version: *//p' galaxy.yml)

# Publishes the tarball `make release` left in dist/ (PSR's build_command
# builds dist/jomrr-samba-<version>.tar.gz for the version it bumped galaxy.yml
# to), so Galaxy gets the asset of the GitHub release, not a fresh build of the
# working tree. ansible-galaxy reads the API key from ~/.ansible/galaxy_token
# (ANSIBLE_GALAXY_TOKEN_PATH), a YAML file with `token: <key>`.
galaxy: ## Publish the released tarball to Ansible Galaxy (after `make release`)
	ansible-galaxy collection publish dist/jomrr-samba-$(VERSION).tar.gz

clean: ## Remove build artifacts (dist/)
	rm -rf dist/
