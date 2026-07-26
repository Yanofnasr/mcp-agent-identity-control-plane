PYTHON ?= python3
PACKAGE_OUT ?= ../mcp-agent-identity-reference-$(shell cat VERSION).zip

.PHONY: validate validate-structure sync hash-action diagrams manifest package

validate:
	./scripts/validate.sh

validate-structure:
	$(PYTHON) scripts/validate_artifacts.py

sync:
	$(PYTHON) scripts/update_derived_values.py

hash-action:
	$(PYTHON) scripts/hash_action.py \
		--arguments examples/action-arguments.example.json \
		--context examples/authorization-context.example.json

diagrams:
	dot -Tsvg architecture/agent-identity-control-plane.dot -o architecture/agent-identity-control-plane.svg
	dot -Tpng -Gdpi=180 architecture/agent-identity-control-plane.dot -o architecture/agent-identity-control-plane.png
	dot -Tsvg architecture/four-principal-control-plane.dot -o architecture/four-principal-control-plane.svg
	dot -Tpng -Gdpi=180 architecture/four-principal-control-plane.dot -o architecture/four-principal-control-plane.png

manifest:
	LC_ALL=C find . -type f ! -name MANIFEST.sha256 ! -path './.git/*' -print0 | \
		LC_ALL=C sort -z | xargs -0 sha256sum > MANIFEST.sha256

package:
	./scripts/package.sh "$(PACKAGE_OUT)"
