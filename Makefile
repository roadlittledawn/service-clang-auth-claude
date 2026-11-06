# Convenience targets. Everything here is also runnable as the plain command.
.PHONY: dev db seed test lint check-template smoke docs-check build-lambda

db:            ## start MongoDB
	docker compose up -d

.env:
	cp .env.example .env

seed: db .env  ## idempotent dev data: app demo, user dev@localtest.me
	cargo run -q -p service -- seed

dev: db .env   ## run the service on http://auth.localtest.me:4000
	cargo run -p service

test: db       ## all Rust tests (needs MongoDB) + example app tests
	cargo test --workspace
	cd examples/node-app && npm test

lint:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings

check-template: ## cfn-lint + guardrail assertions on infra/template.yaml
	scripts/check-template.sh

smoke:         ## browser-like end-to-end check (service + demo app running)
	scripts/smoke.sh

docs-check:    ## run every ```bash example in the docs against the local service
	scripts/run-doc-examples.sh

build-lambda:  ## arm64 Lambda build
	sam build
