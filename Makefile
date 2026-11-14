.PHONY: reproduce test test-formal test-fuzz test-chaos lint audit clean

reproduce:
	python scripts/reproduce.py

test:
	python -m pytest backend/tests -q

test-formal:
	python -m pytest backend/tests/test_formal_invariants.py -q

test-fuzz:
	python -m pytest backend/tests/test_fuzzing.py -q

test-chaos:
	python -m pytest backend/tests/test_chaos.py -q

test-mcp:
	python -m pytest backend/tests/test_mcp_proxy.py -q

lint:
	python -m bandit -r backend/app -ll

audit:
	python -m pip_audit
	cd frontend && npm audit

mutation:
	python scripts/run_mutation_tests.py
