.PHONY: help up down test demo demo-attack demo-benign benchmark clean

help:
	@echo "SentinelMesh AI — Available commands:"
	@echo "  make up          - Start backend and dashboard via Docker Compose"
	@echo "  make down        - Stop all Docker Compose services"
	@echo "  make demo        - Run both demo agent scenarios (ATK-001 & BEN-001)"
	@echo "  make demo-attack - Run scenario ATK-001 (Poisoned Résumé)"
	@echo "  make demo-benign - Run scenario BEN-001 (Security Résumé Review)"
	@echo "  make benchmark   - Run end-to-end benchmark suite and export metrics report"
	@echo "  make test        - Run backend pytest test suite"
	@echo "  make clean       - Remove temporary artifacts and databases"

up:
	docker compose up --build

down:
	docker compose down

demo:
	python -m demo_agents.agent_runner --scenario=both

demo-attack:
	python -m demo_agents.agent_runner --scenario=atk-001

demo-benign:
	python -m demo_agents.agent_runner --scenario=ben-001

benchmark:
	python benchmark/run_benchmark.py

test:
	python -m pytest backend/tests -v

clean:
	rm -f sentinelmesh.db
	find . -type d -name __pycache__ -exec rm -rf {} +
