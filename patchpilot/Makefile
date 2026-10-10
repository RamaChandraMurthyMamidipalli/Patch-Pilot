.PHONY: help up up-local down install install-backend install-frontend \
        migrate seed lint lint-backend lint-frontend type-check \
        test test-backend test-frontend test-e2e test-security \
        eval eval-smoke train-baselines ingest-kb \
        docker-build docker-push clean

SHELL := powershell.exe
.SHELLFLAGS := -NoProfile -Command

PATCHPILOT_DIR := $(CURDIR)
BACKEND_DIR := $(PATCHPILOT_DIR)/backend
FRONTEND_DIR := $(PATCHPILOT_DIR)/frontend
ML_DIR := $(PATCHPILOT_DIR)/ml
RAG_DIR := $(PATCHPILOT_DIR)/rag

## ─── Help ─────────────────────────────────────────────────────────────────────
help: ## Show this help
	@echo "PatchPilot Makefile targets:"
	@echo ""
	@echo "  make up            - Start full stack (Docker)"
	@echo "  make up-local      - Start services locally (no Docker)"
	@echo "  make down          - Stop Docker services"
	@echo "  make install       - Install all dependencies"
	@echo "  make migrate       - Run Alembic migrations"
	@echo "  make seed          - Seed demo data"
	@echo "  make lint          - Run all linters"
	@echo "  make test          - Run all tests"
	@echo "  make eval          - Run full evaluation suite"
	@echo "  make eval-smoke    - Run smoke eval (CI)"
	@echo "  make train-baselines - Train baseline ML models"
	@echo "  make ingest-kb     - Ingest knowledge base into Qdrant"
	@echo "  make clean         - Remove build artifacts"

## ─── Docker ───────────────────────────────────────────────────────────────────
up: ## Start full stack with Docker Compose
	docker compose up --build -d
	@echo "PatchPilot is starting up..."
	@echo "Frontend: http://localhost:5173"
	@echo "API: http://localhost:8000/docs"
	@echo "MLflow: http://localhost:5000"
	@echo "Grafana: http://localhost:3000"

down: ## Stop Docker services
	docker compose down

docker-build: ## Build all Docker images
	docker compose build

## ─── Local Dev (no Docker) ───────────────────────────────────────────────────
up-local: ## Start backend + frontend for local dev (requires Postgres + Redis running)
	@echo "Starting backend API..."
	Start-Process powershell -ArgumentList '-NoProfile -Command "cd backend; uvicorn app.main:app --reload --port 8000"'
	@echo "Starting ML service..."
	Start-Process powershell -ArgumentList '-NoProfile -Command "cd ml/serving; uvicorn main:app --reload --port 8001"'
	@echo "Starting frontend..."
	Start-Process powershell -ArgumentList '-NoProfile -Command "cd frontend; npm run dev"'
	@echo "Services starting. Check individual terminals for output."

## ─── Install ─────────────────────────────────────────────────────────────────
install: install-backend install-frontend ## Install all dependencies

install-backend: ## Install backend Python dependencies
	pip install -r backend/requirements.txt
	pip install -r ml/requirements.txt
	pip install -r rag/requirements.txt

install-frontend: ## Install frontend Node dependencies
	cd frontend && npm install

## ─── Database ────────────────────────────────────────────────────────────────
migrate: ## Run Alembic migrations
	cd backend && alembic upgrade head

migrate-new: ## Create new migration (ARGS="migration name")
	cd backend && alembic revision --autogenerate -m "$(ARGS)"

seed: ## Seed demo data
	cd backend && python -m scripts.seed_demo

## ─── Linting & Type Checking ─────────────────────────────────────────────────
lint: lint-backend lint-frontend ## Run all linters

lint-backend: ## Lint backend with ruff
	cd backend && ruff check . --fix
	cd ml && ruff check . --fix
	cd rag && ruff check . --fix

lint-frontend: ## Lint frontend with ESLint
	cd frontend && npm run lint

type-check: ## Run mypy and tsc
	cd backend && mypy app/ --ignore-missing-imports
	cd frontend && npm run type-check

## ─── Testing ─────────────────────────────────────────────────────────────────
test: test-backend test-frontend ## Run all tests

test-backend: ## Run backend tests with coverage
	cd backend && pytest tests/ -v --cov=app --cov-report=term-missing --cov-fail-under=70

test-frontend: ## Run frontend tests
	cd frontend && npm run test

test-e2e: ## Run Playwright E2E tests
	cd frontend && npx playwright test

test-security: ## Run security tests
	cd backend && pytest tests/security/ -v

## ─── ML & Evaluation ─────────────────────────────────────────────────────────
train-baselines: ## Train baseline ML models locally
	cd ml && python training/train_baselines.py

train-unixcoder: ## Fine-tune UniXcoder (GPU required; use Colab if no GPU)
	cd ml && python training/train_unixcoder.py

export-onnx: ## Export model to ONNX + quantize
	cd ml && python export/export_onnx.py

eval: ## Run full evaluation suite
	cd evaluation && python run_eval.py --full

eval-smoke: ## Run smoke evaluation (CI-friendly, fast)
	cd evaluation && python run_eval.py --smoke

ingest-kb: ## Ingest knowledge base (CWE, NVD, OWASP) into Qdrant
	cd rag && python ingest/ingest_all.py

## ─── Cleanup ──────────────────────────────────────────────────────────────────
clean: ## Remove build artifacts
	Remove-Item -Recurse -Force backend/.mypy_cache, backend/.ruff_cache, backend/.pytest_cache -ErrorAction SilentlyContinue
	Remove-Item -Recurse -Force frontend/dist, frontend/node_modules/.cache -ErrorAction SilentlyContinue
	Remove-Item -Recurse -Force ml/__pycache__ -ErrorAction SilentlyContinue
