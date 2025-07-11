IMAGE ?= buckets-app
TAG ?= latest
REPOSITORY ?= ghcr.io/neuro-inc

.PHONY: format fmt
format fmt: ### Reformat source files and run linters
ifdef CI_LINT_RUN
	poetry run pre-commit run --all-files --show-diff-on-failure
else
	poetry run pre-commit run --all-files
endif

.PHONY: setup
setup:
	poetry config virtualenvs.in-project true
	poetry install
	poetry run pre-commit install

.PHONY: lint
lint: fmt ### Reformat files, run linters and mypy checks
	poetry run mypy src --show-error-codes

.PHONY: build
build:
	@echo "Building the project..."
	docker build -t $(IMAGE):$(TAG) .

.PHONY: push
push: build
	@echo "Pushing the image to the repository..."
	docker tag $(IMAGE):$(TAG) $(REPOSITORY)/$(IMAGE):$(TAG)
	docker push $(REPOSITORY)/$(IMAGE):$(TAG)

.PHONY: run
run:
	@echo "Running the container..."
	docker run --rm -it -v ${HOME}/.apolo:/root/.apolo -p 8080:8000 $(IMAGE):$(TAG)
