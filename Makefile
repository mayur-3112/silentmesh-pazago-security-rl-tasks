.PHONY: help suite test build verify clean
PY ?= python

help:
	@echo "make suite   - run the full task suite (static + oracle, no Docker)"
	@echo "make test T=<task-id>  - run one task's local test"
	@echo "make build T=<task-id> - docker build one task image"
	@echo "make verify T=<task-id> - docker build + oracle + grader for one task"
	@echo "make clean   - remove temp artifacts"

suite:
	$(PY) run_suite.py

test:
	$(PY) tasks/$(T)/local_test.py

build:
	cd tasks/$(T) && docker build -t $(T) .

verify:
	cd tasks/$(T) && docker build -t $(T) . \
	 && docker run --network=none -dit --name $(T)-run $(T) \
	 && docker cp solution.sh $(T)-run:/app/solution.sh \
	 && docker exec $(T)-run bash /app/solution.sh \
	 && docker cp tests $(T)-run:/app/tests && docker cp run-tests.sh $(T)-run:/app/ \
	 && docker exec $(T)-run bash /app/run-tests.sh; \
	 docker rm -f $(T)-run

clean:
	rm -rf **/__pycache__ .pytest_cache
