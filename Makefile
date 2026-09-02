.PHONY: install test serve lint clean

install:
	python3 -m venv .venv
	.venv/bin/pip install -r requirements-dev.txt

test:
	.venv/bin/python -m pytest tests -q

serve:
	cd server && ../.venv/bin/uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

clean:
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	rm -rf .pytest_cache
