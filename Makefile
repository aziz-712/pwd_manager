.PHONY: install test serve openapi lint clean

install:
	python3 -m venv .venv
	.venv/bin/pip3.14 install -r requirements-dev.txt

test:
	.venv/bin/python3.14 -m pytest tests -q

# Swagger UI at http://127.0.0.1:8000/docs, ReDoc at /redoc
serve:
	cd server && ../.venv/bin/uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

openapi:
	.venv/bin/python3.14 server/export_openapi.py docs/openapi.json

clean:
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	rm -rf .pytest_cache
