.PHONY: init test clean run
VENV_DIR=./venv

init:
	virtualenv -p python3 $(VENV_DIR)
	$(VENV_DIR)/bin/pip3 install -r ./requirements.txt

test: init
	$(VENV_DIR)/bin/pip3 install -r ./requirements-test.txt
	$(VENV_DIR)/bin/pytest --cov --cov-report term tests/

clean:
	rm -rf $(VENV_DIR)

run: init
	$(VENV_DIR)/bin/python -m freetacacs.factory

