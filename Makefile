.PHONY: init test clean run lint
VENV_DIR=./venv

init:
	virtualenv -p python3 $(VENV_DIR)
	$(VENV_DIR)/bin/pip3 install -r ./requirements.txt
	$(VENV_DIR)/bin/pip3 install .

test: init
	$(VENV_DIR)/bin/pip3 install -r ./requirements-test.txt
	$(VENV_DIR)/bin/pytest --cov --cov-report term freetacacs/tests/

clean:
	rm -rf $(VENV_DIR)
	rm -rf ./_trial_temp ./build ./dist ./.coverage ./.pytest_cache *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} \;

run: init
	$(VENV_DIR)/bin/python -m freetacacs.factory

lint: init
	$(VENV_DIR)/bin/pip3 install pylint
	$(VENV_DIR)/bin/pylint freetacacs || return 0
