VENV = venv
PYTHON = $(VENV)/bin/python
PIP = $(VENV)/bin/pip

# Default target
all: install

# Create virtual environment and install dependencies
install: requirements.txt
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

# Run the test suite
test:
	$(PYTHON) -m unittest discover -s tests -p "*_test.py"

# Clean up generated files and virtual environment
clean:
	rm -rf $(VENV)
	rm -rf test_output
	rm -rf __pycache__
	rm -f *.pcap
	rm -f rto_log.txt

.PHONY: all install test clean
