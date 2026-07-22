.PHONY: all monitor attack test clean docker

VERSION ?= 2.0.0

all: install

monitor:
	./edr.sh monitor

attack:
	./sim/attack.sh

test:
	python3 -m pytest tests/ -v

clean:
	rm -rf logs/ honeypot/*.txt honeypot/*.enc honeypot/*.bin honeypot/.edr_state.json
	rm -rf *.pyc __pycache__ .pytest_cache

docker:
	docker build -t ransomwatch:$(VERSION) .
