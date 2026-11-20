# fuzzy-psi - fuzzy private set intersection with consistency proofs
#
# Targets:
#   make test      unit test suite (unittest, no pytest required)
#   make eval      full benchmark, writes results/results.json (~2-3 min)
#   make figures   regenerate the three PNG figures from results.json
#   make demo      run the protocol over loopback TCP
#   make bench     primitive microbenchmarks (modexp, simhash)
#   make all       test + eval + figures

PY ?= python
export PYTHONPATH := src

.PHONY: all test eval figures demo bench leak info clean check

all: test eval figures

test:
	$(PY) -m unittest discover -s tests -v

eval:
	$(PY) -m fuzzy_psi.cli eval --out results/results.json

figures:
	$(PY) scripts/make_figures.py results/results.json --outdir results

demo:
	$(PY) -m fuzzy_psi.cli demo --n 64 --radius 4

bench:
	$(PY) -m fuzzy_psi.cli bench

leak:
	$(PY) scripts/leak_probe.py

info:
	$(PY) -m fuzzy_psi.cli info

check:
	$(PY) scripts/check_repro.py

clean:
	rm -f results/smoke.json results/*.log
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
