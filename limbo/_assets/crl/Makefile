.PHONY: assets
assets: bad_version.crl generalized_time_2025.crl

%.crl: %.txt crl_cases_ca_key.pem ../scripts/generate_crl.py
	go run github.com/google/der-ascii/cmd/ascii2der@latest < $< > $@
	$(VENV_BIN)/python -m limbo._assets.scripts.generate_crl $@
