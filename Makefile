.PHONY: install entra_id google

install:
	Rscript -e "devtools::install()"

entra_id:
	faucet start -w 1 -d example/entra_id

google:
	faucet start -w 1 -d example/google
