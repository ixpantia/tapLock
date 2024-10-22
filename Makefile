.PHONY: install entra_id google document

install:
	Rscript -e "devtools::install()"

document:
	Rscript -e "devtools::document()"

entra_id:
	faucet start -w 1 -d example/entra_id

google:
	faucet start -w 1 -d example/google
