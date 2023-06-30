.PHONY: all
all:
	go run .

schema.go: ../../limbo-schema.json
	go run \
		github.com/atombender/go-jsonschema/cmd/gojsonschema@latest -v \
		-p main $< >$@
