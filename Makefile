
.PHONY: rsca
rsca:
	go build ./cmd/...

.PHONY: clean
clean:
	rm -f rsca
