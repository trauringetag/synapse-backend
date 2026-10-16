.PHONY: run tidy docker

run:
	go run ./cmd/api

tidy:
	go mod tidy

docker:
	docker compose up --build
