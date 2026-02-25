IMAGE ?= tak-server
TAG ?= latest
PLATFORMS ?= linux/amd64,linux/arm64

.PHONY: run build build-multiarch

run:
	docker compose up --build

build:
	docker build -t $(IMAGE):$(TAG) .

build-multiarch:
	docker buildx build --platform $(PLATFORMS) -t $(IMAGE):$(TAG) --push .
