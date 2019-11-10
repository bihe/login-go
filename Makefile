PROJECTNAME=$(shell basename "$(PWD)")

# Make is verbose in Linux. Make it silent.
MAKEFLAGS += --silent

VERSION="2.0.0-"
COMMIT=`git rev-parse HEAD | cut -c 1-8`
BUILD=`date -u +%Y%m%d.%H%M%S`
RUNTIME=`go version | sed 's/.*version //' | sed 's/ .*//'`

compile:
	@-$(MAKE) -s go-compile

release:
	@-$(MAKE) -s go-compile-release

test:
	@-$(MAKE) -s go-test

clean-test:
	@-$(MAKE) -s go-clean-test

coverage:
	@-$(MAKE) -s go-test-coverage

swagger:
	@-$(MAKE) -s go-swagger

run:
	@-$(MAKE) -s go-compile go-run

clean:
	@-$(MAKE) go-clean

docker-build:
	@-$(MAKE) -s __docker-build

docker-run:
	@-$(MAKE) -s __docker-run

frontend:
	@-$(MAKE) do-frontend-build

go-compile: go-clean go-build

go-compile-release: go-clean go-build-release

go-run:
	@echo "  >  Running application ..."
	./login.api

go-test:
	@echo "  >  Go test ..."
	go test -race ./...

go-clean-test:
	@echo "  >  Go test (no cache)..."
	go test -race -count=1 ./...

go-test-coverage:
	@echo "  >  Go test coverage ..."
	go test -race -coverprofile="coverage.txt" -covermode atomic ./...

go-build:
	@echo "  >  Building binary ..."
	go build -o login.api ./cmd/server/main.go

go-build-release:
	@echo "  >  Building binary..."
	GOOS=linux GOARCH=amd64 go build -ldflags="-w -s -X main.Version=${VERSION}${COMMIT} -X main.Build=${BUILD} -X main.Runtime=${RUNTIME}" -tags prod -o login.api cmd/server/main.go

go-swagger:
	# go get -u github.com/swaggo/swag/cmd/swag
	swag init -g cmd/server/main.go

go-clean:
	@echo "  >  Cleaning build cache"
	go clean ./...
	rm -f ./login.api

__docker-build:
	@echo " ... building docker image"
	docker build -t login .

__docker-run:
	@echo " ... running docker image"
	docker run -it -p 127.0.0.1:3000:3000 -v "$(PWD)":/opt/login/etc login

do-frontend-build:
	@echo "  >  Building angular frontend ..."
	cd ./frontend.angular;	npm install && npm run build -- --prod --base-href /ui/

.PHONY: compile release test run clean coverage
