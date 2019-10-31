.PHONY: build clean

build:
	env GOOS=linux go build -ldflags="-s -w" -o bin/utils main.go

clean:
	rm -rf ./bin
