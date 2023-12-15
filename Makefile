Binary_Name=passlock

build:
	go build -o ./target/${Binary_Name}.exe main.go

test:
	go test ./...

run: build
	./target/${Binary_Name}

clean:
	go clean
	rm -rf ./target

test:
	go test ./...

dep:
	go mod download

tidy:
	go mod tidy	