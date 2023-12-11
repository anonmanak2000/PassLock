Binary_Name=PassLock

build:
	go build -o ./target/${Binary_Name}.exe main.go

run: build
	./target/${Binary_Name}

clean:
	go clean
	rmdir /s /q .\target

test:
	go test ./...

dep:
	go mod download