Binary_Name=passlock

build:
	go build -o ./target/${Binary_Name}.exe main.go

run: build
	./target/${Binary_Name}

clean:
	go clean
	rm -rf ./target

test:
	go clean
	go test ./implementation -cover

tidy:
	go mod tidy	