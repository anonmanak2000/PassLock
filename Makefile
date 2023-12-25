Binary_Name=passlock

build:
	go build -o ./passlock/${Binary_Name}.exe main.go

run: build
	./passlock/${Binary_Name}

clean:
	go clean
	rm -rf ./passlock

test:
	go clean
	go test ./implementation -cover

tidy:
	go mod tidy	