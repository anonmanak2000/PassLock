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
	go test -count=1 ./implementation -v

dep:
	go mod download

tidy:
	go mod tidy	