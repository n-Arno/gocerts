all:
	go build

clean:
	- go clean
	- rm -f *.key *.crt *.pfx gocerts-*

cross:
	GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o gocerts-linux-amd64
	GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o gocerts-windows-amd64.exe
	GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w" -o gocerts-darwin-amd64

