all:
	go build

clean:
	- go clean
	- rm -f *.key *.crt gocerts-*

cross:
	GOOS=linux GOARCH=amd64 go build -o gocerts-linux-amd64
	GOOS=windows GOARCH=amd64 go build -o gocerts-windows-amd64.exe
	GOOS=darwin GOARCH=amd64 go build -o gocerts-darwin-amd64

