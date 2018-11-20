all:
	~/go/bin/go build -o compiled/client client.go shared_structs.go
	~/go/bin/go build -o compiled/client_auto client_auto.go shared_structs.go
	~/go/bin/go build -o compiled/server server.go shared_structs.go
	~/go/bin/go build -o compiled/find_servers find_servers.go
	~/go/bin/go build -o compiled/ping_all ping_all.go