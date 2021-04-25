RUNTIME=linux-x64

build: clean
	dotnet build ipk-sniffer/ipk-sniffer -c Release -o build -r $(RUNTIME)

clean:
	dotnet clean ipk-sniffer/ipk-sniffer
	rm -rf build

