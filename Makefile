build:
	dotnet build ipk-sniffer/ipk-sniffer -c Release -o build/

clean:
	dotnet clean ipk-sniffer/ipk-sniffer
	rm -rf build

