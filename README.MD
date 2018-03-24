# Golang pcap-reader 

**Golang pcap-reader reads files that are in lib pcap file format.**

Example:

```go
package main

import (
	"fmt"
	"io"

	"github.com/evnix/pcap-reader"
)

func main() {

	fname := "/var/file.pcap"
	pcaprdr := pcapreader.PCapReader{}
	pcaprdr.Open(fname)
	defer pcaprdr.Close()
	fmt.Println(pcaprdr.PcapHdr.MagicNumber)

	for {
		packetHeader, data, err := pcaprdr.ReadNextPacket()
		if err == io.EOF {
			fmt.Println("Reached end of file.")
			break
		}
		fmt.Println("Packet Header:", packetHeader)
		fmt.Println("Data:", data)
	}

}

```



For more info on the libpcap file format, refer:
https://wiki.wireshark.org/Development/LibpcapFileFormat

