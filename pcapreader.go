package pcapreader

import (
	"encoding/binary"
	"os"
)

//PcapHdrS global file header
// for more info: https://wiki.wireshark.org/Development/LibpcapFileFormat
type PcapHdrS struct {
	MagicNumber  uint32 /* magic number */
	VersionMajor uint16 /* major version number */
	VersionMinor uint16 /* minor version number */
	Thiszone     int32  /* GMT to local correction */
	Sigfigs      uint32 /* accuracy of timestamps */
	Snaplen      uint32 /* max length of captured packets, in octets */
	Network      uint32 /* data link type */
}

//PcaprecHdrS packet header
type PcaprecHdrS struct {
	TsSec   int32 /* timestamp seconds */
	TsUsec  int32 /* timestamp microseconds */
	InclLen int32 /* number of octets of packet saved in file */
	OrigLen int32 /* actual length of packet */
}

//PCapReader struct
type PCapReader struct {
	FileHandle *os.File
	PcapHdr    PcapHdrS
}

//Open pcap file
func (P *PCapReader) Open(filename string) error {
	var err error
	P.FileHandle, err = os.Open(filename)
	if err != nil {
		return err
	}
	return binary.Read(P.FileHandle, binary.LittleEndian, &P.PcapHdr)
}

//ReadNextPacket read next packet. returns header,data,error
func (P *PCapReader) ReadNextPacket() (PcaprecHdrS, []byte, error) {
	pcaprecHdr := PcaprecHdrS{}
	err := binary.Read(P.FileHandle, binary.LittleEndian, &pcaprecHdr)
	if err != nil {
		return pcaprecHdr, nil, err
	}
	buf := make([]byte, pcaprecHdr.InclLen)
	err2 := binary.Read(P.FileHandle, binary.LittleEndian, &buf)
	return pcaprecHdr, buf, err2
}

//Close pcap file
func (P *PCapReader) Close() error {
	return P.FileHandle.Close()
}
