package ssh

type DirectTCPIPPayload struct {
	HostToConnect       string
	PortToConnect       uint32
	OriginatorIPAddress string
	OriginatorPort      uint32
}
