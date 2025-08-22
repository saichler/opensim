package main

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
)

// SNMP Server implementation
func (s *SNMPServer) Start() error {
	addr := &net.UDPAddr{
		IP:   s.device.IP,
		Port: s.device.SNMPPort,
	}

	listener, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}

	s.listener = listener
	s.running = true

	go s.handleRequests()
	return nil
}

func (s *SNMPServer) Stop() error {
	if s.listener != nil {
		s.running = false
		return s.listener.Close()
	}
	return nil
}

func (s *SNMPServer) handleRequests() {
	buffer := make([]byte, 1024)

	for s.running {
		n, clientAddr, err := s.listener.ReadFromUDP(buffer)
		if err != nil {
			if s.running {
				log.Printf("SNMP server error reading UDP: %v", err)
			}
			continue
		}

		requestData := buffer[:n] // Store the full request

		// Debug: Print hex dump of request packet
		log.Printf("DEBUG: Request packet hex (%d bytes):", n)
		for i := 0; i < n && i < 64; i += 16 {
			end := i + 16
			if end > n {
				end = n
			}
			hexStr := fmt.Sprintf("  %04X: ", i)
			for j := i; j < end; j++ {
				hexStr += fmt.Sprintf("%02X ", requestData[j])
			}
			log.Printf(hexStr)
		}

		var responsePacket []byte

		// Check if this is SNMPv3 request
		if isSNMPv3Request(requestData) {
			log.Printf("DEBUG: Processing SNMPv3 request")
			responsePacket = s.handleSNMPv3Request(requestData)
		} else {
			log.Printf("DEBUG: Processing SNMPv1/v2c request")
			responsePacket = s.handleSNMPv2cRequest(requestData)
		}

		// Send response
		if len(responsePacket) > 0 {
			// Debug: Print hex dump of response packet
			log.Printf("DEBUG: Response packet hex (first 64 bytes):")
			for i := 0; i < len(responsePacket) && i < 64; i += 16 {
				end := i + 16
				if end > len(responsePacket) {
					end = len(responsePacket)
				}
				hexStr := fmt.Sprintf("  %04X: ", i)
				for j := i; j < end; j++ {
					hexStr += fmt.Sprintf("%02X ", responsePacket[j])
				}
				log.Printf(hexStr)
			}

			_, err = s.listener.WriteToUDP(responsePacket, clientAddr)
			if err != nil {
				log.Printf("Error sending SNMP response: %v", err)
			} else {
				log.Printf("DEBUG: Sent response packet (%d bytes)", len(responsePacket))
			}
		}
	}
}

// handleSNMPv2cRequest handles traditional SNMP v1/v2c requests
func (s *SNMPServer) handleSNMPv2cRequest(requestData []byte) []byte {
	// Parse SNMP request to get OID and request type
	req := s.parseIncomingRequest(requestData)
	oid := req.OID
	var response string
	var responseOID string

	// Determine PDU type from request data
	pduType := s.getPDUType(requestData)
	log.Printf("DEBUG: Received %s request for OID: %s (version=%d, community=%s, requestID=0x%X)", 
		map[byte]string{ASN1_GET_REQUEST: "GET", ASN1_GET_NEXT: "GETNEXT"}[pduType], oid, req.Version, req.Community, req.RequestID)
	
	if pduType == ASN1_GET_NEXT {
		// Handle GetNext request for SNMP walk
		responseOID, response = s.findNextOID(oid)
		if responseOID == "" {
			// End of MIB view - use a special response
			responseOID = oid
			response = "endOfMibView"
		}
		log.Printf("SNMP %s: GetNext %s -> %s = %s", s.device.ID, oid, responseOID, response)
		
		// Additional debug - show all available OIDs for comparison
		log.Printf("DEBUG: Available OIDs:")
		for i, res := range s.device.resources.SNMP[:5] { // Show first 5
			log.Printf("  %d: %s = %s", i, res.OID, res.Response)
		}
	} else {
		// Handle regular Get request
		responseOID = oid
		response = s.findResponse(oid)
		log.Printf("SNMP %s: Get %s -> %s", s.device.ID, oid, response)
	}

	// Create proper SNMP response (pass the request data)
	return s.createSNMPResponse(responseOID, response, requestData)
}

// handleSNMPv3Request handles SNMPv3 requests with USM authentication
func (s *SNMPServer) handleSNMPv3Request(requestData []byte) []byte {
	// Check if SNMPv3 is enabled
	if s.v3Config == nil || !s.v3Config.Enabled {
		log.Printf("SNMPv3 request received but SNMPv3 not enabled")
		return []byte{} // Return empty response
	}

	// Parse SNMPv3 message
	v3Msg, err := s.parseSNMPv3Message(requestData)
	if err != nil {
		log.Printf("Error parsing SNMPv3 message: %v", err)
		return []byte{}
	}

	// Validate credentials
	if !s.validateSNMPv3Credentials(v3Msg) {
		log.Printf("SNMPv3 authentication failed")
		return []byte{}
	}

	log.Printf("SNMPv3: Authenticated user: %s, flags: 0x%02X", 
		v3Msg.SecurityParams.UserName, v3Msg.GlobalData.MsgFlags)

	// Decrypt scoped PDU if encrypted
	_ = v3Msg.ScopedPDU
	if v3Msg.GlobalData.MsgFlags&SNMPV3_MSG_FLAG_PRIV != 0 {
		// TODO: Implement decryption
		log.Printf("SNMPv3: Privacy enabled but decryption not fully implemented")
	}

	// Parse the scoped PDU to extract OID and request type
	// For simplicity, we'll extract a basic OID - in a full implementation
	// you'd properly parse the scoped PDU structure
	oid := "1.3.6.1.2.1.1.1.0" // Default system description OID
	response := s.findResponse(oid)

	// Create SNMPv3 response
	responseBytes, err := s.createSNMPv3Response(oid, response, v3Msg)
	if err != nil {
		log.Printf("Error creating SNMPv3 response: %v", err)
		return []byte{}
	}

	log.Printf("SNMPv3 %s: Get %s -> %s", s.device.ID, oid, response)
	return responseBytes
}

func (s *SNMPServer) findResponse(oid string) string {
	for _, resource := range s.device.resources.SNMP {
		if resource.OID == oid {
			return resource.Response
		}
	}
	return "OID not supported"
}

// Compare two OIDs lexicographically
func compareOIDs(oid1, oid2 string) int {
	parts1 := strings.Split(oid1, ".")
	parts2 := strings.Split(oid2, ".")
	
	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}
	
	for i := 0; i < maxLen; i++ {
		var val1, val2 int
		
		if i < len(parts1) {
			val1, _ = strconv.Atoi(parts1[i])
		}
		if i < len(parts2) {
			val2, _ = strconv.Atoi(parts2[i])
		}
		
		if val1 < val2 {
			return -1
		} else if val1 > val2 {
			return 1
		}
	}
	
	if len(parts1) < len(parts2) {
		return -1
	} else if len(parts1) > len(parts2) {
		return 1
	}
	
	return 0
}

// Find the next OID in lexicographic order for SNMP GetNext requests
func (s *SNMPServer) findNextOID(currentOID string) (string, string) {
	var candidates []SNMPResource
	
	// Find all OIDs that are lexicographically greater than currentOID
	for _, resource := range s.device.resources.SNMP {
		if compareOIDs(resource.OID, currentOID) > 0 {
			candidates = append(candidates, resource)
		}
	}
	
	if len(candidates) == 0 {
		return "", "endOfMibView"
	}
	
	// Find the smallest OID among candidates (lexicographically first)
	nextOID := candidates[0]
	for _, candidate := range candidates[1:] {
		if compareOIDs(candidate.OID, nextOID.OID) < 0 {
			nextOID = candidate
		}
	}
	
	return nextOID.OID, nextOID.Response
}

// Extract PDU type from SNMP request
func (s *SNMPServer) getPDUType(data []byte) byte {
	if len(data) < 10 {
		return ASN1_GET_REQUEST // Default
	}

	pos := 0
	
	// Skip SEQUENCE tag and length
	if data[pos] != ASN1_SEQUENCE {
		return ASN1_GET_REQUEST
	}
	pos++
	pos += s.skipLength(data[pos:])
	
	// Skip version
	if pos < len(data) && data[pos] == ASN1_INTEGER {
		pos++
		pos += s.skipLength(data[pos:])
		pos++ // skip version value
	}
	
	// Skip community
	if pos < len(data) && data[pos] == ASN1_OCTET_STRING {
		pos++
		communityLen := int(data[pos])
		pos++
		pos += communityLen
	}
	
	// Get PDU type
	if pos < len(data) {
		return data[pos]
	}
	
	return ASN1_GET_REQUEST
}

// parseOIDFromRequest extracts the first OID from an SNMP request packet
func (s *SNMPServer) parseOIDFromRequest(data []byte) string {
	if len(data) < 10 {
		return "1.3.6.1.2.1.1.1.0" // Default fallback
	}

	// Find the OID in the SNMP packet
	oid := extractOIDFromSNMPPacket(data)
	if oid == "" {
		return "1.3.6.1.2.1.1.1.0" // Default fallback
	}

	return oid
}

// extractOIDFromSNMPPacket parses SNMP BER/DER encoded packet to find OID
func extractOIDFromSNMPPacket(data []byte) string {
	pos := 0

	// Parse the outer SEQUENCE
	if pos >= len(data) || data[pos] != ASN1_SEQUENCE {
		return ""
	}
	pos++

	// Skip length of outer sequence
	length, newPos := parseLength(data, pos)
	if length == -1 {
		return ""
	}
	pos = newPos

	// Parse SNMP version (INTEGER)
	if pos >= len(data) || data[pos] != ASN1_INTEGER {
		return ""
	}
	pos++

	// Skip version length and value
	versionLen, newPos := parseLength(data, pos)
	if versionLen == -1 {
		return ""
	}
	pos = newPos + versionLen

	// Parse community string (OCTET STRING)
	if pos >= len(data) || data[pos] != ASN1_OCTET_STRING {
		return ""
	}
	pos++

	// Skip community length and value
	communityLen, newPos := parseLength(data, pos)
	if communityLen == -1 {
		return ""
	}
	pos = newPos + communityLen

	// Parse PDU (GET_REQUEST, GET_NEXT, etc.)
	if pos >= len(data) {
		return ""
	}
	pduType := data[pos]
	if pduType != ASN1_GET_REQUEST && pduType != ASN1_GET_NEXT &&
		pduType != ASN1_SET_REQUEST && pduType != ASN1_GET_RESPONSE {
		return ""
	}
	pos++

	// Skip PDU length
	pduLen, newPos := parseLength(data, pos)
	if pduLen == -1 {
		return ""
	}
	pos = newPos

	// Parse request ID (INTEGER)
	if pos >= len(data) || data[pos] != ASN1_INTEGER {
		return ""
	}
	pos++

	// Skip request ID length and value
	reqIdLen, newPos := parseLength(data, pos)
	if reqIdLen == -1 {
		return ""
	}
	pos = newPos + reqIdLen

	// Parse error status (INTEGER)
	if pos >= len(data) || data[pos] != ASN1_INTEGER {
		return ""
	}
	pos++

	// Skip error status length and value
	errorLen, newPos := parseLength(data, pos)
	if errorLen == -1 {
		return ""
	}
	pos = newPos + errorLen

	// Parse error index (INTEGER)
	if pos >= len(data) || data[pos] != ASN1_INTEGER {
		return ""
	}
	pos++

	// Skip error index length and value
	errorIdxLen, newPos := parseLength(data, pos)
	if errorIdxLen == -1 {
		return ""
	}
	pos = newPos + errorIdxLen

	// Parse variable bindings (SEQUENCE)
	if pos >= len(data) || data[pos] != ASN1_SEQUENCE {
		return ""
	}
	pos++

	// Skip varbind list length
	varbindLen, newPos := parseLength(data, pos)
	if varbindLen == -1 {
		return ""
	}
	pos = newPos

	// Parse first variable binding (SEQUENCE)
	if pos >= len(data) || data[pos] != ASN1_SEQUENCE {
		return ""
	}
	pos++

	// Skip first varbind length
	firstVarbindLen, newPos := parseLength(data, pos)
	if firstVarbindLen == -1 {
		return ""
	}
	pos = newPos

	// Parse OID (OBJECT IDENTIFIER)
	if pos >= len(data) || data[pos] != ASN1_OBJECT_ID {
		return ""
	}
	pos++

	// Parse OID length
	oidLen, newPos := parseLength(data, pos)
	if oidLen == -1 || newPos+oidLen > len(data) {
		return ""
	}
	pos = newPos

	// Extract and decode the OID
	oidBytes := data[pos : pos+oidLen]
	return decodeOID(oidBytes)
}

// parseLength parses ASN.1 BER/DER length encoding
func parseLength(data []byte, pos int) (int, int) {
	if pos >= len(data) {
		return -1, pos
	}

	length := int(data[pos])
	pos++

	// Short form (length < 128)
	if length < 0x80 {
		return length, pos
	}

	// Long form
	lengthBytes := length & 0x7F
	if lengthBytes == 0 || lengthBytes > 4 || pos+lengthBytes > len(data) {
		return -1, pos
	}

	length = 0
	for i := 0; i < lengthBytes; i++ {
		length = (length << 8) | int(data[pos])
		pos++
	}

	return length, pos
}

// decodeOID converts ASN.1 encoded OID bytes to dot notation string
func decodeOID(oidBytes []byte) string {
	if len(oidBytes) == 0 {
		return ""
	}

	var oid []string

	// First byte encodes first two sub-identifiers
	// first = byte / 40, second = byte % 40
	firstByte := oidBytes[0]
	first := firstByte / 40
	second := firstByte % 40
	oid = append(oid, strconv.Itoa(int(first)))
	oid = append(oid, strconv.Itoa(int(second)))

	// Process remaining bytes
	pos := 1
	for pos < len(oidBytes) {
		value := 0

		// Parse variable length encoding (base 128)
		for pos < len(oidBytes) {
			b := oidBytes[pos]
			pos++

			value = (value << 7) | int(b&0x7F)

			// If high bit is 0, this is the last byte of this sub-identifier
			if (b & 0x80) == 0 {
				break
			}
		}

		oid = append(oid, strconv.Itoa(value))
	}

	return strings.Join(oid, ".")
}

// ASN.1 encoding helper functions
func encodeLength(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}

	// Long form
	var bytes []byte
	temp := length
	for temp > 0 {
		bytes = append([]byte{byte(temp & 0xff)}, bytes...)
		temp >>= 8
	}

	result := make([]byte, len(bytes)+1)
	result[0] = byte(0x80 | len(bytes))
	copy(result[1:], bytes)
	return result
}

func encodeInteger(value int) []byte {
	var bytes []byte
	if value == 0 {
		bytes = []byte{0x00}
	} else {
		temp := value
		for temp > 0 {
			bytes = append([]byte{byte(temp & 0xff)}, bytes...)
			temp >>= 8
		}
		// Add leading zero if high bit is set (to keep it positive)
		if bytes[0]&0x80 != 0 {
			bytes = append([]byte{0x00}, bytes...)
		}
	}

	result := []byte{ASN1_INTEGER}
	result = append(result, encodeLength(len(bytes))...)
	result = append(result, bytes...)
	return result
}

func encodeOctetString(value string) []byte {
	data := []byte(value)
	result := []byte{ASN1_OCTET_STRING}
	result = append(result, encodeLength(len(data))...)
	result = append(result, data...)
	return result
}

func encodeOID(oid string) []byte {
	parts := strings.Split(oid, ".")
	if len(parts) < 2 {
		return []byte{ASN1_OID, 0x00}
	}

	var encoded []byte

	// First two components are encoded as 40*first + second
	first, _ := strconv.Atoi(parts[0])
	second, _ := strconv.Atoi(parts[1])
	encoded = append(encoded, byte(40*first+second))

	// Encode remaining components
	for i := 2; i < len(parts); i++ {
		val, _ := strconv.Atoi(parts[i])
		encoded = append(encoded, encodeOIDComponent(val)...)
	}

	result := []byte{ASN1_OID}
	result = append(result, encodeLength(len(encoded))...)
	result = append(result, encoded...)
	return result
}

func encodeOIDComponent(value int) []byte {
	if value < 0x80 {
		return []byte{byte(value)}
	}

	var result []byte
	temp := value
	for temp > 0x7f {
		result = append([]byte{byte((temp & 0x7f) | 0x80)}, result...)
		temp >>= 7
	}
	result = append([]byte{byte(temp)}, result...)
	return result
}

func encodeSequence(contents []byte) []byte {
	result := []byte{ASN1_SEQUENCE}
	result = append(result, encodeLength(len(contents))...)
	result = append(result, contents...)
	return result
}

func encodeNull() []byte {
	return []byte{ASN1_NULL, 0x00}
}

// SNMP request parser
type SNMPRequest struct {
	Community string
	RequestID int
	OID       string
	Version   int
}

// Parse incoming SNMP request to extract all needed info
func (s *SNMPServer) parseIncomingRequest(data []byte) SNMPRequest {
	req := SNMPRequest{
		Community: "public",
		RequestID: 1,
		OID:       "1.3.6.1.2.1.1.1.0",
		Version:   1, // Default to SNMPv2c
	}

	if len(data) < 10 {
		return req
	}

	log.Printf("DEBUG: Starting parse, data length: %d", len(data))

	// Parse the SNMP packet structure
	// SEQUENCE { version, community, PDU }
	pos := 0

	// Skip SEQUENCE tag and length
	if data[pos] != ASN1_SEQUENCE {
		log.Printf("DEBUG: Expected SEQUENCE tag at pos %d, got 0x%02X", pos, data[pos])
		return req
	}
	log.Printf("DEBUG: Found SEQUENCE at pos %d", pos)
	pos++
	lengthSkip := s.skipLength(data[pos:])
	log.Printf("DEBUG: Skipping %d bytes for SEQUENCE length", lengthSkip)
	pos += lengthSkip

	// Parse version
	if pos < len(data) && data[pos] == ASN1_INTEGER {
		log.Printf("DEBUG: Found version INTEGER at pos %d", pos)
		pos++
		versionLen := int(data[pos])
		log.Printf("DEBUG: Version length: %d", versionLen)
		pos++
		if pos+versionLen <= len(data) && versionLen == 1 {
			req.Version = int(data[pos])
			log.Printf("DEBUG: Version: %d", req.Version)
			pos += versionLen
		} else {
			log.Printf("DEBUG: Skipping version, invalid length")
			pos += versionLen // skip if we can't parse
		}
	}

	// Parse community
	if pos < len(data) && data[pos] == ASN1_OCTET_STRING {
		log.Printf("DEBUG: Found community STRING at pos %d", pos)
		pos++
		communityLen := int(data[pos])
		log.Printf("DEBUG: Community length: %d", communityLen)
		pos++
		if pos+communityLen <= len(data) {
			req.Community = string(data[pos : pos+communityLen])
			log.Printf("DEBUG: Community: %s", req.Community)
			pos += communityLen
		}
	}

	// Parse PDU (GetRequest = 0xa0, GetNext = 0xa1)
	log.Printf("DEBUG: Looking for PDU at pos %d, byte: 0x%02X", pos, data[pos])
	if pos < len(data) && (data[pos] == 0xa0 || data[pos] == 0xa1) {
		pduType := data[pos]
		log.Printf("DEBUG: Found PDU type 0x%02X at pos %d", pduType, pos)
		pos++
		pduLengthSkip := s.skipLength(data[pos:])
		log.Printf("DEBUG: Skipping %d bytes for PDU length", pduLengthSkip)
		pos += pduLengthSkip

		// Parse request ID
		log.Printf("DEBUG: Looking for request ID at pos %d, byte: 0x%02X", pos, data[pos])
		if pos < len(data) && data[pos] == ASN1_INTEGER {
			log.Printf("DEBUG: Found request ID INTEGER at pos %d", pos)
			pos++
			reqIDLen := int(data[pos])
			log.Printf("DEBUG: Request ID length: %d", reqIDLen)
			pos++
			if pos+reqIDLen <= len(data) && reqIDLen <= 4 {
				req.RequestID = 0
				log.Printf("DEBUG: Request ID bytes at pos %d:", pos)
				for i := 0; i < reqIDLen; i++ {
					log.Printf("  byte[%d] = 0x%02X", i, data[pos+i])
					req.RequestID = (req.RequestID << 8) | int(data[pos+i])
				}
				pos += reqIDLen
				log.Printf("DEBUG: Parsed Request ID: 0x%X (%d bytes)", req.RequestID, reqIDLen)
			} else {
				log.Printf("DEBUG: Invalid request ID length or bounds")
			}
		} else {
			log.Printf("DEBUG: No INTEGER tag for request ID")
		}

		// Skip error-status and error-index
		for i := 0; i < 2; i++ {
			if pos < len(data) && data[pos] == ASN1_INTEGER {
				pos++
				pos += s.skipLength(data[pos:])
				pos++ // skip value
			}
		}

		// Parse variable bindings
		if pos < len(data) && data[pos] == ASN1_SEQUENCE {
			pos++
			pos += s.skipLength(data[pos:])

			// First variable binding
			if pos < len(data) && data[pos] == ASN1_SEQUENCE {
				pos++
				pos += s.skipLength(data[pos:])

				// Parse OID
				if pos < len(data) && data[pos] == ASN1_OID {
					pos++
					oidLen := int(data[pos])
					pos++
					if pos+oidLen <= len(data) {
						oidBytes := data[pos : pos+oidLen]
						if oid := decodeOID(oidBytes); oid != "" {
							req.OID = oid
						}
					}
				}
			}
		}
	}

	return req
}

// Helper to skip length bytes
func (s *SNMPServer) skipLength(data []byte) int {
	if len(data) == 0 {
		return 0
	}

	if data[0] < 0x80 {
		return 1
	}

	lengthBytes := int(data[0] & 0x7f)
	return 1 + lengthBytes
}

// Create proper SNMP response packet
func (s *SNMPServer) createSNMPResponse(oid, value string, requestData []byte) []byte {
	// Parse incoming request to get actual community and request ID
	req := s.parseIncomingRequest(requestData)

	// Determine SNMP data type based on OID and value
	var valueBytes []byte

	if value == "endOfMibView" {
		// Special handling for endOfMibView (SNMPv2c)
		valueBytes = []byte{0x82, 0x00} // endOfMibView exception
	} else if intVal, err := strconv.Atoi(value); err == nil {
		// Integer value
		valueBytes = encodeInteger(intVal)
	} else {
		// String value
		valueBytes = encodeOctetString(value)
	}

	// Create variable binding (OID + value)
	oidBytes := encodeOID(oid)
	varBind := encodeSequence(append(oidBytes, valueBytes...))

	// Variable bindings list
	varBindList := encodeSequence(varBind)

	// PDU contents: request-id, error-status, error-index, variable-bindings
	pduContents := []byte{}
	pduContents = append(pduContents, encodeInteger(req.RequestID)...) // Use actual request ID
	pduContents = append(pduContents, encodeInteger(0)...)             // error-status (noError)
	pduContents = append(pduContents, encodeInteger(0)...)             // error-index
	pduContents = append(pduContents, varBindList...)                  // variable-bindings

	// GetResponse PDU
	pdu := []byte{SNMP_GET_RESPONSE}
	pdu = append(pdu, encodeLength(len(pduContents))...)
	pdu = append(pdu, pduContents...)

	// Message contents: version, community, PDU
	msgContents := []byte{}
	msgContents = append(msgContents, encodeInteger(req.Version)...)       // Use client's version
	msgContents = append(msgContents, encodeOctetString(req.Community)...) // Use actual community
	msgContents = append(msgContents, pdu...)                              // PDU

	// Complete SNMP message
	return encodeSequence(msgContents)
}