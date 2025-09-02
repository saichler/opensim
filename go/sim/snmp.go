package main

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
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

		var responsePacket []byte

		// Check if this is SNMPv3 request
		if isSNMPv3Request(requestData) {
			responsePacket = s.handleSNMPv3Request(requestData)
		} else {
			responsePacket = s.handleSNMPv2cRequest(requestData)
		}

		// Send response
		if len(responsePacket) > 0 {
			_, err = s.listener.WriteToUDP(responsePacket, clientAddr)
			if err != nil {
				log.Printf("Error sending SNMP response: %v", err)
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
	
	if pduType == ASN1_GET_NEXT {
		// Handle GetNext request for SNMP walk
		responseOID, response = s.findNextOID(oid)
		if responseOID == "" {
			// End of MIB view - use a special response
			responseOID = oid
			response = "endOfMibView"
		}
		// log.Printf("SNMP %s: GetNext %s -> %s = %s", s.device.ID, oid, responseOID, response)
	} else {
		// Handle regular Get request
		responseOID = oid
		response = s.findResponse(oid)
		// log.Printf("SNMP %s: Get %s -> %s", s.device.ID, oid, response)
	}

	// Create proper SNMP response (pass the request data)
	return s.createSNMPResponse(responseOID, response, requestData)
}

// handleSNMPv3Request handles SNMPv3 requests with USM authentication
func (s *SNMPServer) handleSNMPv3Request(requestData []byte) []byte {
	// Check if SNMPv3 is enabled
	if s.v3Config == nil || !s.v3Config.Enabled {
		// log.Printf("SNMPv3 request received but SNMPv3 not enabled")
		return []byte{} // Return empty response
	}

	// Parse SNMPv3 message
	v3Msg, err := s.parseSNMPv3Message(requestData)
	if err != nil {
		// log.Printf("Error parsing SNMPv3 message: %v", err)
		return []byte{}
	}

	// Check if this is a discovery request
	isDiscovery := v3Msg.SecurityParams.UserName == "" && 
		v3Msg.SecurityParams.AuthoritativeEngineID == ""
	
	// Validate credentials (discovery requests are allowed through)
	if !s.validateSNMPv3Credentials(v3Msg) {
		// log.Printf("SNMPv3 authentication failed")
		return []byte{}
	}
	
	if isDiscovery {
		// log.Printf("SNMPv3: Processing discovery request")
		// For discovery, return a report with our engine ID
		return s.createSNMPv3DiscoveryResponse(v3Msg)
	}

	// log.Printf("SNMPv3: Authenticated user: %s, flags: 0x%02X", 
	//	v3Msg.SecurityParams.UserName, v3Msg.GlobalData.MsgFlags)

	// Handle scoped PDU decryption
	scopedPDU := v3Msg.ScopedPDU
	if v3Msg.GlobalData.MsgFlags&SNMPV3_MSG_FLAG_PRIV != 0 {
		// log.Printf("SNMPv3: Privacy enabled, attempting decryption")
		decryptedPDU, err := s.decryptScopedPDU(v3Msg.ScopedPDU, v3Msg.SecurityParams.PrivParams)
		if err != nil {
			// log.Printf("SNMPv3: Failed to decrypt scoped PDU: %v", err)
			// log.Printf("SNMPv3: Using default OID for encrypted request (decryption failed)")
		} else {
			// log.Printf("SNMPv3: Successfully decrypted scoped PDU (%d bytes)", len(decryptedPDU))
			// Verify the decrypted data looks valid (starts with SEQUENCE tag)
			if len(decryptedPDU) > 0 && decryptedPDU[0] == ASN1_SEQUENCE {
				scopedPDU = decryptedPDU
				// log.Printf("SNMPv3: Decrypted data appears valid (starts with SEQUENCE)")
			} else {
				// log.Printf("SNMPv3: Decrypted data appears invalid (tag: 0x%02X), using default OID", 
				//	func() byte { if len(decryptedPDU) > 0 { return decryptedPDU[0] } else { return 0 } }())
			}
		}
	}

	// Parse the scoped PDU to extract OID and request type
	oid, pduType, err := s.extractOIDAndTypeFromScopedPDU(scopedPDU)
	if err != nil {
		log.Printf("Failed to extract OID from scoped PDU: %v, using default", err)
		// For encrypted requests where decryption failed, use a reasonable default
		// Since snmpwalk typically starts with 1.3.6.1.2.1.1, use system description
		oid = "1.3.6.1.2.1.1.1.0" // System description OID
		pduType = ASN1_GET_REQUEST // Default to GET
		// log.Printf("SNMPv3: Using default OID %s for failed decryption case", oid)
	}

	// Handle GetNext request for SNMP walk (same logic as SNMPv2)
	var responseOID string
	var response string
	
	if pduType == ASN1_GET_NEXT {
		// log.Printf("SNMPv3: Processing GetNext request for OID: %s", oid)
		responseOID, response = s.findNextOID(oid)
		if responseOID == "" {
			// End of MIB view - use a special response
			responseOID = oid
			response = "endOfMibView"
		}
		// log.Printf("SNMPv3 %s: GetNext %s -> %s = %s", s.device.ID, oid, responseOID, response)
	} else {
		// Handle regular Get request
		responseOID = oid
		response = s.findResponse(oid)
		// log.Printf("SNMPv3 %s: Get %s -> %s", s.device.ID, oid, response)
	}

	// Create SNMPv3 response (use responseOID for the response)
	responseBytes, err := s.createSNMPv3Response(responseOID, response, v3Msg)
	if err != nil {
		log.Printf("Error creating SNMPv3 response: %v", err)
		return []byte{}
	}
	return responseBytes
}

// extractOIDFromScopedPDU extracts the first OID from a scoped PDU
func (s *SNMPServer) extractOIDFromScopedPDU(scopedPDU []byte) (string, error) {
	if len(scopedPDU) < 10 {
		return "", fmt.Errorf("scoped PDU too short")
	}

	pos := 0
	
	// Parse contextEngineID (OCTET STRING)
	if pos >= len(scopedPDU) || scopedPDU[pos] != ASN1_OCTET_STRING {
		return "", fmt.Errorf("expected contextEngineID OCTET STRING")
	}
	pos++
	engineIDLen, newPos := parseLength(scopedPDU, pos)
	pos = newPos + engineIDLen
	
	// Parse contextName (OCTET STRING)
	if pos >= len(scopedPDU) || scopedPDU[pos] != ASN1_OCTET_STRING {
		return "", fmt.Errorf("expected contextName OCTET STRING")
	}
	pos++
	contextNameLen, newPos := parseLength(scopedPDU, pos)
	pos = newPos + contextNameLen
	
	// Parse PDU - should be GetRequest (0xA0) or GetNext (0xA1)
	if pos >= len(scopedPDU) {
		return "", fmt.Errorf("unexpected end of scoped PDU")
	}
	
	pduType := scopedPDU[pos]
	
	if pduType != ASN1_GET_REQUEST && pduType != ASN1_GET_NEXT {
		return "", fmt.Errorf("unsupported PDU type in scoped PDU: 0x%02X", pduType)
	}
	pos++
	
	// Skip PDU length
	_, newPos = parseLength(scopedPDU, pos)
	pos = newPos
	
	// Parse request ID, error status, error index (skip them)
	for i := 0; i < 3; i++ {
		if pos >= len(scopedPDU) || scopedPDU[pos] != ASN1_INTEGER {
			return "", fmt.Errorf("expected INTEGER in PDU")
		}
		pos++
		intLen, newPos := parseLength(scopedPDU, pos)
		pos = newPos + intLen
	}
	
	// Parse variable bindings (SEQUENCE)
	if pos >= len(scopedPDU) || scopedPDU[pos] != ASN1_SEQUENCE {
		return "", fmt.Errorf("expected variable bindings SEQUENCE")
	}
	pos++
	_, newPos = parseLength(scopedPDU, pos)
	pos = newPos
	
	// Parse first variable binding (SEQUENCE)
	if pos >= len(scopedPDU) || scopedPDU[pos] != ASN1_SEQUENCE {
		return "", fmt.Errorf("expected first variable binding SEQUENCE")
	}
	pos++
	_, newPos = parseLength(scopedPDU, pos)
	pos = newPos
	
	// Parse OID (OBJECT IDENTIFIER)
	if pos >= len(scopedPDU) || scopedPDU[pos] != ASN1_OBJECT_ID {
		return "", fmt.Errorf("expected OID in variable binding")
	}
	pos++
	oidLen, newPos := parseLength(scopedPDU, pos)
	pos = newPos
	
	if pos+oidLen > len(scopedPDU) {
		return "", fmt.Errorf("OID length exceeds remaining data")
	}
	
	oidBytes := scopedPDU[pos : pos+oidLen]
	oid := decodeOID(oidBytes)
	
	return oid, nil
}

// extractOIDAndTypeFromScopedPDU extracts both OID and PDU type from a scoped PDU
func (s *SNMPServer) extractOIDAndTypeFromScopedPDU(scopedPDU []byte) (string, byte, error) {
	if len(scopedPDU) < 10 {
		return "", ASN1_GET_REQUEST, fmt.Errorf("scoped PDU too short")
	}

	pos := 0
	
	// Parse contextEngineID (OCTET STRING)
	if pos >= len(scopedPDU) || scopedPDU[pos] != ASN1_OCTET_STRING {
		return "", ASN1_GET_REQUEST, fmt.Errorf("expected contextEngineID OCTET STRING")
	}
	pos++
	engineIDLen, newPos := parseLength(scopedPDU, pos)
	pos = newPos + engineIDLen
	
	// Parse contextName (OCTET STRING)
	if pos >= len(scopedPDU) || scopedPDU[pos] != ASN1_OCTET_STRING {
		return "", ASN1_GET_REQUEST, fmt.Errorf("expected contextName OCTET STRING")
	}
	pos++
	contextNameLen, newPos := parseLength(scopedPDU, pos)
	pos = newPos + contextNameLen
	
	// Parse PDU - should be GetRequest (0xA0) or GetNext (0xA1)
	if pos >= len(scopedPDU) {
		return "", ASN1_GET_REQUEST, fmt.Errorf("unexpected end of scoped PDU")
	}
	
	pduType := scopedPDU[pos]
	
	if pduType != ASN1_GET_REQUEST && pduType != ASN1_GET_NEXT {
		return "", ASN1_GET_REQUEST, fmt.Errorf("unsupported PDU type in scoped PDU: 0x%02X", pduType)
	}
	pos++
	
	// Skip PDU length
	_, newPos = parseLength(scopedPDU, pos)
	pos = newPos
	
	// Parse request ID, error status, error index (skip them)
	for i := 0; i < 3; i++ {
		if pos >= len(scopedPDU) || scopedPDU[pos] != ASN1_INTEGER {
			return "", pduType, fmt.Errorf("expected INTEGER in PDU")
		}
		pos++
		intLen, newPos := parseLength(scopedPDU, pos)
		pos = newPos + intLen
	}
	
	// Parse variable bindings (SEQUENCE)
	if pos >= len(scopedPDU) || scopedPDU[pos] != ASN1_SEQUENCE {
		return "", pduType, fmt.Errorf("expected variable bindings SEQUENCE")
	}
	pos++
	_, newPos = parseLength(scopedPDU, pos)
	pos = newPos
	
	// Parse first variable binding (SEQUENCE)
	if pos >= len(scopedPDU) || scopedPDU[pos] != ASN1_SEQUENCE {
		return "", pduType, fmt.Errorf("expected first variable binding SEQUENCE")
	}
	pos++
	_, newPos = parseLength(scopedPDU, pos)
	pos = newPos
	
	// Parse OID (OBJECT IDENTIFIER)
	if pos >= len(scopedPDU) || scopedPDU[pos] != ASN1_OBJECT_ID {
		return "", pduType, fmt.Errorf("expected OID in variable binding")
	}
	pos++
	oidLen, newPos := parseLength(scopedPDU, pos)
	pos = newPos
	
	if pos+oidLen > len(scopedPDU) {
		return "", pduType, fmt.Errorf("OID length exceeds remaining data")
	}
	
	oidBytes := scopedPDU[pos : pos+oidLen]
	oid := decodeOID(oidBytes)
	
	return oid, pduType, nil
}

// createSNMPv3DiscoveryResponse creates a discovery response with engine ID
func (s *SNMPServer) createSNMPv3DiscoveryResponse(requestMsg *SNMPv3Message) []byte {
	if s.v3Config == nil || !s.v3Config.Enabled {
		return []byte{}
	}
	
	// log.Printf("SNMPv3: Creating discovery response with engine ID: %s", s.v3Config.EngineID)
	
	// Create discovery response scoped PDU (typically a report PDU)
	reportOID := "1.3.6.1.6.3.15.1.1.4.0" // usmStatsUnknownEngineIDs
	reportValue := "1" // Counter value
	
	// Create simple report scoped PDU
	scopedPDU, err := s.createDiscoveryScopedPDU(reportOID, reportValue)
	if err != nil {
		log.Printf("Failed to create discovery scoped PDU: %v", err)
		return []byte{}
	}
	
	// Create USM security parameters for discovery response
	secParams := SNMPv3SecurityParams{
		AuthoritativeEngineID:    s.v3Config.EngineID,
		AuthoritativeEngineBoots: 1,
		AuthoritativeEngineTime:  int(time.Now().Unix()),
		UserName:                 "", // Empty for discovery
		AuthParams:               []byte{},
		PrivParams:               []byte{},
	}
	
	// Encode USM parameters
	usmParams, err := s.encodeUSMSecurityParameters(&secParams)
	if err != nil {
		log.Printf("Failed to encode USM parameters for discovery: %v", err)
		return []byte{}
	}
	
	// Create response message structure
	responseMsg := SNMPv3Message{
		Version: SNMPV3_VERSION,
		GlobalData: SNMPv3GlobalData{
			MsgID:           requestMsg.GlobalData.MsgID,
			MsgMaxSize:      65507,
			MsgFlags:        SNMPV3_MSG_FLAG_REPORT, // Set report flag
			MsgSecurityModel: SNMPV3_SECURITY_MODEL_USM,
		},
		ScopedPDU: scopedPDU,
	}
	
	// Encode the message
	msgBytes, err := s.encodeSNMPv3Message(&responseMsg, usmParams)
	if err != nil {
		log.Printf("Failed to encode SNMPv3 discovery message: %v", err)
		return []byte{}
	}
	
	return msgBytes
}

// createDiscoveryScopedPDU creates a scoped PDU for discovery responses
func (s *SNMPServer) createDiscoveryScopedPDU(oid, value string) ([]byte, error) {
	// Create integer value for report counter
	valueBytes := encodeInteger(1)
	
	// Create variable binding
	oidBytes := encodeOID(oid)
	varBind := encodeSequence(append(oidBytes, valueBytes...))
	varBindList := encodeSequence(varBind)
	
	// Create Report PDU (0xA8)
	pduContents := []byte{}
	pduContents = append(pduContents, encodeInteger(1)...) // request-id
	pduContents = append(pduContents, encodeInteger(0)...) // error-status
	pduContents = append(pduContents, encodeInteger(0)...) // error-index
	pduContents = append(pduContents, varBindList...)      // variable-bindings
	
	// Report PDU
	pdu := []byte{0xA8} // Report PDU type
	pdu = append(pdu, encodeLength(len(pduContents))...)
	pdu = append(pdu, pduContents...)
	
	// Scoped PDU: contextEngineID + contextName + data
	contextEngineID := encodeOctetString(s.v3Config.EngineID)
	contextName := encodeOctetString("") // Default context
	
	scopedContents := []byte{}
	scopedContents = append(scopedContents, contextEngineID...)
	scopedContents = append(scopedContents, contextName...)
	scopedContents = append(scopedContents, pdu...)
	
	return encodeSequence(scopedContents), nil
}

func (s *SNMPServer) findResponse(oid string) string {
	// Handle dynamic sysLocation OID
	if oid == "1.3.6.1.2.1.1.6.0" {
		return s.device.sysLocation
	}
	
	// Handle dynamic sysName OID
	if oid == "1.3.6.1.2.1.1.5.0" {
		return s.device.sysName
	}
	
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
	
	// Add dynamic sysName OID if it's greater than currentOID
	sysNameOID := "1.3.6.1.2.1.1.5.0"
	if compareOIDs(sysNameOID, currentOID) > 0 {
		candidates = append(candidates, SNMPResource{
			OID:      sysNameOID,
			Response: s.device.sysName,
		})
	}
	
	// Add dynamic sysLocation OID if it's greater than currentOID
	sysLocationOID := "1.3.6.1.2.1.1.6.0"
	if compareOIDs(sysLocationOID, currentOID) > 0 {
		candidates = append(candidates, SNMPResource{
			OID:      sysLocationOID,
			Response: s.device.sysLocation,
		})
	}
	
	// Find all OIDs that are lexicographically greater than currentOID
	for _, resource := range s.device.resources.SNMP {
		// Skip the dynamic OIDs from resources since we handle them dynamically
		if resource.OID == sysLocationOID || resource.OID == sysNameOID {
			continue
		}
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
	} else if value > 0 {
		// Positive integer
		temp := value
		for temp > 0 {
			bytes = append([]byte{byte(temp & 0xff)}, bytes...)
			temp >>= 8
		}
		// Add leading zero if high bit is set (to keep it positive)
		if len(bytes) > 0 && bytes[0]&0x80 != 0 {
			bytes = append([]byte{0x00}, bytes...)
		}
	} else {
		// Negative integer - use two's complement representation
		temp := uint64(value) // Convert to unsigned for bit manipulation
		// For negative numbers, we need to ensure proper two's complement encoding
		if value >= -128 && value < 0 {
			bytes = []byte{byte(temp)}
		} else if value >= -32768 && value < 0 {
			bytes = []byte{byte(temp >> 8), byte(temp)}
		} else if value >= -8388608 && value < 0 {
			bytes = []byte{byte(temp >> 16), byte(temp >> 8), byte(temp)}
		} else {
			// For larger negative numbers, use full 32-bit representation
			bytes = []byte{byte(temp >> 24), byte(temp >> 16), byte(temp >> 8), byte(temp)}
		}
		
		// Ensure we have the minimum number of bytes for negative representation
		// If the high bit is not set, we need to add 0xFF prefix to maintain negative value
		if len(bytes) > 0 && bytes[0]&0x80 == 0 {
			bytes = append([]byte{0xFF}, bytes...)
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
	
	// First, collect all the 7-bit chunks in reverse order
	var chunks []byte
	for temp > 0 {
		chunks = append(chunks, byte(temp & 0x7f))
		temp >>= 7
	}
	
	// Now build the result with proper bit flags
	// All bytes except the last should have the high bit set
	for i := len(chunks) - 1; i >= 0; i-- {
		if i > 0 {
			result = append(result, chunks[i] | 0x80) // Set high bit for continuation
		} else {
			result = append(result, chunks[i]) // Last byte, no high bit
		}
	}
	
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


	// Parse the SNMP packet structure
	// SEQUENCE { version, community, PDU }
	pos := 0

	// Skip SEQUENCE tag and length
	if data[pos] != ASN1_SEQUENCE {
		return req
	}
	pos++
	lengthSkip := s.skipLength(data[pos:])
	pos += lengthSkip

	// Parse version
	if pos < len(data) && data[pos] == ASN1_INTEGER {
		pos++
		versionLen := int(data[pos])
		pos++
		if pos+versionLen <= len(data) && versionLen == 1 {
			req.Version = int(data[pos])
			pos += versionLen
		} else {
			pos += versionLen // skip if we can't parse
		}
	}

	// Parse community
	if pos < len(data) && data[pos] == ASN1_OCTET_STRING {
		pos++
		communityLen := int(data[pos])
		pos++
		if pos+communityLen <= len(data) {
			req.Community = string(data[pos : pos+communityLen])
			pos += communityLen
		}
	}

	// Parse PDU (GetRequest = 0xa0, GetNext = 0xa1)
	if pos < len(data) && (data[pos] == 0xa0 || data[pos] == 0xa1) {
		pos++
		pduLengthSkip := s.skipLength(data[pos:])
		pos += pduLengthSkip

		// Parse request ID
		if pos < len(data) && data[pos] == ASN1_INTEGER {
			pos++
			reqIDLen := int(data[pos])
			pos++
			if pos+reqIDLen <= len(data) && reqIDLen <= 4 {
				req.RequestID = 0
				for i := 0; i < reqIDLen; i++ {
					req.RequestID = (req.RequestID << 8) | int(data[pos+i])
				}
				pos += reqIDLen
			}
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

// decryptScopedPDU decrypts an encrypted scoped PDU
func (s *SNMPServer) decryptScopedPDU(encryptedPDU []byte, privParams []byte) ([]byte, error) {
	if s.v3Config.PrivProtocol == SNMPV3_PRIV_NONE {
		return encryptedPDU, nil
	}
	
	// log.Printf("SNMPv3: Attempting to decrypt scoped PDU with privacy protocol")
	
	// Decrypt based on the configured privacy protocol
	switch s.v3Config.PrivProtocol {
	case SNMPV3_PRIV_DES:
		// log.Printf("SNMPv3: Using DES decryption")
		return s.decryptDES(encryptedPDU, privParams)
	case SNMPV3_PRIV_AES128:
		// log.Printf("SNMPv3: Using AES128 decryption")
		return s.decryptAES128(encryptedPDU, privParams)
	default:
		return nil, fmt.Errorf("unsupported privacy protocol: %d", s.v3Config.PrivProtocol)
	}
}

// generateDESKey generates a DES key from the privacy password using RFC 3414 method
func (s *SNMPServer) generateDESKey() []byte {
	// RFC 3414 compatible key derivation for SNMPv3 privacy
	// This is a simplified version that should work with standard SNMP clients
	
	// Step 1: Create auth key from password using MD5
	password := s.v3Config.PrivPassword
	if len(password) == 0 {
		password = s.v3Config.Password // Fallback to main password
	}
	
	// Create 1MB buffer with repeated password (RFC 3414)
	passwordBytes := []byte(password)
	keyBuffer := make([]byte, 1048576) // 1MB
	for i := 0; i < len(keyBuffer); i++ {
		keyBuffer[i] = passwordBytes[i%len(passwordBytes)]
	}
	
	// Hash the 1MB buffer with MD5
	authKey := md5.Sum(keyBuffer)
	
	// Step 2: Localize the key with engine ID
	engineID := s.v3Config.EngineID
	if len(engineID) == 0 {
		engineID = "800000090300AABBCCDD" // Default engine ID
	}
	
	// Convert hex engine ID to bytes
	engineIDBytes, _ := s.parseHexEngineID(engineID)
	
	// Localize: MD5(authKey + engineID + authKey)
	localizeInput := append(append(authKey[:], engineIDBytes...), authKey[:]...)
	localizedKey := md5.Sum(localizeInput)
	
	// Step 3: For privacy key, derive from localized auth key
	// Privacy key = first 8 bytes of localized key for DES
	return localizedKey[:8]
}

// parseHexEngineID converts hex engine ID string to bytes
func (s *SNMPServer) parseHexEngineID(hexEngineID string) ([]byte, error) {
	// Remove any spaces or colons
	clean := ""
	for _, c := range hexEngineID {
		if (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f') {
			clean += string(c)
		}
	}
	
	// Convert hex pairs to bytes
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("invalid hex engine ID length")
	}
	
	result := make([]byte, len(clean)/2)
	for i := 0; i < len(clean); i += 2 {
		var b byte
		for j := 0; j < 2; j++ {
			c := clean[i+j]
			b <<= 4
			if c >= '0' && c <= '9' {
				b |= c - '0'
			} else if c >= 'A' && c <= 'F' {
				b |= c - 'A' + 10
			} else if c >= 'a' && c <= 'f' {
				b |= c - 'a' + 10
			}
		}
		result[i/2] = b
	}
	
	return result, nil
}

// decryptDES performs basic DES decryption (simplified for simulation)
func (s *SNMPServer) decryptDES(encryptedData []byte, privParams []byte) ([]byte, error) {
	if len(privParams) < 8 {
		return nil, fmt.Errorf("invalid DES privacy parameters length: %d", len(privParams))
	}
	
	// Generate DES key from privacy password using RFC 3414 method
	key := s.generateDESKey() // Use the same method as encryption
	iv := privParams[:8] // Use privacy parameters as IV
	
	// log.Printf("SNMPv3: DES decryption - key: %d bytes, IV: %d bytes, data: %d bytes", 
	//	len(key), len(iv), len(encryptedData))
	
	// For simulation purposes, implement basic DES-CBC decryption
	// In a real implementation, you'd need proper key derivation from the password
	
	// Create DES cipher
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create DES cipher: %v", err)
	}
	
	if len(encryptedData)%8 != 0 {
		return nil, fmt.Errorf("encrypted data length must be multiple of 8 bytes")
	}
	
	// Decrypt using CBC mode
	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(encryptedData))
	mode.CryptBlocks(decrypted, encryptedData)
	
	// Remove PKCS padding (simplified)
	if len(decrypted) > 0 {
		paddingLen := int(decrypted[len(decrypted)-1])
		if paddingLen <= len(decrypted) && paddingLen <= 8 {
			decrypted = decrypted[:len(decrypted)-paddingLen]
		}
	}
	
	// log.Printf("SNMPv3: DES decryption completed - result: %d bytes", len(decrypted))
	
	// Print hex dump of decrypted data for debugging
	// if len(decrypted) > 0 {
	//	log.Printf("Decrypted data hex:")
	//	for i := 0; i < len(decrypted) && i < 64; i += 16 {
	//		end := i + 16
	//		if end > len(decrypted) {
	//			end = len(decrypted)
	//		}
	//		hexStr := fmt.Sprintf("  %04X: ", i)
	//		for j := i; j < end; j++ {
	//			hexStr += fmt.Sprintf("%02X ", decrypted[j])
	//		}
	//		log.Printf(hexStr)
	//	}
	// }
	
	return decrypted, nil
}