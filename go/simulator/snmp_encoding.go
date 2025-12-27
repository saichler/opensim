/*
 * © 2025 Sharon Aicler (saichler@gmail.com)
 *
 * Layer 8 Ecosystem is licensed under the Apache License, Version 2.0.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"strconv"
	"strings"
)

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
		chunks = append(chunks, byte(temp&0x7f))
		temp >>= 7
	}

	// Now build the result with proper bit flags
	// All bytes except the last should have the high bit set
	for i := len(chunks) - 1; i >= 0; i-- {
		if i > 0 {
			result = append(result, chunks[i]|0x80) // Set high bit for continuation
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
		pduType != ASN1_SET_REQUEST && pduType != ASN1_GET_RESPONSE && pduType != ASN1_GET_BULK {
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
