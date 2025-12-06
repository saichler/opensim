package main

// SNMP ASN.1 BER/DER type tags (shared constants defined here)
const (
	ASN1_SEQUENCE     = 0x30
	ASN1_INTEGER      = 0x02
	ASN1_OCTET_STRING = 0x04
	ASN1_NULL         = 0x05
	ASN1_OBJECT_ID    = 0x06
	ASN1_GET_REQUEST  = 0xA0
	ASN1_GET_NEXT     = 0xA1
	ASN1_GET_RESPONSE = 0xA2
	ASN1_SET_REQUEST  = 0xA3
	ASN1_GET_BULK     = 0xA5
	ASN1_OID          = 0x06
	SNMP_GET_RESPONSE = 0xa2
)

// SNMPv3 specific constants
const (
	SNMPV3_VERSION            = 3
	SNMPV3_MSG_FLAG_AUTH      = 0x01
	SNMPV3_MSG_FLAG_PRIV      = 0x02
	SNMPV3_MSG_FLAG_REPORT    = 0x04
	SNMPV3_SECURITY_MODEL_USM = 3
	SNMPV3_AUTH_NONE          = 0
	SNMPV3_AUTH_MD5           = 1
	SNMPV3_AUTH_SHA1          = 2
	SNMPV3_PRIV_NONE          = 0
	SNMPV3_PRIV_DES           = 1
	SNMPV3_PRIV_AES128        = 2
)

// Configuration constants
const (
	DEFAULT_SNMP_PORT = 161
	DEFAULT_SSH_PORT  = 22
	DEFAULT_API_PORT  = 8443 // HTTPS API port for storage devices
	USERNAME          = "simadmin"
	PASSWORD          = "simadmin"
	TUN_DEVICE_PREFIX = "sim"
)

// Global manager instance
var manager *SimulatorManager
