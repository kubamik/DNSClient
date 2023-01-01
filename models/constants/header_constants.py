HEADER_LENGTH = 12

HEADER_ID_SECTION = slice(0, 2)
HEADER_ID_SECTION_LENGTH_BITS = 16
HEADER_FLAGS_SECTION = slice(2, 4)
HEADER_QDCOUNT_SECTION = slice(4, 6)
HEADER_ANCOUNT_SECTION = slice(6, 8)
HEADER_NSCOUNT_SECTION = slice(8, 10)
HEADER_ARCOUNT_SECTION = slice(10, 12)

HEADER_QR_MASK = 0b1000000000000000
HEADER_QR_SHIFT = 15
HEADER_OPCODE_MASK = 0b0111100000000000
HEADER_OPCODE_SHIFT = 11
HEADER_AA_MASK = 0b0000010000000000
HEADER_AA_SHIFT = 10
HEADER_TC_MASK = 0b0000001000000000
HEADER_TC_SHIFT = 9
HEADER_RD_MASK = 0b0000000100000000
HEADER_RD_SHIFT = 8
HEADER_RA_MASK = 0b0000000010000000
HEADER_RA_SHIFT = 7
HEADER_Z_MASK = 0b0000000001110000
HEADER_Z_SHIFT = 4
HEADER_RCODE_MASK = 0b0000000000001111
HEADER_RCODE_SHIFT = 0