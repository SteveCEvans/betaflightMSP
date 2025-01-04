from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame

class Hla(HighLevelAnalyzer):
    """
    Betaflight MSP (MultiWii Serial Protocol) Decoder for Saleae Logic 2.
    Compatible with MSP V1, looking for either '$M<' or '$M>'.
    """

    result_types = {
        'msp_frame': {
            'format': '{{data.info}}'
        },
        'msp_error': {
            'format': '{{data.error}}'
        }
    }

    def __init__(self):
        """
        Initialize any state you need for decoding, such as buffers, pointers, etc.
        """
        self.buffer = bytearray()
        self.start_time = None

        # We’ll look for either of these two possible headers:
        self.HEADERS = [b"$M<", b"$M>"]
        
        print("[DEBUG] Hla initialized. Ready to parse MSP packets (either $M< or $M>).")

    def decode(self, frame: AnalyzerFrame):
        """
        Called for every input frame from the lower-level analyzer (Async Serial).
        Each frame contains raw bytes from the serial data.
        """
        if frame.type != 'data':
            print(f"[DEBUG] Skipping non-data frame: {frame.type}")
            return None

        # Convert the byte(s) to an integer
        byte_value = int.from_bytes(frame.data['data'], byteorder='little')
        print(f"[DEBUG] Received new byte: 0x{byte_value:02X}")

        if self.start_time is None:
            self.start_time = frame.start_time
            print("[DEBUG] No existing start_time; setting it now.")

        # Append this byte to our buffer
        self.buffer.append(byte_value)
        print(f"[DEBUG] Buffer appended: {self.buffer.hex()} (len={len(self.buffer)})")

        results = []

        while True:
            # Minimum length for MSP v1 is 6 bytes:
            # 3 (header: '$M<' or '$M>') + 1 (payload_size) + 1 (cmd) + 1 (checksum)
            if len(self.buffer) < 6:
                print(f"[DEBUG] Not enough data to parse a full MSP frame (len={len(self.buffer)}).")
                break

            # Find the earliest occurrence of either $M< or $M>
            header_index, header_found = self.find_earliest_header(self.buffer, self.HEADERS)
            if header_index == -1:
                # Neither header is found; discard one byte
                del self.buffer[0]
                print("[DEBUG] No $M< or $M> found. Discarding first byte and re-checking.")
                continue

            print(f"[DEBUG] Found {header_found.decode('ascii')} at index {header_index}.")

            # Check if we have enough bytes after the header
            if header_index + 6 > len(self.buffer):
                print("[DEBUG] Header found, but insufficient data for a complete packet. Waiting for more bytes.")
                break

            # Discard any bytes before the header
            if header_index > 0:
                print(f"[DEBUG] Discarding {header_index} byte(s) before the header.")
                del self.buffer[:header_index]

            # Now buffer[0..2] = either '$M<' or '$M>'
            # The rest of the parsing is the same for MSP V1
            payload_size = self.buffer[3]
            needed_len = 6 + payload_size  # 3 header + 1 size + 1 cmd + N payload + 1 checksum
            print(f"[DEBUG] Payload size={payload_size}, Total needed bytes={needed_len}, Current buffer len={len(self.buffer)}")

            if len(self.buffer) < needed_len:
                print("[DEBUG] Not enough data for the full MSP packet. Waiting for more.")
                break

            cmd = self.buffer[4]
            payload = self.buffer[5 : 5 + payload_size]
            chksum = self.buffer[5 + payload_size]

            # Calculate MSP v1 checksum:
            #   sum = payload_size ^ cmd ^ [each byte in payload]
            calc_sum = payload_size ^ cmd
            for b in payload:
                calc_sum ^= b
            calc_sum &= 0xFF

            # Determine direction from header
            direction = "Rx" if header_found == b"$M<" else "Tx"

            # Compare checksums
            if calc_sum == chksum:
                info_str = (
                    f"{direction} MSP CMD: 0x{cmd:02X}, "
                    f"Size: {payload_size}, "
                    f"Payload: {payload.hex()}"
                )
                print(f"[DEBUG] Valid MSP frame decoded: {info_str}")
                results.append(
                    AnalyzerFrame(
                        'msp_frame',
                        self.start_time,  # keep our existing start_time
                        frame.end_time,
                        {
                            'info': info_str,
                            'cmd': cmd,
                            'payload': payload,
                            'direction': direction
                        }
                    )
                )
            else:
                error_str = (
                    f"{direction} MSP Checksum Error: "
                    f"Expected 0x{calc_sum:02X}, got 0x{chksum:02X}, "
                    f"CMD=0x{cmd:02X}, Size={payload_size}"
                )
                print(f"[DEBUG] {error_str}")
                results.append(
                    AnalyzerFrame(
                        'msp_error',
                        self.start_time,
                        frame.end_time,
                        {'error': error_str}
                    )
                )

            # Remove the parsed MSP frame from the buffer
            del self.buffer[:needed_len]
            print(f"[DEBUG] Removed parsed frame from buffer. Remaining: {self.buffer.hex()} (len={len(self.buffer)})")

            if len(self.buffer) == 0:
                print("[DEBUG] Buffer is empty after parsing. Resetting start_time.")
                self.start_time = None
            else:
                print("[DEBUG] Possible next frame in buffer. Retaining current start_time.")
                self.start_time = frame.end_time

        return results

    def find_earliest_header(self, buf: bytearray, headers: list) -> tuple:
        """
        Finds the earliest occurrence of any header in 'headers' within 'buf'.
        Returns a tuple (index, header_bytes).
        If none is found, returns (-1, None).
        """
        earliest_index = -1
        earliest_header = None
        for h in headers:
            idx = buf.find(h)
            if idx != -1:
                # If we haven't set earliest_index yet or we found an earlier header
                if earliest_index == -1 or idx < earliest_index:
                    earliest_index = idx
                    earliest_header = h
        if earliest_index == -1:
            return (-1, None)
        return (earliest_index, earliest_header)
