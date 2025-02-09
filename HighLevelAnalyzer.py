# This file is part of Betaflight.
#
# Betaflight is free software. You can redistribute this software
# and/or modify this software under the terms of the GNU General
# Public License as published by the Free Software Foundation,
# either version 3 of the License, or (at your option) any later
# version.
#
# Betaflight is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this software.
#
# Author: Steve@SCEvans.com
#
# If not, see <http://www.gnu.org/licenses/>.

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame
import struct
from msp_decode import *
from msp2_decode import *

# MSP Command Constants
MSP_API_VERSION = 1
MSP_FC_VARIANT = 2
MSP_FC_VERSION = 3
MSP_BOARD_INFO = 4
MSP_BUILD_INFO = 5
MSP_NAME = 10
MSP_SET_NAME = 11
MSP_BATTERY_CONFIG = 32
MSP_SET_BATTERY_CONFIG = 33
MSP_MODE_RANGES = 34
MSP_SET_MODE_RANGE = 35
MSP_FEATURE_CONFIG = 36
MSP_SET_FEATURE_CONFIG = 37
MSP_BOARD_ALIGNMENT_CONFIG = 38
MSP_SET_BOARD_ALIGNMENT_CONFIG = 39
MSP_CURRENT_METER_CONFIG = 40
MSP_SET_CURRENT_METER_CONFIG = 41
MSP_MIXER_CONFIG = 42
MSP_SET_MIXER_CONFIG = 43
MSP_RX_CONFIG = 44
MSP_SET_RX_CONFIG = 45
MSP_LED_COLORS = 46
MSP_SET_LED_COLORS = 47
MSP_LED_STRIP_CONFIG = 48
MSP_SET_LED_STRIP_CONFIG = 49
MSP_RSSI_CONFIG = 50
MSP_SET_RSSI_CONFIG = 51
MSP_ADJUSTMENT_RANGES = 52
MSP_SET_ADJUSTMENT_RANGE = 53
MSP_CF_SERIAL_CONFIG = 54
MSP_SET_CF_SERIAL_CONFIG = 55
MSP_VOLTAGE_METER_CONFIG = 56
MSP_SET_VOLTAGE_METER_CONFIG = 57
MSP_SONAR_ALTITUDE = 58
MSP_PID_CONTROLLER = 59
MSP_SET_PID_CONTROLLER = 60
MSP_ARMING_CONFIG = 61
MSP_SET_ARMING_CONFIG = 62
MSP_RX_MAP = 64
MSP_SET_RX_MAP = 65
MSP_REBOOT = 68
MSP_DATAFLASH_SUMMARY = 70
MSP_DATAFLASH_READ = 71
MSP_DATAFLASH_ERASE = 72
MSP_FAILSAFE_CONFIG = 75
MSP_SET_FAILSAFE_CONFIG = 76
MSP_RXFAIL_CONFIG = 77
MSP_SET_RXFAIL_CONFIG = 78
MSP_SDCARD_SUMMARY = 79
MSP_BLACKBOX_CONFIG = 80
MSP_SET_BLACKBOX_CONFIG = 81
MSP_TRANSPONDER_CONFIG = 82
MSP_SET_TRANSPONDER_CONFIG = 83
MSP_OSD_CONFIG = 84
MSP_SET_OSD_CONFIG = 85
MSP_OSD_CHAR_READ = 86
MSP_OSD_CHAR_WRITE = 87
MSP_VTX_CONFIG = 88
MSP_SET_VTX_CONFIG = 89
MSP_ADVANCED_CONFIG = 90
MSP_SET_ADVANCED_CONFIG = 91
MSP_FILTER_CONFIG = 92
MSP_SET_FILTER_CONFIG = 93
MSP_PID_ADVANCED = 94
MSP_SET_PID_ADVANCED = 95
MSP_SENSOR_CONFIG = 96
MSP_SET_SENSOR_CONFIG = 97
MSP_CAMERA_CONTROL = 98
MSP_SET_ARMING_DISABLED = 99
MSP_STATUS = 101
MSP_RAW_IMU = 102
MSP_SERVO = 103
MSP_MOTOR = 104
MSP_RC = 105
MSP_RAW_GPS = 106
MSP_COMP_GPS = 107
MSP_ATTITUDE = 108
MSP_ALTITUDE = 109
MSP_ANALOG = 110
MSP_RC_TUNING = 111
MSP_PID = 112
MSP_BOXNAMES = 116
MSP_PIDNAMES = 117
MSP_WP = 118
MSP_BOXIDS = 119
MSP_SERVO_CONFIGURATIONS = 120
MSP_NAV_STATUS = 121
MSP_NAV_CONFIG = 122
MSP_MOTOR_3D_CONFIG = 124
MSP_RC_DEADBAND = 125
MSP_SENSOR_ALIGNMENT = 126
MSP_LED_STRIP_MODECOLOR = 127
MSP_VOLTAGE_METERS = 128
MSP_CURRENT_METERS = 129
MSP_BATTERY_STATE = 130
MSP_MOTOR_CONFIG = 131
MSP_GPS_CONFIG = 132
MSP_COMPASS_CONFIG = 133
MSP_ESC_SENSOR_DATA = 134
MSP_GPS_RESCUE = 135
MSP_GPS_RESCUE_PIDS = 136
MSP_VTXTABLE_BAND = 137
MSP_VTXTABLE_POWERLEVEL = 138
MSP_MOTOR_TELEMETRY = 139
MSP_SIMPLIFIED_TUNING = 140
MSP_SET_SIMPLIFIED_TUNING = 141
MSP_CALCULATE_SIMPLIFIED_PID = 142
MSP_CALCULATE_SIMPLIFIED_GYRO = 143
MSP_CALCULATE_SIMPLIFIED_DTERM = 144
MSP_VALIDATE_SIMPLIFIED_TUNING = 145
MSP_STATUS_EX = 150
MSP_UID = 160
MSP_GPSSVINFO = 164
MSP_GPSSTATISTICS = 166
MSP_OSD_VIDEO_CONFIG = 180
MSP_SET_OSD_VIDEO_CONFIG = 181
MSP_DISPLAYPORT = 182
MSP_COPY_PROFILE = 183
MSP_BEEPER_CONFIG = 184
MSP_SET_BEEPER_CONFIG = 185
MSP_SET_TX_INFO = 186
MSP_TX_INFO = 187
MSP_SET_OSD_CANVAS = 188
MSP_OSD_CANVAS = 189
MSP_SET_RAW_RC = 200
MSP_SET_RAW_GPS = 201
MSP_SET_PID = 202
MSP_SET_RC_TUNING = 204
MSP_ACC_CALIBRATION = 205
MSP_MAG_CALIBRATION = 206
MSP_RESET_CONF = 208
MSP_SET_WP = 209
MSP_SELECT_SETTING = 210
MSP_SET_HEADING = 211
MSP_SET_SERVO_CONFIGURATION = 212
MSP_SET_MOTOR = 214
MSP_SET_NAV_CONFIG = 215
MSP_SET_MOTOR_3D_CONFIG = 217
MSP_SET_RC_DEADBAND = 218
MSP_SET_RESET_CURR_PID = 219
MSP_SET_SENSOR_ALIGNMENT = 220
MSP_SET_LED_STRIP_MODECOLOR = 221
MSP_SET_MOTOR_CONFIG = 222
MSP_SET_GPS_CONFIG = 223
MSP_SET_COMPASS_CONFIG = 224
MSP_SET_GPS_RESCUE = 225
MSP_SET_GPS_RESCUE_PIDS = 226
MSP_SET_VTXTABLE_BAND = 227
MSP_SET_VTXTABLE_POWERLEVEL = 228
MSP_MULTIPLE_MSP = 230
MSP_MODE_RANGES_EXTRA = 238
MSP_SET_ACC_TRIM = 239
MSP_ACC_TRIM = 240
MSP_SERVO_MIX_RULES = 241
MSP_SET_SERVO_MIX_RULE = 242
MSP_SET_PASSTHROUGH = 245
MSP_SET_RTC = 246
MSP_RTC = 247
MSP_SET_BOARD_INFO = 248
MSP_SET_SIGNATURE = 249
MSP_EEPROM_WRITE = 250
MSP_DEBUGMSG = 253
MSP_DEBUG = 254
MSP_V2_FRAME = 255

# MSP2 Command Constants
MSP2_COMMON_SERIAL_CONFIG = 0x1009
MSP2_COMMON_SET_SERIAL_CONFIG = 0x100A
MSP2_SENSOR_GPS = 0x1F03
MSP2_SENSOR_RANGEFINDER_LIDARMT = 0x1F01
MSP2_SENSOR_OPTICALFLOW_MT = 0x1F02
MSP2_MOTOR_OUTPUT_REORDERING = 0x3001
MSP2_SET_MOTOR_OUTPUT_REORDERING = 0x3002
MSP2_SEND_DSHOT_COMMAND = 0x3003
MSP2_GET_VTX_DEVICE_STATUS = 0x3004
MSP2_GET_OSD_WARNINGS = 0x3005
MSP2_GET_TEXT = 0x3006
MSP2_SET_TEXT = 0x3007
MSP2_GET_LED_STRIP_CONFIG_VALUES = 0x3008
MSP2_SET_LED_STRIP_CONFIG_VALUES = 0x3009
MSP2_SENSOR_CONFIG_ACTIVE = 0x300A
MSP2_SENSOR_OPTICALFLOW = 0x300B
MSP2_MCU_INFO = 0x300C
MSP2_BETAFLIGHT_BIND = 0x3000

# Command name lookup dictionary
msp_commands = {
    MSP_API_VERSION: "MSP_API_VERSION",
    MSP_FC_VARIANT: "MSP_FC_VARIANT",
    MSP_FC_VERSION: "MSP_FC_VERSION",
    MSP_BOARD_INFO: "MSP_BOARD_INFO",
    MSP_BUILD_INFO: "MSP_BUILD_INFO",
    MSP_NAME: "MSP_NAME",
    MSP_SET_NAME: "MSP_SET_NAME",
    MSP_BATTERY_CONFIG: "MSP_BATTERY_CONFIG",
    MSP_SET_BATTERY_CONFIG: "MSP_SET_BATTERY_CONFIG",
    MSP_MODE_RANGES: "MSP_MODE_RANGES",
    MSP_SET_MODE_RANGE: "MSP_SET_MODE_RANGE",
    MSP_FEATURE_CONFIG: "MSP_FEATURE_CONFIG",
    MSP_SET_FEATURE_CONFIG: "MSP_SET_FEATURE_CONFIG",
    MSP_BOARD_ALIGNMENT_CONFIG: "MSP_BOARD_ALIGNMENT_CONFIG",
    MSP_SET_BOARD_ALIGNMENT_CONFIG: "MSP_SET_BOARD_ALIGNMENT_CONFIG",
    MSP_CURRENT_METER_CONFIG: "MSP_CURRENT_METER_CONFIG",
    MSP_SET_CURRENT_METER_CONFIG: "MSP_SET_CURRENT_METER_CONFIG",
    MSP_MIXER_CONFIG: "MSP_MIXER_CONFIG",
    MSP_SET_MIXER_CONFIG: "MSP_SET_MIXER_CONFIG",
    MSP_RX_CONFIG: "MSP_RX_CONFIG",
    MSP_SET_RX_CONFIG: "MSP_SET_RX_CONFIG",
    MSP_LED_COLORS: "MSP_LED_COLORS",
    MSP_SET_LED_COLORS: "MSP_SET_LED_COLORS",
    MSP_LED_STRIP_CONFIG: "MSP_LED_STRIP_CONFIG",
    MSP_SET_LED_STRIP_CONFIG: "MSP_SET_LED_STRIP_CONFIG",
    MSP_RSSI_CONFIG: "MSP_RSSI_CONFIG",
    MSP_SET_RSSI_CONFIG: "MSP_SET_RSSI_CONFIG",
    MSP_ADJUSTMENT_RANGES: "MSP_ADJUSTMENT_RANGES",
    MSP_SET_ADJUSTMENT_RANGE: "MSP_SET_ADJUSTMENT_RANGE",
    MSP_CF_SERIAL_CONFIG: "MSP_CF_SERIAL_CONFIG",
    MSP_SET_CF_SERIAL_CONFIG: "MSP_SET_CF_SERIAL_CONFIG",
    MSP_VOLTAGE_METER_CONFIG: "MSP_VOLTAGE_METER_CONFIG",
    MSP_SET_VOLTAGE_METER_CONFIG: "MSP_SET_VOLTAGE_METER_CONFIG",
    MSP_SONAR_ALTITUDE: "MSP_SONAR_ALTITUDE",
    MSP_PID_CONTROLLER: "MSP_PID_CONTROLLER",
    MSP_SET_PID_CONTROLLER: "MSP_SET_PID_CONTROLLER",
    MSP_ARMING_CONFIG: "MSP_ARMING_CONFIG",
    MSP_SET_ARMING_CONFIG: "MSP_SET_ARMING_CONFIG",
    MSP_RX_MAP: "MSP_RX_MAP",
    MSP_SET_RX_MAP: "MSP_SET_RX_MAP",
    MSP_REBOOT: "MSP_REBOOT",
    MSP_DATAFLASH_SUMMARY: "MSP_DATAFLASH_SUMMARY",
    MSP_DATAFLASH_READ: "MSP_DATAFLASH_READ",
    MSP_DATAFLASH_ERASE: "MSP_DATAFLASH_ERASE",
    MSP_FAILSAFE_CONFIG: "MSP_FAILSAFE_CONFIG",
    MSP_SET_FAILSAFE_CONFIG: "MSP_SET_FAILSAFE_CONFIG",
    MSP_RXFAIL_CONFIG: "MSP_RXFAIL_CONFIG",
    MSP_SET_RXFAIL_CONFIG: "MSP_SET_RXFAIL_CONFIG",
    MSP_SDCARD_SUMMARY: "MSP_SDCARD_SUMMARY",
    MSP_BLACKBOX_CONFIG: "MSP_BLACKBOX_CONFIG",
    MSP_SET_BLACKBOX_CONFIG: "MSP_SET_BLACKBOX_CONFIG",
    MSP_TRANSPONDER_CONFIG: "MSP_TRANSPONDER_CONFIG",
    MSP_SET_TRANSPONDER_CONFIG: "MSP_SET_TRANSPONDER_CONFIG",
    MSP_OSD_CONFIG: "MSP_OSD_CONFIG",
    MSP_SET_OSD_CONFIG: "MSP_SET_OSD_CONFIG",
    MSP_OSD_CHAR_READ: "MSP_OSD_CHAR_READ",
    MSP_OSD_CHAR_WRITE: "MSP_OSD_CHAR_WRITE",
    MSP_VTX_CONFIG: "MSP_VTX_CONFIG",
    MSP_SET_VTX_CONFIG: "MSP_SET_VTX_CONFIG",
    MSP_ADVANCED_CONFIG: "MSP_ADVANCED_CONFIG",
    MSP_SET_ADVANCED_CONFIG: "MSP_SET_ADVANCED_CONFIG",
    MSP_FILTER_CONFIG: "MSP_FILTER_CONFIG",
    MSP_SET_FILTER_CONFIG: "MSP_SET_FILTER_CONFIG",
    MSP_PID_ADVANCED: "MSP_PID_ADVANCED",
    MSP_SET_PID_ADVANCED: "MSP_SET_PID_ADVANCED",
    MSP_SENSOR_CONFIG: "MSP_SENSOR_CONFIG",
    MSP_SET_SENSOR_CONFIG: "MSP_SET_SENSOR_CONFIG",
    MSP_CAMERA_CONTROL: "MSP_CAMERA_CONTROL",
    MSP_SET_ARMING_DISABLED: "MSP_SET_ARMING_DISABLED",
    MSP_STATUS: "MSP_STATUS",
    MSP_RAW_IMU: "MSP_RAW_IMU",
    MSP_SERVO: "MSP_SERVO",
    MSP_MOTOR: "MSP_MOTOR",
    MSP_RC: "MSP_RC",
    MSP_RAW_GPS: "MSP_RAW_GPS",
    MSP_COMP_GPS: "MSP_COMP_GPS",
    MSP_ATTITUDE: "MSP_ATTITUDE",
    MSP_ALTITUDE: "MSP_ALTITUDE",
    MSP_ANALOG: "MSP_ANALOG",
    MSP_RC_TUNING: "MSP_RC_TUNING",
    MSP_PID: "MSP_PID",
    MSP_BOXNAMES: "MSP_BOXNAMES",
    MSP_PIDNAMES: "MSP_PIDNAMES",
    MSP_WP: "MSP_WP",
    MSP_BOXIDS: "MSP_BOXIDS",
    MSP_SERVO_CONFIGURATIONS: "MSP_SERVO_CONFIGURATIONS",
    MSP_NAV_STATUS: "MSP_NAV_STATUS",
    MSP_NAV_CONFIG: "MSP_NAV_CONFIG",
    MSP_MOTOR_3D_CONFIG: "MSP_MOTOR_3D_CONFIG",
    MSP_RC_DEADBAND: "MSP_RC_DEADBAND",
    MSP_SENSOR_ALIGNMENT: "MSP_SENSOR_ALIGNMENT",
    MSP_LED_STRIP_MODECOLOR: "MSP_LED_STRIP_MODECOLOR",
    MSP_VOLTAGE_METERS: "MSP_VOLTAGE_METERS",
    MSP_CURRENT_METERS: "MSP_CURRENT_METERS",
    MSP_BATTERY_STATE: "MSP_BATTERY_STATE",
    MSP_MOTOR_CONFIG: "MSP_MOTOR_CONFIG",
    MSP_GPS_CONFIG: "MSP_GPS_CONFIG",
    MSP_COMPASS_CONFIG: "MSP_COMPASS_CONFIG",
    MSP_ESC_SENSOR_DATA: "MSP_ESC_SENSOR_DATA",
    MSP_GPS_RESCUE: "MSP_GPS_RESCUE",
    MSP_GPS_RESCUE_PIDS: "MSP_GPS_RESCUE_PIDS",
    MSP_VTXTABLE_BAND: "MSP_VTXTABLE_BAND",
    MSP_VTXTABLE_POWERLEVEL: "MSP_VTXTABLE_POWERLEVEL",
    MSP_MOTOR_TELEMETRY: "MSP_MOTOR_TELEMETRY",
    MSP_SIMPLIFIED_TUNING: "MSP_SIMPLIFIED_TUNING",
    MSP_SET_SIMPLIFIED_TUNING: "MSP_SET_SIMPLIFIED_TUNING",
    MSP_CALCULATE_SIMPLIFIED_PID: "MSP_CALCULATE_SIMPLIFIED_PID",
    MSP_CALCULATE_SIMPLIFIED_GYRO: "MSP_CALCULATE_SIMPLIFIED_GYRO",
    MSP_CALCULATE_SIMPLIFIED_DTERM: "MSP_CALCULATE_SIMPLIFIED_DTERM",
    MSP_VALIDATE_SIMPLIFIED_TUNING: "MSP_VALIDATE_SIMPLIFIED_TUNING",
    MSP_STATUS_EX: "MSP_STATUS_EX",
    MSP_UID: "MSP_UID",
    MSP_GPSSVINFO: "MSP_GPSSVINFO",
    MSP_GPSSTATISTICS: "MSP_GPSSTATISTICS",
    MSP_OSD_VIDEO_CONFIG: "MSP_OSD_VIDEO_CONFIG",
    MSP_SET_OSD_VIDEO_CONFIG: "MSP_SET_OSD_VIDEO_CONFIG",
    MSP_DISPLAYPORT: "MSP_DISPLAYPORT",
    MSP_COPY_PROFILE: "MSP_COPY_PROFILE",
    MSP_BEEPER_CONFIG: "MSP_BEEPER_CONFIG",
    MSP_SET_BEEPER_CONFIG: "MSP_SET_BEEPER_CONFIG",
    MSP_SET_TX_INFO: "MSP_SET_TX_INFO",
    MSP_TX_INFO: "MSP_TX_INFO",
    MSP_SET_OSD_CANVAS: "MSP_SET_OSD_CANVAS",
    MSP_OSD_CANVAS: "MSP_OSD_CANVAS",
    MSP_SET_RAW_RC: "MSP_SET_RAW_RC",
    MSP_SET_RAW_GPS: "MSP_SET_RAW_GPS",
    MSP_SET_PID: "MSP_SET_PID",
    MSP_SET_RC_TUNING: "MSP_SET_RC_TUNING",
    MSP_ACC_CALIBRATION: "MSP_ACC_CALIBRATION",
    MSP_MAG_CALIBRATION: "MSP_MAG_CALIBRATION",
    MSP_RESET_CONF: "MSP_RESET_CONF",
    MSP_SET_WP: "MSP_SET_WP",
    MSP_SELECT_SETTING: "MSP_SELECT_SETTING",
    MSP_SET_HEADING: "MSP_SET_HEADING",
    MSP_SET_SERVO_CONFIGURATION: "MSP_SET_SERVO_CONFIGURATION",
    MSP_SET_MOTOR: "MSP_SET_MOTOR",
    MSP_SET_NAV_CONFIG: "MSP_SET_NAV_CONFIG",
    MSP_SET_MOTOR_3D_CONFIG: "MSP_SET_MOTOR_3D_CONFIG",
    MSP_SET_RC_DEADBAND: "MSP_SET_RC_DEADBAND",
    MSP_SET_RESET_CURR_PID: "MSP_SET_RESET_CURR_PID",
    MSP_SET_SENSOR_ALIGNMENT: "MSP_SET_SENSOR_ALIGNMENT",
    MSP_SET_LED_STRIP_MODECOLOR: "MSP_SET_LED_STRIP_MODECOLOR",
    MSP_SET_MOTOR_CONFIG: "MSP_SET_MOTOR_CONFIG",
    MSP_SET_GPS_CONFIG: "MSP_SET_GPS_CONFIG",
    MSP_SET_COMPASS_CONFIG: "MSP_SET_COMPASS_CONFIG",
    MSP_SET_GPS_RESCUE: "MSP_SET_GPS_RESCUE",
    MSP_SET_GPS_RESCUE_PIDS: "MSP_SET_GPS_RESCUE_PIDS",
    MSP_SET_VTXTABLE_BAND: "MSP_SET_VTXTABLE_BAND",
    MSP_SET_VTXTABLE_POWERLEVEL: "MSP_SET_VTXTABLE_POWERLEVEL",
    MSP_MULTIPLE_MSP: "MSP_MULTIPLE_MSP",
    MSP_MODE_RANGES_EXTRA: "MSP_MODE_RANGES_EXTRA",
    MSP_SET_ACC_TRIM: "MSP_SET_ACC_TRIM",
    MSP_ACC_TRIM: "MSP_ACC_TRIM",
    MSP_SERVO_MIX_RULES: "MSP_SERVO_MIX_RULES",
    MSP_SET_SERVO_MIX_RULE: "MSP_SET_SERVO_MIX_RULE",
    MSP_SET_PASSTHROUGH: "MSP_SET_PASSTHROUGH",
    MSP_SET_RTC: "MSP_SET_RTC",
    MSP_RTC: "MSP_RTC",
    MSP_SET_BOARD_INFO: "MSP_SET_BOARD_INFO",
    MSP_SET_SIGNATURE: "MSP_SET_SIGNATURE",
    MSP_EEPROM_WRITE: "MSP_EEPROM_WRITE",
    MSP_DEBUGMSG: "MSP_DEBUGMSG",
    MSP_DEBUG: "MSP_DEBUG",
    MSP_V2_FRAME: "MSP_V2_FRAME",
    MSP2_COMMON_SERIAL_CONFIG: "MSP2_COMMON_SERIAL_CONFIG",
    MSP2_COMMON_SET_SERIAL_CONFIG: "MSP2_COMMON_SET_SERIAL_CONFIG",
    MSP2_SENSOR_GPS: "MSP2_SENSOR_GPS",
    MSP2_SENSOR_RANGEFINDER_LIDARMT: "MSP2_SENSOR_RANGEFINDER_LIDARMT",
    MSP2_SENSOR_OPTICALFLOW_MT: "MSP2_SENSOR_OPTICALFLOW_MT",
    MSP2_MOTOR_OUTPUT_REORDERING: "MSP2_MOTOR_OUTPUT_REORDERING",
    MSP2_SET_MOTOR_OUTPUT_REORDERING: "MSP2_SET_MOTOR_OUTPUT_REORDERING",
    MSP2_SEND_DSHOT_COMMAND: "MSP2_SEND_DSHOT_COMMAND",
    MSP2_GET_VTX_DEVICE_STATUS: "MSP2_GET_VTX_DEVICE_STATUS",
    MSP2_GET_OSD_WARNINGS: "MSP2_GET_OSD_WARNINGS",
    MSP2_GET_TEXT: "MSP2_GET_TEXT",
    MSP2_SET_TEXT: "MSP2_SET_TEXT",
    MSP2_GET_LED_STRIP_CONFIG_VALUES: "MSP2_GET_LED_STRIP_CONFIG_VALUES",
    MSP2_SET_LED_STRIP_CONFIG_VALUES: "MSP2_SET_LED_STRIP_CONFIG_VALUES",
    MSP2_SENSOR_CONFIG_ACTIVE: "MSP2_SENSOR_CONFIG_ACTIVE",
    MSP2_SENSOR_OPTICALFLOW: "MSP2_SENSOR_OPTICALFLOW",
    MSP2_MCU_INFO: "MSP2_MCU_INFO",
    MSP2_BETAFLIGHT_BIND: "MSP2_BETAFLIGHT_BIND",
}
    
# ===========================
# High-Level Analyzer Class
# ===========================
def crc8_bf(data: bytes) -> int:
    polynomial = 0xD5
    crc = 0x00
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = (crc << 1) ^ polynomial
            else:
                crc <<= 1
            crc &= 0xFF  # Ensure CRC remains 8-bit
    return crc

class Hla(HighLevelAnalyzer):
    result_types = {
        'msp_frame': {'format': '{{data.cmd}} {{data.direction}}: {{data.info}}'},
        'msp_error': {'format': '{{data.error}}'}
    }

    def __init__(self):
        self.byte_buffer = []  # List of (byte, frame) tuples
        self.HEADERS = [b"$M<", b"$M>", b"$X<", b"$X>"]  # request and response headers
        self.msp_version = 1

    def decode(self, frame: AnalyzerFrame):
        if frame.type != 'data':
            return None
        
        byte_val = frame.data['data'][0]
        self.byte_buffer.append((byte_val, frame))
        results = []
        
        while True:
            if len(self.byte_buffer) < 6:
                break
                
            # Convert current buffer to bytes for header search
            buffer_bytes = bytearray(b[0] for b in self.byte_buffer)
            
            # Find the earliest occurrence of any header
            header_positions = [buffer_bytes.find(h) for h in self.HEADERS]
            header_positions = [pos for pos in header_positions if pos != -1]
            
            if not header_positions:
                # No headers found, discard first byte
                self.byte_buffer.pop(0)
                break
                
            header_index = min(header_positions)
            if header_index > 0:
                # Discard bytes before the header
                self.byte_buffer = self.byte_buffer[header_index:]

            # Reset MSP version at the start of each command
            self.msp_version = 1

            if self.byte_buffer[0][0] == ord('$') and self.byte_buffer[1][0] == ord('X'): # MSP2
                self.msp_version = 2
                if len(self.byte_buffer) < 8:
                    break
                    
                p_size = int.from_bytes([self.byte_buffer[6][0], self.byte_buffer[7][0]], 'little')
                needed_len = 8 + p_size + 1  # 3(header)+1(flag)+2(cmd)+2(size)+p_size+1(chksum)
                if len(self.byte_buffer) < needed_len:
                    break

                # Extract all bytes for CRC calculation in correct order
                flag_byte = self.byte_buffer[3][0]  # Flag byte
                cmd_bytes = bytes([self.byte_buffer[4][0], self.byte_buffer[5][0]])  # Command bytes
                size_bytes = bytes([self.byte_buffer[6][0], self.byte_buffer[7][0]])  # Size bytes
                payload = bytes(b[0] for b in self.byte_buffer[8:8 + p_size])  # Include all payload bytes
                
                # Combine all bytes for CRC calculation in correct order
                crc_data = bytearray([flag_byte]) + cmd_bytes + size_bytes + payload
                calc_sum = crc8_bf(crc_data)
                
                self.cmd = int.from_bytes(cmd_bytes, 'little')  # Get MSP2 command
                chksum = self.byte_buffer[8 + p_size][0]

                self.direction = "response" if self.byte_buffer[2][0] == ord('>') else "request"
                cmd_name = msp_commands.get(self.cmd, f"MSP2_0x{self.cmd:04X}")
                
                if (calc_sum == chksum) or (p_size == 255):
                    # General handling for MSP2 commands
                    cmd_name_stripped = cmd_name.replace("MSP2_", "").lower()
                    decoder_name = f"decode_msp2_{cmd_name_stripped}_{self.direction}"

                    try:
                        # Try to get MSPv2 decoder from msp2_decode module
                        import msp2_decode
                        decoder = getattr(msp2_decode, decoder_name, None)
                        if decoder:
                            decoded = decoder(payload)
                        else:
                            decoded = f"Raw payload: {payload.hex()}"

                        # Create frame with proper timing - from first byte to last
                        if decoded != MSG_INVALID_PAYLOAD:
                            results.append(AnalyzerFrame(
                                'msp_frame',
                                self.byte_buffer[0][1].start_time,  # First byte's start time
                                self.byte_buffer[needed_len-1][1].end_time,  # Last byte's end time
                                {"info": decoded, "cmd": cmd_name, "direction": self.direction}
                            ))
                        else:
                            results.append(AnalyzerFrame(
                                'msp_frame',
                                self.byte_buffer[0][1].start_time,
                                self.byte_buffer[needed_len-1][1].end_time,
                                {"info": f"{cmd_name} payload: {payload.hex()}", "cmd": cmd_name, "direction": self.direction}
                            ))
                    except Exception as e:
                        decoded = f"Error: {e}"
                        results.append(AnalyzerFrame(
                            'msp_frame',
                            self.byte_buffer[0][1].start_time,
                            self.byte_buffer[needed_len-1][1].end_time,
                            {"info": decoded, "cmd": cmd_name, "direction": self.direction}
                        ))
                else:
                    error_str = (f"{self.direction} {cmd_name} CRC Error: expected=0x{calc_sum:02X}, "
                                f"got=0x{chksum:02X}, size={p_size}")
                    results.append(AnalyzerFrame(
                        'msp_error',
                        self.byte_buffer[0][1].start_time,
                        self.byte_buffer[needed_len-1][1].end_time,
                        {"error": error_str}
                    ))
                
                self.byte_buffer = self.byte_buffer[needed_len:]
            else:
                if len(self.byte_buffer) < 6:
                    break
                p_size = self.byte_buffer[3][0]
                needed_len = 6 + p_size  # 3(header)+1(size)+1(cmd)+p_size+1(chksum)
                if len(self.byte_buffer) < needed_len:
                    break
                self.cmd = self.byte_buffer[4][0]

                if self.cmd == MSP_V2_FRAME:
                    if len(self.byte_buffer) < 11:
                        break
                    p_size = int.from_bytes([self.byte_buffer[9][0], self.byte_buffer[10][0]], 'little')
                    needed_len = 12 + p_size  # 3(header)+1(size)+1(cmd)+5(v2 header)+p_size+1(v2 chksum)
                    if len(self.byte_buffer) < needed_len:
                        break
                    msp2_msg = bytes(b[0] for b in self.byte_buffer[5:10 + p_size])
                    self.cmd = int.from_bytes([self.byte_buffer[7][0], self.byte_buffer[8][0]], 'little')  # Get MSP2 command from V2 header
                    payload = bytes(b[0] for b in self.byte_buffer[10:10 + p_size])  # Extract payload correctly
                    calc_sum = crc8_bf(msp2_msg)
                    chksum = self.byte_buffer[10 + p_size][0]
                else:
                    # Special handling for MSP_BOXNAMES with 0xFF length
                    if self.cmd == MSP_BOXNAMES and p_size == 0xFF:
                        # Look ahead for next header
                        buffer_bytes = bytearray(b[0] for b in self.byte_buffer[5:])  # Start after cmd byte
                        next_header_pos = -1
                        for header in self.HEADERS:
                            pos = buffer_bytes.find(header)
                            if pos != -1 and (next_header_pos == -1 or pos < next_header_pos):
                                next_header_pos = pos
                        
                        if next_header_pos == -1:
                            # No header found yet, need more data
                            break
                            
                        # Adjust needed_len to include all data up to next header
                        needed_len = 5 + next_header_pos  # 3(header)+1(size)+1(cmd)+payload_to_next_header
                        if len(self.byte_buffer) < needed_len:
                            break
                            
                        payload = bytes(b[0] for b in self.byte_buffer[5:5 + next_header_pos])
                        calc_sum = p_size ^ self.cmd  # Special case - no checksum for variable length
                        chksum = calc_sum  # Force checksum match for this special case
                    else:
                        payload = bytes(b[0] for b in self.byte_buffer[5:5 + p_size])
                        chksum = self.byte_buffer[5 + p_size][0]
                        calc_sum = p_size ^ self.cmd
                        for bb in payload:
                            calc_sum ^= bb
                        calc_sum &= 0xFF

                self.direction = "response" if self.byte_buffer[2][0] == ord('>') else "request"
                cmd_name = msp_commands.get(self.cmd, f"MSP_{self.cmd}")

                # Get decoder function name and function
                if self.msp_version == 2:
                    # Handle MSP2 commands
                    cmd_name_stripped = cmd_name.replace("MSP2_", "").lower()
                    decoder_name = f"decode_msp2_{cmd_name_stripped}_{self.direction}"
                    # Try to get MSPv2 decoder from msp2_decode module
                    import msp2_decode
                    decoder = getattr(msp2_decode, decoder_name, msp2_decode.decode_no_fields)

                    if (calc_sum == chksum) or (p_size == 255):
                        # Decode payload
                        decoded = decoder(payload)
                        if decoded != MSG_INVALID_PAYLOAD:  # Only show decoded message if it's valid
                            results.append(AnalyzerFrame(
                                'msp_frame',
                                self.byte_buffer[0][1].start_time,
                                self.byte_buffer[needed_len-1][1].end_time,
                                {"info": decoded, "cmd": cmd_name, "direction": self.direction}
                            ))
                        else:
                            # If decoder returned invalid payload, show raw hex
                            results.append(AnalyzerFrame(
                                'msp_frame',
                                self.byte_buffer[0][1].start_time,
                                self.byte_buffer[needed_len-1][1].end_time,
                                {"info": f"{cmd_name} payload: {payload.hex()}", "cmd": cmd_name, "direction": self.direction}
                            ))
                    else:
                        error_str = (f"{self.direction} {cmd_name} CRC Error: expected=0x{calc_sum:02X}, "
                                    f"got=0x{chksum:02X}, size={p_size}")
                        results.append(AnalyzerFrame(
                            'msp_error',
                            self.byte_buffer[0][1].start_time,
                            self.byte_buffer[needed_len-1][1].end_time,
                            {"error": error_str}
                        ))
                else:
                    # Handle MSPv1 commands
                    cmd_name_stripped = cmd_name.replace("MSP_", "").lower()
                    decoder_name = f"decode_msp_{cmd_name_stripped}_{self.direction}"
                    # Try to get MSPv1 decoder from msp_decode module
                    import msp_decode
                    decoder = getattr(msp_decode, decoder_name, None)
                    if decoder is None:
                        # Try alternate name without MSP_ prefix
                        decoder_name = f"decode_{cmd_name_stripped}_{self.direction}"
                        decoder = getattr(msp_decode, decoder_name, msp_decode.decode_no_fields)

                    if (calc_sum == chksum) or (p_size == 255):
                        # Decode payload
                        decoded = decoder(payload)
                        if decoded != MSG_INVALID_PAYLOAD:  # Only show decoded message if it's valid
                            results.append(AnalyzerFrame(
                                'msp_frame',
                                self.byte_buffer[0][1].start_time,
                                self.byte_buffer[needed_len-1][1].end_time,
                                {"info": decoded, "cmd": cmd_name, "direction": self.direction}
                            ))
                        else:
                            # If decoder returned invalid payload, show raw hex
                            results.append(AnalyzerFrame(
                                'msp_frame',
                                self.byte_buffer[0][1].start_time,
                                self.byte_buffer[needed_len-1][1].end_time,
                                {"info": f"{cmd_name} payload: {payload.hex()}", "cmd": cmd_name, "direction": self.direction}
                            ))
                    else:
                        error_str = (f"{self.direction} {cmd_name} CRC Error: expected=0x{calc_sum:02X}, "
                                    f"got=0x{chksum:02X}, size={p_size}")
                        results.append(AnalyzerFrame(
                            'msp_error',
                            self.byte_buffer[0][1].start_time,
                            self.byte_buffer[needed_len-1][1].end_time,
                            {"error": error_str}
                        ))
                self.byte_buffer = self.byte_buffer[needed_len:]

        return results