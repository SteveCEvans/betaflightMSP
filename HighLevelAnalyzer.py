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

# ===========================
# Decoder Functions
# ===========================

def decode_no_fields(payload: bytes) -> str:
    return "no fields"

MSG_INVALID_PAYLOAD = "Invalid payload"

# ---------------------------
# MSP Command-Specific Decoders
# ---------------------------

# ---------------------------
# MSP_API_VERSION
# ---------------------------
def decode_msp_api_version_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for API version"
    return MSG_INVALID_PAYLOAD

def decode_msp_api_version_response(payload: bytes) -> str:
    if len(payload) == 3:
        major, minor, patch = payload
        return f"API Version: v{major}.{minor}.{patch}"
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP_FC_VARIANT
# ---------------------------
def decode_msp_fc_variant_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request FC Variant"
    return MSG_INVALID_PAYLOAD

def decode_msp_fc_variant_response(payload: bytes) -> str:
    try:
        variant = payload.decode('ascii', 'replace').rstrip('\x00')
        return f"FC Variant: {variant}"
    except:
        return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP_FC_VERSION
# ---------------------------
def decode_msp_fc_version_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for FC version"
    return MSG_INVALID_PAYLOAD

def decode_msp_fc_version_response(payload: bytes) -> str:
    if len(payload) == 3:
        major, minor, patch = struct.unpack('<BBB', payload)
        return f"FC Version: {major}.{minor}.{patch}"
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP_BOARD_INFO
# ---------------------------
def decode_msp_board_info_request(payload: bytes) -> str:
    """
    Decodes the request for board information.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request Board Information"
    return MSG_INVALID_PAYLOAD


def decode_msp_board_info_response(payload: bytes) -> str:
    """
    Decodes the response for board information.

    :param payload: Payload bytes
    :return: Decoded string
    """
    index = 0
    BOARD_IDENTIFIER_LENGTH = 4 # 4 UPPER CASE alpha numeric characters that identify the board being used
    SIGNATURE_LENGTH = 32
        
    # Read board identifier
    board_identifier = payload[index:index + BOARD_IDENTIFIER_LENGTH].decode('utf-8').strip('\x00')
    index += BOARD_IDENTIFIER_LENGTH

    # Read hardware revision
    hardware_revision = int.from_bytes(payload[index:index + 2], 'little')
    index += 2

    # Read target capabilities
    hasMAX7456 = payload[index]
    index += 1

    # Read target capabilities
    target_capabilities = payload[index]
    index += 1

    # Read target name
    target_name_length = payload[index]
    index += 1
    target_name = payload[index:index + target_name_length].decode('utf-8').strip('\x00')
    index += target_name_length

    # Read board name if available
    board_name_length = payload[index]
    index += 1
    board_name = payload[index:index + board_name_length].decode('utf-8').strip('\x00')
    index += board_name_length

    # Read manufacturer ID if available
    manufacturer_id_length = payload[index]
    index += 1
    manufacturer_id = payload[index:index + manufacturer_id_length].decode('utf-8').strip('\x00')
    index += manufacturer_id_length

    # Read signature
    signature = payload[index:index + SIGNATURE_LENGTH].decode('utf-8').strip('\x00')
    index += SIGNATURE_LENGTH
    
    # Read MCU type ID
    mcu_type_id = payload[index]
    index += 1

    # Read configuration state
    configuration_state = payload[index]
    index += 1

    # Read gyro sample rate
    gyro_sample_rate = int.from_bytes(payload[index:index + 2], 'little')
    index += 2

    # Read configuration problems
    configuration_problems = int.from_bytes(payload[index:index + 4], 'little')
    index += 4

    # Read SPI registered device count
    spi_device_count = payload[index]
    index += 1

    # Read I2C registered device count
    i2c_device_count = payload[index]

    # Construct the response string
    response = (f"ID: {board_identifier}\n"
                f"Rev: {hardware_revision}\n"
                f"MAX7456: {hasMAX7456 == 2}\n"
                f"Capa: {target_capabilities}\n"
                f"Target: {target_name}\n"
                f"Board: {board_name}\n"
                f"Man ID: {manufacturer_id}\n"
                f"Sig: {signature}\n"
                f"MCU: {mcu_type_id}\n"
                f"State: {configuration_state}\n"
                f"Gyro: {gyro_sample_rate} Hz\n"
                f"Probs: {configuration_problems}\n"
                f"SPI: {spi_device_count}\n"
                f"I2C: {i2c_device_count}\n")

    return response.strip()  # Remove any trailing whitespace

# ---------------------------
# MSP_BUILD_INFO
# ---------------------------
def decode_msp_build_info_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for Build Info"
    return MSG_INVALID_PAYLOAD

def decode_msp_build_info_response(payload: bytes) -> str:
    """
    Decodes the response for build information.

    :param payload: Payload bytes
    :return: Decoded string
    """
    GIT_SHORT_REVISION_LENGTH = 7
    BUILD_DATE_LENGTH = 11 # "MMM DD YYYY" MMM = Jan/Feb/...
    BUILD_TIME_LENGTH = 8 # "HH:MM:SS"

    if len(payload) < (BUILD_DATE_LENGTH + BUILD_TIME_LENGTH + GIT_SHORT_REVISION_LENGTH):
        return MSG_INVALID_PAYLOAD

    index = 0
    build_date = payload[index:index + BUILD_DATE_LENGTH].decode('utf-8').strip('\x00')  # Build date
    index += BUILD_DATE_LENGTH
    build_time = payload[index:index + BUILD_TIME_LENGTH].decode('utf-8').strip('\x00')  # Build time
    index += BUILD_TIME_LENGTH
    short_git_revision = payload[index:index + GIT_SHORT_REVISION_LENGTH].decode('utf-8').strip('\x00')  # Short Git revision
    index += GIT_SHORT_REVISION_LENGTH

    # Check for build info flags if present
    build_info_flags = None
    if len(payload) > index:
        build_info_flags = payload[index]  # Assuming it's a single byte for flags

    # Construct the response string
    response = (f"Date: {build_date}\n"
                f", Time: {build_time}\n"
                f", Commit: {short_git_revision}\n")
    
    if build_info_flags is not None:
        response += f", Flags: {build_info_flags}\n"

    return response.strip()  # Remove any trailing whitespace

# ---------------------------
# MSP_NAME
# ---------------------------
def decode_msp_name_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for Device Name"
    return MSG_INVALID_PAYLOAD

def decode_msp_name_response(payload: bytes) -> str:
    try:
        name = payload.decode('ascii', 'replace').rstrip('\x00')
        return f"Device Name: '{name}'"
    except:
        return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP_SET_NAME
# ---------------------------
def decode_msp_set_name_request(payload: bytes) -> str:
    try:
        new_name = payload.decode('ascii', 'replace').rstrip('\x00')
        return f"Set Device Name: '{new_name}'"
    except:
        return MSG_INVALID_PAYLOAD

def decode_msp_set_name_response(payload: bytes) -> str:
    if len(payload) == 0:
        return "Device name set successfully"
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP_BATTERY_CONFIG
# ---------------------------
def decode_msp_battery_config_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Battery Config"
    return MSG_INVALID_PAYLOAD

def decode_msp_battery_config_response(payload: bytes) -> str:
    if len(payload) >= 13:
        vbat_min_cell_voltage, vbat_max_cell_voltage, vbat_warning_cell_voltage, battery_capacity, voltage_meter_source, current_meter_source, vbat_min_cell_voltage16, vbat_max_cell_voltage16, vbat_warning_cell_voltage16 = struct.unpack('<BBBHBBHHH', payload[:13])
        return (f"Battery Config: Min={vbat_min_cell_voltage/10}V, Max={vbat_max_cell_voltage/10}V, "
                f"Warn={vbat_warning_cell_voltage/10}V, Cap={battery_capacity}mAh, "
                f"Vsrc={voltage_meter_source}, Csrc={current_meter_source},"
                f"Min={vbat_min_cell_voltage16/100}V, Max={vbat_max_cell_voltage16/100}V, "
                f"Warn={vbat_warning_cell_voltage16/100}V")
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP_BOARD_ALIGNMENT_CONFIG
# ---------------------------
def decode_msp_board_alignment_config_request(payload: bytes) -> str:
    """
    Decodes the request for board alignment configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request Board Alignment Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_board_alignment_config_response(payload: bytes) -> str:
    """
    Decodes the response for board alignment configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 6:  # Assuming at least 6 bytes for alignment config
        return MSG_INVALID_PAYLOAD

    # Unpack the board alignment configuration data
    # Example structure (this may vary based on actual implementation):
    # [0] - Roll alignment (int8_t)
    # [1] - Pitch alignment (int8_t)
    # [2] - Yaw alignment (int8_t)
    # [3] - Additional flags or settings (uint8_t)

    roll_alignment = payload[0]  # Roll alignment
    pitch_alignment = payload[1]  # Pitch alignment
    yaw_alignment = payload[2]  # Yaw alignment
    additional_flags = payload[3]  # Additional flags

    return (f"Roll={roll_alignment}, Pitch={pitch_alignment}, Yaw={yaw_alignment}, "
            f"Flags={additional_flags}")

# ---------------------------
# MSP_RC_TUNING
# ---------------------------
def decode_msp_rc_tuning_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request RC Tuning Parameters"
    return MSG_INVALID_PAYLOAD

def decode_msp_rc_tuning_response(payload: bytes) -> str:
    if len(payload) < 10:
        return MSG_INVALID_PAYLOAD

    roll_rate = int.from_bytes(payload[0:2], 'little')
    pitch_rate = int.from_bytes(payload[2:4], 'little')
    yaw_rate = int.from_bytes(payload[4:6], 'little')
    rc_rate = int.from_bytes(payload[6:8], 'little')
    super_rate = int.from_bytes(payload[8:10], 'little')

    return (f"RC Tuning Data: Roll Rate={roll_rate}, "
            f"Pitch Rate={pitch_rate}, Yaw Rate={yaw_rate}, "
            f"RC Rate={rc_rate}, Super Rate={super_rate}")

# ---------------------------
# MSP_ANALOG
# ---------------------------
def decode_msp_analog_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Analog Sensor Data"
    return MSG_INVALID_PAYLOAD

def decode_msp_analog_response(payload: bytes) -> str:
    if len(payload) < 6:
        return MSG_INVALID_PAYLOAD

    voltage = int.from_bytes(payload[0:2], 'little')
    current = int.from_bytes(payload[2:4], 'little')
    rssi = int.from_bytes(payload[4:6], 'little')

    return (f"Analog Data: Voltage={voltage / 1000.0:.2f}V, "
            f"Current={current}mA, RSSI={rssi}%")

# ---------------------------
# MSP_LED_STRIP_MODE_COLOR
# ---------------------------
def decode_msp_led_strip_mode_color_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request LED Strip Mode and Color Settings"
    return MSG_INVALID_PAYLOAD

def decode_msp_led_strip_mode_color_response(payload: bytes) -> str:
    if len(payload) < 4:
        return MSG_INVALID_PAYLOAD

    mode = payload[0]
    red = payload[1]
    green = payload[2]
    blue = payload[3]

    return (f"LED Strip Settings: Mode={mode}, "
            f"Color=({red}, {green}, {blue})")

# ---------------------------
# MSP_BATTERY_STATE
# ---------------------------
def decode_msp_battery_state_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Battery State"
    return MSG_INVALID_PAYLOAD

def decode_msp_battery_state_response(payload: bytes) -> str:
    if len(payload) < 6:
        return MSG_INVALID_PAYLOAD

    cell_count = payload[0]
    voltage = int.from_bytes(payload[1:3], 'little')  # Voltage in millivolts
    current = int.from_bytes(payload[3:5], 'little')  # Current in milliamps
    capacity = int.from_bytes(payload[5:7], 'little')  # Capacity in mAh

    return (f"Battery State: {cell_count} cells, "
            f"Voltage={voltage / 1000.0:.2f}V, "
            f"Current={current}mA, "
            f"Capacity={capacity}mAh")

# ---------------------------
# MSP_SET_VTX_CONFIG
# ---------------------------
def decode_msp_set_vtx_config_request(payload: bytes) -> str:
    try:
        vtx_config = payload.decode('ascii', 'replace').rstrip('\x00')
        return f"Set VTX Config: {vtx_config}"
    except:
        return MSG_INVALID_PAYLOAD

def decode_msp_set_vtx_config_response(payload: bytes) -> str:
    if len(payload) == 0:
        return "VTX config set successfully"
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP_VTX_CONFIG
# ---------------------------
def decode_msp_vtx_config_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request VTX Config"
    return MSG_INVALID_PAYLOAD

def decode_msp_vtx_config_response(payload: bytes) -> str:
    try:
        vtx_config = payload.decode('ascii', 'replace').rstrip('\x00')
        return f"VTX Config: {vtx_config}"
    except:
        return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP_EEPROM_WRITE
# ---------------------------
def decode_msp_eeprom_write_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request EEPROM Write"
    return MSG_INVALID_PAYLOAD

def decode_msp_eeprom_write_response(payload: bytes) -> str:
    if len(payload) == 0:
        return "EEPROM write initiated successfully"
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP_BAT_SETTING
# ---------------------------
def decode_msp_bat_setting_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Battery Settings"
    return MSG_INVALID_PAYLOAD

def decode_msp_bat_setting_response(payload: bytes) -> str:
    try:
        bat_setting = payload.decode('ascii', 'replace').rstrip('\x00')
        return f"Battery Settings: {bat_setting}"
    except:
        return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP_SET_BAT_SETTING
# ---------------------------
def decode_msp_set_bat_setting_request(payload: bytes) -> str:
    try:
        bat_setting = payload.decode('ascii', 'replace').rstrip('\x00')
        return f"Set Battery Settings: {bat_setting}"
    except:
        return MSG_INVALID_PAYLOAD

def decode_msp_set_bat_setting_response(payload: bytes) -> str:
    if len(payload) == 0:
        return "Battery settings set successfully"
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP_SONAR_ALTITUDE
# ---------------------------
def decode_msp_sonar_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Sonar Altitude"
    return MSG_INVALID_PAYLOAD

def decode_msp_sonar_response(payload: bytes) -> str:
    if len(payload) < 2:
        return MSG_INVALID_PAYLOAD

    altitude = int.from_bytes(payload[0:2], 'little')  # Altitude in centimeters
    return f"Sonar Altitude: {altitude} cm"

# ---------------------------
# MSP_PID_CONTROLLER
# ---------------------------
def decode_msp_pid_controller_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request PID Controller"
    return MSG_INVALID_PAYLOAD

def decode_msp_pid_controller_response(payload: bytes) -> str:
    if len(payload) < 8:
        return MSG_INVALID_PAYLOAD

    roll_pid = struct.unpack('<fff', payload[0:12])  # Roll PID values
    pitch_pid = struct.unpack('<fff', payload[12:24])  # Pitch PID values
    yaw_pid = struct.unpack('<fff', payload[24:36])  # Yaw PID values

    return (f"PID Controller: Roll PID={roll_pid}, Pitch PID={pitch_pid}, Yaw PID={yaw_pid}")

# ---------------------------
# MSP_REBOOT
# ---------------------------
def decode_msp_reboot_request(payload: bytes) -> str:
    """
    Decodes the request for rebooting the system.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request Reboot with default mode (Firmware)"
    
    reboot_mode = payload[0]  # Read the reboot mode from the payload


    # Additional checks for specific modes can be added here
    return f"Request Reboot with mode: {reboot_mode}"


def decode_msp_reboot_response(payload: bytes) -> str:
    """
    Decodes the response for rebooting the system.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 1:  # At least 1 byte for the reboot mode
        return "Error: Invalid Response Payload"

    reboot_mode = payload[0]  # Reboot mode from the response

    # Construct the response string
    response = (f"Reboot Mode: {reboot_mode}\n")

    return response.strip()  # Remove any trailing whitespace

# ---------------------------
# MSP_DATAFLASH_SUMMARY
# ---------------------------
def decode_msp_dataflash_summary_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Dataflash Summary"
    return MSG_INVALID_PAYLOAD

def decode_msp_dataflash_summary_response(payload: bytes) -> str:
    if len(payload) < 8:
        return MSG_INVALID_PAYLOAD

    total_size = int.from_bytes(payload[0:4], 'little')  # Total size in bytes
    used_size = int.from_bytes(payload[4:8], 'little')  # Used size in bytes

    return f"Dataflash Summary: Total Size={total_size} bytes, Used Size={used_size} bytes"

# ---------------------------
# MSP_DATAFLASH_READ
# ---------------------------
def decode_msp_dataflash_read_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Dataflash Read"
    return MSG_INVALID_PAYLOAD

def decode_msp_dataflash_read_response(payload: bytes) -> str:
    if len(payload) == 0:
        return "Dataflash read initiated successfully"
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP_STATUS
# ---------------------------
def decode_msp_status_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Status"
    return MSG_INVALID_PAYLOAD

def decode_msp_status_response(payload: bytes) -> str:
    if len(payload) < 4:
        return MSG_INVALID_PAYLOAD

    status = payload[0]  # Status byte
    mode = payload[1]    # Mode byte
    flags = payload[2:4]  # Flags (2 bytes)

    return (f"Status: {status}, Mode: {mode}, Flags: {flags.hex()}")

# ---------------------------
# MSP_RAW_IMU
# ---------------------------
def decode_msp_raw_imu_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Raw IMU Data"
    return MSG_INVALID_PAYLOAD

def decode_msp_raw_imu_response(payload: bytes) -> str:
    if len(payload) < 12:
        return MSG_INVALID_PAYLOAD

    acc_x = int.from_bytes(payload[0:2], 'little')  # Accelerometer X
    acc_y = int.from_bytes(payload[2:4], 'little')  # Accelerometer Y
    acc_z = int.from_bytes(payload[4:6], 'little')  # Accelerometer Z
    gyro_x = int.from_bytes(payload[6:8], 'little')  # Gyroscope X
    gyro_y = int.from_bytes(payload[8:10], 'little')  # Gyroscope Y
    gyro_z = int.from_bytes(payload[10:12], 'little')  # Gyroscope Z

    return (f"Raw IMU Data: Accel=({acc_x}, {acc_y}, {acc_z}), "
            f"Gyro=({gyro_x}, {gyro_y}, {gyro_z})")

# ---------------------------
# MSP_RC
# ---------------------------
def decode_msp_rc_request(payload: bytes) -> str:
    """
    Decodes the request for RC channel values.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request RC Channel Values"
    return MSG_INVALID_PAYLOAD

def decode_msp_rc_response(payload: bytes) -> str:
    """
    Decodes the response for RC channel values.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 16:  # Assuming 8 channels, each with 2 bytes
        return MSG_INVALID_PAYLOAD

    # Unpack the RC channel values (assuming 8 channels)
    channels = [int.from_bytes(payload[i:i+2], 'little', signed=True) for i in range(0, 16, 2)]

    return (f"RC Channel Values: "
            f"Ch1={channels[0]}, Ch2={channels[1]}, Ch3={channels[2]}, Ch4={channels[3]}, "
            f"Ch5={channels[4]}, Ch6={channels[5]}, Ch7={channels[6]}, Ch8={channels[7]}")

# ---------------------------
# MSP_ATTITUDE
# ---------------------------
def decode_msp_attitude_request(payload: bytes) -> str:
    """
    Decodes the request for attitude data.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request Attitude Data"
    return MSG_INVALID_PAYLOAD

def decode_msp_attitude_response(payload: bytes) -> str:
    """
    Decodes the response for attitude data.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 6:  # Assuming 3 angles (roll, pitch, yaw) each as int16
        return MSG_INVALID_PAYLOAD

    roll = int.from_bytes(payload[0:2], 'little', signed=True)  # Roll angle in degrees
    pitch = int.from_bytes(payload[2:4], 'little', signed=True)  # Pitch angle in degrees
    yaw = int.from_bytes(payload[4:6], 'little', signed=True)  # Yaw angle in degrees

    return (f"Attitude Data: Roll={roll}°, Pitch={pitch}°, Yaw={yaw}°")

# ---------------------------
# MSP_ALTITUDE
# ---------------------------
def decode_msp_altitude_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Altitude"
    return MSG_INVALID_PAYLOAD

def decode_msp_altitude_response(payload: bytes) -> str:
    if len(payload) < 2:
        return MSG_INVALID_PAYLOAD

    altitude = int.from_bytes(payload[0:2], 'little')  # Altitude in centimeters
    return f"Altitude: {altitude} cm"

# ---------------------------
# MSP_ANALOG
# ---------------------------
def decode_msp_analog_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Analog Sensor Data"
    return MSG_INVALID_PAYLOAD

def decode_msp_analog_response(payload: bytes) -> str:
    if len(payload) < 6:
        return MSG_INVALID_PAYLOAD

    voltage = int.from_bytes(payload[0:2], 'little')
    current = int.from_bytes(payload[2:4], 'little')
    rssi = int.from_bytes(payload[4:6], 'little')

    return (f"Analog Data: Voltage={voltage / 1000.0:.2f}V, "
            f"Current={current}mA, RSSI={rssi}%")

# ---------------------------
# MSP_BOXNAMES
# ---------------------------
def decode_msp_boxnames_request(payload: bytes) -> str:
    """
    Decodes the request for box names.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request Box Names"
    return MSG_INVALID_PAYLOAD

def decode_msp_boxnames_response(payload: bytes) -> str:
    """
    Decodes the response for box names.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "No box names available"

    # Decode the box names from the payload
    box_names = payload.decode('ascii', 'replace').rstrip('\x00')
    box_count = box_names.count(';')
    return f"{box_count} Box Names"

# ---------------------------
# MSP_BOXIDS
# ---------------------------
def decode_msp_boxids_request(payload: bytes) -> str:
    """
    Decodes the request for box names.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request Box Names"
    return MSG_INVALID_PAYLOAD

def decode_msp_boxids_response(payload: bytes) -> str:
    """
    Decodes the response for box names.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "No box IDs available"

    index = 1
    response = ""
    for i in range(0, len(payload)):
        boxid = payload[i]  # Length of the subframe

        response += (f"{boxid:d}\n")

    return response.strip()  # Remove any trailing whitespace

# ---------------------------
# MSP_LED_STRIP_MODE_COLOR
# ---------------------------
def decode_msp_led_strip_mode_color_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request LED Strip Mode and Color Settings"
    return MSG_INVALID_PAYLOAD

def decode_msp_led_strip_mode_color_response(payload: bytes) -> str:
    if len(payload) < 4:
        return MSG_INVALID_PAYLOAD

    mode = payload[0]
    red = payload[1]
    green = payload[2]
    blue = payload[3]

    return (f"LED Strip Settings: Mode={mode}, "
            f"Color=({red}, {green}, {blue})")

# ---------------------------
# MSP_BATTERY_STATE
# ---------------------------
def decode_msp_battery_state_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Battery State"
    return MSG_INVALID_PAYLOAD

def decode_msp_battery_state_response(payload: bytes) -> str:
    if len(payload) < 6:
        return MSG_INVALID_PAYLOAD

    cell_count = payload[0]
    voltage = int.from_bytes(payload[1:3], 'little')  # Voltage in millivolts
    current = int.from_bytes(payload[3:5], 'little')  # Current in milliamps
    capacity = int.from_bytes(payload[5:7], 'little')  # Capacity in mAh

    return (f"Battery State: {cell_count} cells, "
            f"Voltage={voltage / 1000.0:.2f}V, "
            f"Current={current}mA, "
            f"Capacity={capacity}mAh")

# ---------------------------
# MSP_STATUS_EX
# ---------------------------
def decode_msp_status_ex_request(payload: bytes) -> str:
    """
    Decodes the request for extended status data.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request Extended Status Data"
    return MSG_INVALID_PAYLOAD

def decode_msp_status_ex_response(payload: bytes) -> str:
    """
    Decodes the response for extended status data.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 8:  # Assuming at least 8 bytes for extended status
        return MSG_INVALID_PAYLOAD

    # Unpack the extended status data
    # Example structure (this may vary based on actual implementation):
    # [0:1] - Flight Mode (uint8_t)
    # [1:2] - Battery Voltage (uint16_t)
    # [2:3] - Current (uint16_t)
    # [3:4] - RSSI (uint8_t)
    # [4:5] - Flags (uint8_t)
    # [5:6] - Additional telemetry data (if applicable)

    flight_mode = payload[0]  # Flight mode
    battery_voltage = int.from_bytes(payload[1:3], 'little')  # Battery voltage in millivolts
    current = int.from_bytes(payload[3:5], 'little')  # Current in milliamps
    rssi = payload[5]  # RSSI value
    flags = payload[6]  # Status flags

    return (f"Extended Status: Flight Mode={flight_mode}, "
            f"Battery Voltage={battery_voltage / 1000.0:.2f}V, "
            f"Current={current}mA, RSSI={rssi}%, Flags={flags}")

# ---------------------------
# MSP_DISPLAYPORT
# ---------------------------

DISPLAYPORT_SUBCMD_NAMES = {
    0: "MSP_DP_HEARTBEAT",
    1: "MSP_DP_RELEASE",
    2: "MSP_DP_CLEAR_SCREEN",
    3: "MSP_DP_WRITE_STRING",
    4: "MSP_DP_DRAW_SCREEN",
    5: "MSP_DP_OPTIONS",
    6: "MSP_DP_SYS"
}

def decode_msp_displayport_request(payload: bytes) -> str:
    return "No request expected"

def decode_msp_displayport_response(payload: bytes) -> str:
    if len(payload) < 1:
        return "<No subcommand byte>"

    subcmd = payload[0]
    subcmd_name = DISPLAYPORT_SUBCMD_NAMES.get(subcmd, f"UNKNOWN_SUBCMD={subcmd}")

    if subcmd == 2:
        return f"{subcmd_name}: Clear the entire screen"
    elif subcmd == 3:
        if len(payload) < 4:
            return f"{subcmd_name}: <Not enough data for row,col,attr>"
        row = payload[1]
        col = payload[2]
        attr = payload[3]
        data_bytes = payload[4:]
        zero_pos = data_bytes.find(0)
        if zero_pos != -1:
            text_bytes = data_bytes[:zero_pos]
        else:
            text_bytes = data_bytes
        text_str = text_bytes.decode('ascii', errors='replace')
        return (
            f"{subcmd_name}: row={row}, col={col}, attr=0x{attr:02X}, "
            f"string='{text_str}'"
        )
    else:
        return f"{subcmd_name}"

# ---------------------------
# MSP_BEEPER_CONFIG
# ---------------------------
def decode_msp_beeper_config_request(payload: bytes) -> str:
    """
    Decodes the request for beeper configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request Beeper Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_beeper_config_response(payload: bytes) -> str:
    """
    Decodes the response for beeper configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 4:  # Assuming at least 4 bytes for beeper config
        return MSG_INVALID_PAYLOAD

    # Unpack the beeper configuration data
    # [0] - Beeper mode (uint8_t)
    # [1] - Beeper frequency (uint16_t)
    # [2] - Beeper duration (uint16_t)

    beeper_mode = payload[0]  # Beeper mode (e.g., 0 for off, 1 for on)
    beeper_frequency = int.from_bytes(payload[1:3], 'little')  # Frequency in Hz
    beeper_duration = int.from_bytes(payload[3:5], 'little')  # Duration in milliseconds

    return (f"Beeper Configuration: Mode={beeper_mode}, "
            f"Frequency={beeper_frequency}Hz, Duration={beeper_duration}ms")

# ---------------------------
# MSP_SET_VTX_CONFIG
# ---------------------------
def decode_msp_set_vtx_config_request(payload: bytes) -> str:
    try:
        vtx_config = payload.decode('ascii', 'replace').rstrip('\x00')
        return f"Set VTX Config: {vtx_config}"
    except:
        return MSG_INVALID_PAYLOAD

def decode_msp_set_vtx_config_response(payload: bytes) -> str:
    if len(payload) == 0:
        return "VTX config set successfully"
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP_VTX_CONFIG
# ---------------------------
def decode_msp_vtx_config_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request VTX Config"
    return MSG_INVALID_PAYLOAD

def decode_msp_vtx_config_response(payload: bytes) -> str:
    try:
        vtx_config = payload.decode('ascii', 'replace').rstrip('\x00')
        return f"VTX Config: {vtx_config}"
    except:
        return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP_EEPROM_WRITE
# ---------------------------
def decode_msp_eeprom_write_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request EEPROM Write"
    return MSG_INVALID_PAYLOAD

def decode_msp_eeprom_write_response(payload: bytes) -> str:
    if len(payload) == 0:
        return "EEPROM write initiated successfully"
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP_BAT_SETTING
# ---------------------------
def decode_msp_bat_setting_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Battery Settings"
    return MSG_INVALID_PAYLOAD

def decode_msp_bat_setting_response(payload: bytes) -> str:
    try:
        bat_setting = payload.decode('ascii', 'replace').rstrip('\x00')
        return f"Battery Settings: {bat_setting}"
    except:
        return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP_SET_BAT_SETTING
# ---------------------------
def decode_msp_set_bat_setting_request(payload: bytes) -> str:
    try:
        bat_setting = payload.decode('ascii', 'replace').rstrip('\x00')
        return f"Set Battery Settings: {bat_setting}"
    except:
        return MSG_INVALID_PAYLOAD

def decode_msp_set_bat_setting_response(payload: bytes) -> str:
    if len(payload) == 0:
        return "Battery settings set successfully"
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP_PID
# ---------------------------
def decode_msp_pid_request(payload: bytes) -> str:
    """
    Decodes the request for PID settings.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request PID Settings"
    return MSG_INVALID_PAYLOAD

def decode_msp_pid_response(payload: bytes) -> str:
    """
    Decodes the response for PID settings.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 24:  # Assuming 6 PIDs, each with 4 bytes (Kp, Ki, Kd)
        return MSG_INVALID_PAYLOAD

    # Unpack the PID values (Kp, Ki, Kd) for Roll, Pitch, Yaw
    roll_pid = struct.unpack('<fff', payload[0:12])  # Roll PID values
    pitch_pid = struct.unpack('<fff', payload[12:24])  # Pitch PID values
    yaw_pid = struct.unpack('<fff', payload[24:36])  # Yaw PID values

    return (f"PID Settings: Roll PID={roll_pid}, "
            f"Pitch PID={pitch_pid}, Yaw PID={yaw_pid}")

# ---------------------------
# MSP_MOTOR_3D_CONFIG
# ---------------------------
def decode_msp_motor_3d_config_request(payload: bytes) -> str:
    """
    Decodes the request for 3D motor configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request 3D Motor Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_motor_3d_config_response(payload: bytes) -> str:
    """
    Decodes the response for 3D motor configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 12:  # Assuming 3 motors, each with 4 bytes (Kp, Ki, Kd)
        return MSG_INVALID_PAYLOAD

    # Unpack the motor configuration values (Kp, Ki, Kd) for each motor
    motor1_config = struct.unpack('<fff', payload[0:12])  # Motor 1 PID values
    motor2_config = struct.unpack('<fff', payload[12:24])  # Motor 2 PID values
    motor3_config = struct.unpack('<fff', payload[24:36])  # Motor 3 PID values

    return (f"3D Motor Configuration: Motor 1 PID={motor1_config}, "
            f"Motor 2 PID={motor2_config}, Motor 3 PID={motor3_config}")

# ---------------------------
# MSP_LED_STRIP_MODECOLOR
# ---------------------------
def decode_msp_led_strip_modecolor_request(payload: bytes) -> str:
    """
    Decodes the request for LED strip mode and color settings.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request LED Strip Mode and Color"
    return MSG_INVALID_PAYLOAD

def decode_msp_led_strip_modecolor_response(payload: bytes) -> str:
    """
    Decodes the response for LED strip mode and color settings.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 4:
        return MSG_INVALID_PAYLOAD

    mode = payload[0]  # Mode of the LED strip
    red = payload[1]   # Red color component
    green = payload[2] # Green color component
    blue = payload[3]  # Blue color component

    return (f"LED Strip Mode: {mode}, Color: ({red}, {green}, {blue})")

# ---------------------------
# MSP_BATTERY_STATE
# ---------------------------
def decode_msp_battery_state_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Battery State"
    return MSG_INVALID_PAYLOAD

def decode_msp_battery_state_response(payload: bytes) -> str:
    if len(payload) < 6:
        return MSG_INVALID_PAYLOAD

    cell_count = payload[0]
    voltage = int.from_bytes(payload[1:3], 'little')  # Voltage in millivolts
    current = int.from_bytes(payload[3:5], 'little')  # Current in milliamps
    capacity = int.from_bytes(payload[5:7], 'little')  # Capacity in mAh

    return (f"Battery State: {cell_count} cells, "
            f"Voltage={voltage / 1000.0:.2f}V, "
            f"Current={current}mA, "
            f"Capacity={capacity}mAh")

# ---------------------------
# MSP_MOTOR_CONFIG
# ---------------------------
def decode_msp_motor_config_request(payload: bytes) -> str:
    """
    Decodes the request for motor configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request Motor Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_motor_config_response(payload: bytes) -> str:
    """
    Decodes the response for motor configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 12:  # Assuming 3 motors, each with 4 bytes (Kp, Ki, Kd)
        return MSG_INVALID_PAYLOAD

    motor1_config = struct.unpack('<fff', payload[0:12])  # Motor 1 PID values
    motor2_config = struct.unpack('<fff', payload[12:24])  # Motor 2 PID values
    motor3_config = struct.unpack('<fff', payload[24:36])  # Motor 3 PID values

    return (f"Motor Configuration: Motor 1 PID={motor1_config}, "
            f"Motor 2 PID={motor2_config}, Motor 3 PID={motor3_config}")

# ---------------------------
# MSP_VTXTABLE_POWERLEVEL
# ---------------------------
def decode_msp_vtxtable_powerlevel_request(payload: bytes) -> str:
    """
    Decodes the request for VTX table power level.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request VTX Table Power Level"
    return MSG_INVALID_PAYLOAD

def decode_msp_vtxtable_powerlevel_response(payload: bytes) -> str:
    """
    Decodes the response for VTX table power level.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 1:
        return MSG_INVALID_PAYLOAD

    power_level = payload[0]  # Power level (0-7)
    return f"VTX Table Power Level: {power_level}"

# ---------------------------
# MSP_MOTOR_TELEMETRY
# ---------------------------
def decode_msp_motor_telemetry_request(payload: bytes) -> str:
    """
    Decodes the request for motor telemetry data.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request Motor Telemetry Data"
    return MSG_INVALID_PAYLOAD

def decode_msp_motor_telemetry_response(payload: bytes) -> str:
    """
    Decodes the response for motor telemetry data.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 12:  # Assuming telemetry data for 3 motors
        return MSG_INVALID_PAYLOAD

    motor1_rpm = int.from_bytes(payload[0:4], 'little')  # Motor 1 RPM
    motor2_rpm = int.from_bytes(payload[4:8], 'little')  # Motor 2 RPM
    motor3_rpm = int.from_bytes(payload[8:12], 'little')  # Motor 3 RPM

    return (f"Motor Telemetry: Motor 1 RPM={motor1_rpm}, "
            f"Motor 2 RPM={motor2_rpm}, Motor 3 RPM={motor3_rpm}")
    
# ---------------------------
# MSP_ARMING_CONFIG
# ---------------------------
def decode_msp_arming_config_request(payload: bytes) -> str:
    """
    Decodes the request for arming configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request Arming Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_arming_config_response(payload: bytes) -> str:
    """
    Decodes the response for arming configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 4:  # Expecting at least 4 bytes for arming config
        return MSG_INVALID_PAYLOAD

    # Unpack the arming configuration data
    # Example structure:
    # [0] - Auto disarm delay (uint8_t)
    # [1] - Reserved (uint8_t, typically set to 0)
    # [2] - Small angle (uint8_t)
    # [3] - Gyro calibration on first arm (uint8_t)

    auto_disarm_delay = payload[0]  # Auto disarm delay
    reserved = payload[1]  # Reserved, typically 0
    small_angle = payload[2]  # Small angle
    gyro_cal_on_first_arm = payload[3]  # Gyro calibration on first arm

    return (f"Arming Configuration: Auto Disarm Delay={auto_disarm_delay}s, "
            f"Small Angle={small_angle}°, "
            f"Gyro Cal on First Arm={gyro_cal_on_first_arm}")

# ---------------------------
# MSP_RC_DEADBAND
# ---------------------------
def decode_msp_rc_deadband_request(payload: bytes) -> str:
    """
    Decodes the request for RC deadband configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request RC Deadband Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_rc_deadband_response(payload: bytes) -> str:
    """
    Decodes the response for RC deadband configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 5:  # Expecting at least 5 bytes for deadband config
        return MSG_INVALID_PAYLOAD

    # Unpack the RC deadband configuration data
    # Example structure:
    # [0] - RC deadband (uint8_t)
    # [1] - Yaw deadband (uint8_t)
    # [2] - Position hold deadband (uint8_t) or 0 if not used
    # [3:4] - 3D deadband throttle (uint16_t)

    rc_deadband = payload[0]  # RC deadband value
    yaw_deadband = payload[1]  # Yaw deadband value
    pos_hold_deadband = payload[2]  # Position hold deadband value or 0
    deadband3d_throttle = int.from_bytes(payload[3:5], 'little')  # 3D deadband throttle

    return (f"RC Deadband Configuration: "
            f"RC Deadband={rc_deadband}, "
            f"Yaw Deadband={yaw_deadband}, "
            f"Position Hold Deadband={pos_hold_deadband}, "
            f"3D Deadband Throttle={deadband3d_throttle}")

# ---------------------------
# MSP_SENSOR_CONFIG
# ---------------------------
def decode_msp_sensor_config_request(payload: bytes) -> str:
    """
    Decodes the request for sensor configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request Sensor Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_sensor_config_response(payload: bytes) -> str:
    """
    Decodes the response for sensor configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 4:  # Assuming at least 4 bytes for sensor config
        return MSG_INVALID_PAYLOAD

    # Unpack the sensor configuration data
    # Example structure:
    # [0] - Gyro configuration (uint8_t)
    # [1] - Accelerometer configuration (uint8_t)
    # [2] - Magnetometer configuration (uint8_t)
    # [3] - Barometer configuration (uint8_t)

    gyro_config = payload[0]  # Gyro configuration
    accel_config = payload[1]  # Accelerometer configuration
    mag_config = payload[2]  # Magnetometer configuration
    baro_config = payload[3]  # Barometer configuration

    return (f"Sensor Configuration: "
            f"Gyro={gyro_config}, "
            f"Accelerometer={accel_config}, "
            f"Magnetometer={mag_config}, "
            f"Barometer={baro_config}")

# ---------------------------
# MSP_ADVANCED_CONFIG
# ---------------------------
def decode_msp_advanced_config_request(payload: bytes) -> str:
    """
    Decodes the request for advanced configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request Advanced Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_advanced_config_response(payload: bytes) -> str:
    """
    Decodes the response for advanced configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 14:  # Expecting at least 14 bytes for advanced config
        return MSG_INVALID_PAYLOAD

    # Unpack the advanced configuration data
    # Example structure:
    # [0] - Gyro sync denom (uint8_t) - removed in API 1.43
    # [1] - PID process denom (uint8_t)
    # [2] - Use unsynced PWM (uint8_t)
    # [3] - Motor PWM protocol (uint8_t)
    # [4:5] - Motor PWM rate (uint16_t)
    # [6:7] - Motor idle (uint16_t)
    # [8] - Deprecated: gyro_use_32kHz (uint8_t)
    # [9] - Motor PWM inversion (uint8_t)
    # [10] - Gyro to use (uint8_t)
    # [11] - Gyro high FSR (uint8_t)
    # [12] - Gyro movement calibration threshold (uint8_t)
    # [13:14] - Gyro calibration duration (uint16_t)
    # [15:16] - Gyro offset yaw (uint16_t)
    # [17] - Check overflow (uint8_t)
    # [18] - Debug mode (uint8_t)
    # [19] - Debug count (uint8_t)

    pid_process_denom = payload[1]  # PID process denom
    use_unsynced_pwm = payload[2]  # Use unsynced PWM
    motor_pwm_protocol = payload[3]  # Motor PWM protocol
    motor_pwm_rate = int.from_bytes(payload[4:6], 'little')  # Motor PWM rate
    motor_idle = int.from_bytes(payload[6:8], 'little')  # Motor idle
    motor_pwm_inversion = payload[9]  # Motor PWM inversion
    gyro_to_use = payload[10]  # Gyro to use
    gyro_high_fsr = payload[11]  # Gyro high FSR
    gyro_movement_calibration_threshold = payload[12]  # Gyro movement calibration threshold
    gyro_calibration_duration = int.from_bytes(payload[13:15], 'little')  # Gyro calibration duration
    gyro_offset_yaw = int.from_bytes(payload[15:17], 'little')  # Gyro offset yaw
    check_overflow = payload[17]  # Check overflow
    debug_mode = payload[18]  # Debug mode
    debug_count = payload[19]  # Debug count

    return (f"Advanced Configuration: "
            f"PID Process Denom={pid_process_denom}, "
            f"Use Unsynced PWM={use_unsynced_pwm}, "
            f"Motor PWM Protocol={motor_pwm_protocol}, "
            f"Motor PWM Rate={motor_pwm_rate}, "
            f"Motor Idle={motor_idle}, "
            f"Motor PWM Inversion={motor_pwm_inversion}, "
            f"Gyro to Use={gyro_to_use}, "
            f"Gyro High FSR={gyro_high_fsr}, "
            f"Gyro Movement Calibration Threshold={gyro_movement_calibration_threshold}, "
            f"Gyro Calibration Duration={gyro_calibration_duration}, "
            f"Gyro Offset Yaw={gyro_offset_yaw}, "
            f"Check Overflow={check_overflow}, "
            f"Debug Mode={debug_mode}, "
            f"Debug Count={debug_count}")

# ---------------------------
# MSP_VOLTAGE_METERS
# ---------------------------
def decode_msp_voltage_meters_request(payload: bytes) -> str:
    """
    Decodes the request for voltage meter configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request Voltage Meters Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_voltage_meters_response(payload: bytes) -> str:
    """
    Decodes the response for voltage meter configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
 
    # Each meter has an ID and a filtered voltage value
    index = 0
    response = ""
    while True:
        if index < len(payload):
            meter_id = payload[index]  # Meter ID
        else:
            break
        if index + 1 < len(payload):
            filtered_voltage = payload[index + 1]  # Filtered voltage value
        else:
            break

        response += (f", {meter_id}: {filtered_voltage * 10} mV\n")  # Convert back to mV

        index += 2  # Move to the next meter (2 bytes per meter)

    return response.strip()  # Remove any trailing whitespace

# ---------------------------
# MSP_CURRENT_METERS
# ---------------------------
def decode_msp_current_meters_request(payload: bytes) -> str:
    """
    Decodes the request for current meter configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request Current Meters Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_current_meters_response(payload: bytes) -> str:
    """
    Decodes the response for current meter configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """

    # Each meter has an ID, mAh drawn, and current value
    index = 0
    response = ""
    while True:
        if index < len(payload):
            meter_id = payload[index]  # Meter ID
        else:
            break
        if index + 2 < len(payload):
            mAh_drawn = int.from_bytes(payload[index + 1:index + 3], 'little')  # mAh drawn
        else:
            break

        if index + 4 < len(payload):
            amperage = int.from_bytes(payload[index + 3:index + 5], 'little')  # Current in mA
        else:
            break

        response += (f"Meter ID: {meter_id}, "
                     f"mAh Drawn: {mAh_drawn} mAh, "
                     f"Current: {amperage} mA\n")

        index += 5  # Move to the next meter (1 byte for ID + 2 bytes for mAh + 2 bytes for current)

    return response.strip()  # Remove any trailing whitespace

# ---------------------------
# MSP_CURRENT_METER_CONFIG
# ---------------------------
def decode_msp_current_meter_config_request(payload: bytes) -> str:
    """
    Decodes the request for current meter configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request Current Meter Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_current_meter_config_response(payload: bytes) -> str:
    """
    Decodes the response for current meter configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 1:  # At least 1 byte for the count
        return MSG_INVALID_PAYLOAD

    # The first byte indicates the number of current meters
    current_meter_count = payload[0]
    response = f"Count: {current_meter_count}\n"

    index = 1
    for i in range(current_meter_count):
        if index + 4 >= len(payload):
            return MSG_INVALID_PAYLOAD  # Not enough data for the expected count

        subframe_length = payload[index]  # Length of the subframe
        meter_id = payload[index + 1]  # Meter ID
        sensor_type = payload[index + 2]  # Sensor type
        scale = int.from_bytes(payload[index + 3:index + 5], 'little')  # Scale
        offset = int.from_bytes(payload[index + 5:index + 7], 'little')  # Offset

        response += (f", ID: {meter_id}, "
                     f"Type: {sensor_type}, "
                     f"Scale: {scale}, "
                     f"Offset: {offset}\n")

        index += subframe_length + 1  # Move to the next meter (subframe length + 1 for the count byte)

    return response.strip()  # Remove any trailing whitespace

# ---------------------------
# MSP_VOLTAGE_METER_CONFIG
# ---------------------------
def decode_msp_voltage_meter_config_request(payload: bytes) -> str:
    """
    Decodes the request for voltage meter configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request Voltage Meter Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_voltage_meter_config_response(payload: bytes) -> str:
    """
    Decodes the response for voltage meter configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 1:  # At least 1 byte for the count
        return MSG_INVALID_PAYLOAD

    # The first byte indicates the number of voltage meters
    max_voltage_sensors = payload[0]
    response = f"Count: {max_voltage_sensors}\n"

    index = 1
    for i in range(max_voltage_sensors):
        if index + 5 >= len(payload):
            return MSG_INVALID_PAYLOAD  # Not enough data for the expected count

        subframe_length = payload[index]  # Length of the subframe
        meter_id = payload[index + 1]  # Meter ID
        sensor_type = payload[index + 2]  # Sensor type
        vbat_scale = payload[index + 3]  # Scale for voltage
        vbat_res_div_val = payload[index + 4]  # Resistor divider value
        vbat_res_div_multiplier = payload[index + 5]  # Resistor divider multiplier

        response += (f", ID: {meter_id}, "
                     f"Type: {sensor_type}, "
                     f"Scale: {vbat_scale}, "
                     f"Div: {vbat_res_div_val}, "
                     f"Mult: {vbat_res_div_multiplier}\n")

        index += subframe_length + 1  # Move to the next meter (subframe length + 1 for the count byte)

    return response.strip()  # Remove any trailing whitespace

# ---------------------------
# MSP_RX_CONFIG
# ---------------------------
def decode_msp_rx_config_request(payload: bytes) -> str:
    """
    Decodes the request for RX configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request RX Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_rx_config_response(payload: bytes) -> str:
    """
    Decodes the response for RX configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 20:  # Minimum expected length based on the parameters
        return MSG_INVALID_PAYLOAD

    index = 0
    serial_rx_provider = payload[index]  # Serial RX provider
    index += 1
    max_check = int.from_bytes(payload[index:index + 2], 'little')  # Max check
    index += 2
    mid_rc = int.from_bytes(payload[index:index + 2], 'little')  # Mid RC
    index += 2
    min_check = int.from_bytes(payload[index:index + 2], 'little')  # Min check
    index += 2
    spektrum_sat_bind = payload[index]  # Spektrum satellite bind
    index += 1
    rx_min_usec = int.from_bytes(payload[index:index + 2], 'little')  # RX min usec
    index += 2
    rx_max_usec = int.from_bytes(payload[index:index + 2], 'little')  # RX max usec
    index += 2
    # Skip the two bytes that are not required in API 1.44
    index += 2  # Skip rcInterpolation and rcInterpolationInterval
    air_mode_activate_threshold = int.from_bytes(payload[index:index + 2], 'little') / 10 - 1000  # Air mode activate threshold
    index += 2

    # Check for SPI RX configuration
    if len(payload) > index:
        rx_spi_protocol = payload[index]  # RX SPI protocol
        index += 1
        rx_spi_id = int.from_bytes(payload[index:index + 4], 'little')  # RX SPI ID
        index += 4
        rx_spi_rf_channel_count = payload[index]  # RX SPI RF channel count
        index += 1
    else:
        rx_spi_protocol = 0
        rx_spi_id = 0
        rx_spi_rf_channel_count = 0

    fpv_cam_angle_degrees = payload[index]  # FPV camera angle
    index += 1

    # Skip the byte that is not required in API 1.44
    index += 1  # Skip rcSmoothingChannels

    # Check for RC smoothing filter configuration
    if len(payload) > index:
        rc_smoothing_auto_factor_rpy = payload[index]  # RC smoothing auto factor RPY
        index += 1
        rc_smoothing_mode = payload[index]  # RC smoothing mode
        index += 1
    else:
        rc_smoothing_auto_factor_rpy = 0
        rc_smoothing_mode = 0

    # Check for ExpressLRS configuration
    if len(payload) > index:
        uid = payload[index:index + 6]  # ExpressLRS UID
        index += 6
        model_id = payload[index]  # ExpressLRS model ID
    else:
        uid = bytes(6)  # Empty UID
        model_id = 0

    # Construct the response string
    response = (f"Ser RX: {serial_rx_provider}\n"
                f"{max_check}/{mid_rc}/{min_check}\n"
                f"Spek Bind: {spektrum_sat_bind}\n"
                f"{rx_min_usec}/{rx_max_usec}\n"
                f"Air: {air_mode_activate_threshold}\n"
                f"Cam: {fpv_cam_angle_degrees}\n"
                f"SPI: {rx_spi_protocol}/{rx_spi_id}/{rx_spi_rf_channel_count}\n"
                f"Auto: {rc_smoothing_auto_factor_rpy}\n"
                f"Mode: {rc_smoothing_mode}\n"
                f"ELRS: {uid.hex()}/{model_id}\n")

    return response.strip()  # Remove any trailing whitespace

# ---------------------------
# MSP_FAILSAFE_CONFIG
# ---------------------------
def decode_msp_failsafe_config_request(payload: bytes) -> str:
    """
    Decodes the request for failsafe configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request Failsafe Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_failsafe_config_response(payload: bytes) -> str:
    """
    Decodes the response for failsafe configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 8:  # Minimum expected length based on the parameters
        return MSG_INVALID_PAYLOAD

    index = 0
    failsafe_delay = payload[index]  # Failsafe delay
    index += 1
    failsafe_landing_time = payload[index]  # Failsafe landing time
    index += 1
    failsafe_throttle = int.from_bytes(payload[index:index + 1], 'little')  # Failsafe throttle
    index += 2
    failsafe_switch_mode = payload[index]  # Failsafe switch mode
    index += 1
    failsafe_throttle_low_delay = int.from_bytes(payload[index:index + 1], 'little')  # Failsafe throttle low delay
    index += 2
    failsafe_procedure = payload[index]  # Failsafe procedure

    # Construct the response string
    response = (f"Delay: {failsafe_delay}\n"
                f"Time: {failsafe_landing_time}\n"
                f"Thr: {failsafe_throttle}\n"
                f"Mode: {failsafe_switch_mode}\n"
                f"Thr Low Delay: {failsafe_throttle_low_delay}\n"
                f"Proc: {failsafe_procedure}\n")

    return response.strip()  # Remove any trailing whitespace
                                                
# ---------------------------
# MSP_RXFAIL_CONFIG
# ---------------------------
def decode_msp_rxfail_config_request(payload: bytes) -> str:
    """
    Decodes the request for RX failsafe configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request RX Failsafe Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_rxfail_config_response(payload: bytes) -> str:
    """
    Decodes the response for RX failsafe configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    index = 0
    response = ""
    for i in range(1, 32):
        if index < len(payload):
            mode = payload[index]  # Mode for the channel
        else:
            break
        if index + 2 < len(payload):
            step_value = int.from_bytes(payload[index + 1:index + 3], 'little')  # Step value for the channel
        else:
            break

        index += 3

        response += (f"{i}:{mode}/{step_value}\n")

    return response.strip()  # Remove any trailing whitespace

# ---------------------------
# MSP_GPS_RESCUE
# ---------------------------
def decode_msp_gps_rescue_request(payload: bytes) -> str:
    """
    Decodes the request for GPS rescue configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request GPS Rescue Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_gps_rescue_response(payload: bytes) -> str:
    """
    Decodes the response for GPS rescue configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 20:  # Minimum expected length based on the parameters
        return MSG_INVALID_PAYLOAD

    index = 0
    max_rescue_angle = int.from_bytes(payload[index:index + 2], 'little')  # Max rescue angle
    index += 2
    return_altitude_m = int.from_bytes(payload[index:index + 2], 'little')  # Return altitude
    index += 2
    descent_distance_m = int.from_bytes(payload[index:index + 2], 'little')  # Descent distance
    index += 2
    ground_speed_cm_s = int.from_bytes(payload[index:index + 2], 'little')  # Ground speed
    index += 2
    throttle_min = int.from_bytes(payload[index:index + 2], 'little')  # Minimum throttle
    index += 2
    throttle_max = int.from_bytes(payload[index:index + 2], 'little')  # Maximum throttle
    index += 2
    hover_throttle = int.from_bytes(payload[index:index + 2], 'little')  # Hover throttle
    index += 2
    sanity_checks = payload[index]  # Sanity checks
    index += 1
    min_sats = payload[index]  # Minimum satellites
    index += 1

    # Added in API version 1.43
    ascend_rate = int.from_bytes(payload[index:index + 2], 'little')  # Ascend rate
    index += 2
    descend_rate = int.from_bytes(payload[index:index + 2], 'little')  # Descend rate
    index += 2
    allow_arming_without_fix = payload[index]  # Allow arming without GPS fix
    index += 1
    altitude_mode = payload[index]  # Altitude mode
    index += 1

    # Added in API version 1.44
    min_start_dist_m = int.from_bytes(payload[index:index + 2], 'little')  # Minimum start distance
    index += 2

    # Added in API version 1.46
    initial_climb_m = int.from_bytes(payload[index:index + 2], 'little')  # Initial climb
    index += 2

    # Construct the response string
    response = (f"Max Angle: {max_rescue_angle}\n"
                f"Ret Alt: {return_altitude_m} m\n"
                f"Descent Dist: {descent_distance_m} m\n"
                f"Grd Spd: {ground_speed_cm_s} cm/s\n"
                f"Thr Min: {throttle_min}\n"
                f"Thr Max: {throttle_max}\n"
                f"Hover Thr: {hover_throttle}\n"
                f"Sanity: {sanity_checks}\n"
                f"Min Sat: {min_sats}\n"
                f"Ascend: {ascend_rate}\n"
                f"Descend: {descend_rate}\n"
                f"Arm no fix: {allow_arming_without_fix}\n"
                f"Altitude: {altitude_mode}\n"
                f"Min Dist: {min_start_dist_m} m\n"
                f"Climb: {initial_climb_m} m\n")

    return response.strip()  # Remove any trailing whitespace

# ---------------------------
# MSP_RSSI_CONFIG
# ---------------------------
def decode_msp_rssi_config_request(payload: bytes) -> str:
    """
    Decodes the request for RSSI configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request RSSI Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_rssi_config_response(payload: bytes) -> str:
    """
    Decodes the response for RSSI configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 1:  # At least 1 byte for the RSSI channel
        return MSG_INVALID_PAYLOAD

    rssi_channel = payload[0]  # RSSI channel

    # Construct the response string
    response = (f"Channel: {rssi_channel}\n")

    return response.strip()  # Remove any trailing whitespace

# ---------------------------
# MSP_FEATURE_CONFIG
# ---------------------------
def decode_msp_feature_config_request(payload: bytes) -> str:
    """
    Decodes the request for feature configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request Feature Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_feature_config_response(payload: bytes) -> str:
    """
    Decodes the response for feature configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 4:  # At least 4 bytes for the 32-bit bitmask
        return MSG_INVALID_PAYLOAD

    # Read the enabled features bitmask
    enabled_features = int.from_bytes(payload[0:4], 'little')

    # Construct the response string
    response = (f"Mask: {enabled_features:#010b} (0x{enabled_features:X})\n")

    return response.strip()  # Remove any trailing whitespace

# ---------------------------
# MSP_MOTOR_CONFIG
# ---------------------------
def decode_msp_motor_config_request(payload: bytes) -> str:
    """
    Decodes the request for motor configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request Motor Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_motor_config_response(payload: bytes) -> str:
    """
    Decodes the response for motor configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 10:  # Minimum expected length based on the parameters
        return MSG_INVALID_PAYLOAD

    index = 0
    # Skip the first 2 bytes (previously minthrottle)
    index += 2
    max_throttle = int.from_bytes(payload[index:index + 2], 'little')  # Max throttle
    index += 2
    min_command = int.from_bytes(payload[index:index + 2], 'little')  # Min command
    index += 2

    motor_count = payload[index]  # Motor count
    index += 1
    motor_pole_count = payload[index]  # Motor pole count
    index += 1

    # Check for DShot telemetry
    if index < len(payload):
        use_dshot_telemetry = payload[index]  # DShot telemetry usage
        index += 1
    else:
        use_dshot_telemetry = 0

    # Check for ESC sensor
    if index < len(payload):
        esc_sensor_available = payload[index]  # ESC sensor availability
    else:
        esc_sensor_available = 0

    # Construct the response string
    response = (f"Max Thr: {max_throttle}\n"
                f"Min: {min_command}\n"
                f"Count: {motor_count}\n"
                f"Pole Count: {motor_pole_count}\n"
                f"DShot Telem: {use_dshot_telemetry}\n"
                f"ESC Sensor: {esc_sensor_available}\n")

    return response.strip()  # Remove any trailing whitespace

# ---------------------------
# MSP_PID_CONTROLLER
# ---------------------------
def decode_msp_pid_controller_request(payload: bytes) -> str:
    """
    Decodes the request for PID controller configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request PID Controller Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_pid_controller_response(payload: bytes) -> str:
    """
    Decodes the response for PID controller configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 1:  # At least 1 byte for the PID controller type
        return MSG_INVALID_PAYLOAD

    pid_controller_type = payload[0]  # PID controller type

    # Construct the response string
    response = (f"PID Controller Type: {pid_controller_type}\n")

    return response.strip()  # Remove any trailing whitespace

# ---------------------------
# MSP_PID
# ---------------------------
def decode_msp_pid_request(payload: bytes) -> str:
    """
    Decodes the request for PID configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request PID Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_pid_response(payload: bytes) -> str:
    """
    Decodes the response for PID configuration.

    :param payload: Payload bytes
    :param pid_item_count: Number of PID items
    :return: Decoded string
    """
    # Each PID has P, I and D
    index = 0
    pid = 0
    response = ""
    while True:
        if index < len(payload):
            P = payload[index]  # P
        else:
            break
        if index + 1 < len(payload):
            I = payload[index + 1]  # P
        else:
            break
        if index + 2 < len(payload):
            D = payload[index + 2]  # P
        else:
            break
        
        index += 3
        pid += 1

        response += (f"PID {pid}: {P}/{I}/{D}\n")

    return response.strip()  # Remove any trailing whitespace

# ---------------------------
# MSP_PID_ADVANCED
# ---------------------------
def decode_msp_pid_advanced_request(payload: bytes) -> str:
    """
    Decodes the request for advanced PID configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request Advanced PID Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_pid_advanced_response(payload: bytes) -> str:
    """
    Decodes the response for advanced PID configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 40:  # Minimum expected length based on the parameters
        return MSG_INVALID_PAYLOAD

    index = 0
    # Skip the first three 16-bit values
    index += 6  # Skip 3 * 2 bytes (0, 0, yaw_p_limit)
    index += 2  # Skip two reserved bytes
    feedforward_transition = payload[index]  # Feedforward transition
    index += 1
    dterm_setpoint_weight_low_byte = payload[index]  # Low byte of dterm setpoint weight
    index += 1
    index += 3  # Skip three reserved bytes
    rate_accel_limit = int.from_bytes(payload[index:index + 2], 'little')  # Rate acceleration limit
    index += 2
    yaw_rate_accel_limit = int.from_bytes(payload[index:index + 2], 'little')  # Yaw rate acceleration limit
    index += 2
    angle_limit = payload[index]  # Angle limit
    index += 1
    iterm_throttle_threshold = int.from_bytes(payload[index:index + 2], 'little')  # I-term throttle threshold
    index += 2
    anti_gravity_gain = int.from_bytes(payload[index:index + 2], 'little')  # Anti-gravity gain
    index += 2
    dterm_setpoint_weight = int.from_bytes(payload[index:index + 2], 'little')  # D-term setpoint weight
    index += 2
    iterm_rotation = payload[index]  # I-term rotation
    index += 1

    # Check for optional features
    iterm_relax = payload[index] if index < len(payload) else 0  # I-term relax
    index += 1
    iterm_relax_type = payload[index] if index < len(payload) else 0  # I-term relax type
    index += 1

    abs_control_gain = payload[index] if index < len(payload) else 0  # Absolute control gain
    index += 1

    throttle_boost = payload[index] if index < len(payload) else 0  # Throttle boost
    index += 1

    acro_trainer_angle_limit = payload[index] if index < len(payload) else 0  # Acro trainer angle limit
    index += 1

    # PID values for roll, pitch, yaw
    roll_F = int.from_bytes(payload[index:index + 2], 'little')
    index += 2
    pitch_F = int.from_bytes(payload[index:index + 2], 'little')
    index += 2
    yaw_F = int.from_bytes(payload[index:index + 2], 'little')
    index += 2

    anti_gravity_mode = payload[index]  # Anti-gravity mode
    index += 1

    # D-max values
    d_max_roll = payload[index] if index < len(payload) else 0
    index += 1
    d_max_pitch = payload[index] if index < len(payload) else 0
    index += 1
    d_max_yaw = payload[index] if index < len(payload) else 0
    index += 1
    d_max_gain = payload[index] if index < len(payload) else 0
    index += 1

    # Integrated yaw control
    use_integrated_yaw = payload[index] if index < len(payload) else 0
    index += 1
    integrated_yaw_relax = payload[index] if index < len(payload) else 0
    index += 1

    # I-term relax cutoff
    iterm_relax_cutoff = payload[index] if index < len(payload) else 0
    index += 1

    # Motor output limit and auto profile cell count
    motor_output_limit = payload[index] if index < len(payload) else 0
    index += 1
    auto_profile_cell_count = payload[index] if index < len(payload) else 0
    index += 1

    # Dynamic idle min RPM
    dyn_idle_min_rpm = payload[index] if index < len(payload) else 0
    index += 1

    # Feedforward settings
    feedforward_averaging = payload[index] if index < len(payload) else 0
    index += 1
    feedforward_smooth_factor = payload[index] if index < len(payload) else 0
    index += 1
    feedforward_boost = payload[index] if index < len(payload) else 0
    index += 1
    feedforward_max_rate_limit = payload[index] if index < len(payload) else 0
    index += 1
    feedforward_jitter_factor = payload[index] if index < len(payload) else 0
    index += 1

    # Battery voltage sag compensation
    vbat_sag_compensation = payload[index] if index < len(payload) else 0
    index += 1

    # Thrust linearization
    thrust_linearization = payload[index] if index < len(payload) else 0
    index += 1

    # TPA settings
    tpa_mode = payload[index] if index < len(payload) else 0
    index += 1
    tpa_rate = payload[index] if index < len(payload) else 0
    index += 1
    tpa_breakpoint = int.from_bytes(payload[index:index + 2], 'little') if index < len(payload) else 0  # TPA breakpoint

    # Construct the response string excluding reserved values
    response = (f"FF Trans: {feedforward_transition}\n"
                f"Dterm SetP: {dterm_setpoint_weight_low_byte}\n"
                f"Rate Lim: {rate_accel_limit}\n"
                f"Yaw Lim: {yaw_rate_accel_limit}\n"
                f"Ang Lim: {angle_limit}\n"
                f"I Thr: {iterm_throttle_threshold}\n"
                f"AG Gain: {anti_gravity_gain}\n"
                f"Dterm SetP: {dterm_setpoint_weight}\n"
                f"I Rot: {iterm_rotation}\n"
                f"I Rel: {iterm_relax}\n"
                f"I Type: {iterm_relax_type}\n"
                f"Abs Ctrl: {abs_control_gain}\n"
                f"Thr Boost: {throttle_boost}\n"
                f"Acro Ang Lim: {acro_trainer_angle_limit}\n"
                f"Roll F: {roll_F}\n"
                f"Pitch F: {pitch_F}\n"
                f"Yaw F: {yaw_F}\n"
                f"AG Mode: {anti_gravity_mode}\n"
                f"Dm R: {d_max_roll}\n"
                f"Dm P: {d_max_pitch}\n"
                f"Dm Y: {d_max_yaw}\n"
                f"Dm G: {d_max_gain}\n"
                f"Int Y: {use_integrated_yaw}\n"
                f"Int Y Rel: {integrated_yaw_relax}\n"
                f"I Rel Cutoff: {iterm_relax_cutoff}\n"
                f"Motor Lim {motor_output_limit}\n"
                f"AP Cellst: {auto_profile_cell_count}\n"
                f"Dyn Idle: {dyn_idle_min_rpm}\n"
                f"FF Averaging: {feedforward_averaging}\n"
                f"FF Smooth Factor: {feedforward_smooth_factor}\n"
                f"FF Boost: {feedforward_boost}\n"
                f"FF Lim: {feedforward_max_rate_limit}\n"
                f"FF Jit: {feedforward_jitter_factor}\n"
                f"VBAT Sag: {vbat_sag_compensation}\n"
                f"Thrust Lin: {thrust_linearization}\n"
                f"TPA M: {tpa_mode}\n"
                f"TPA R: {tpa_rate}\n"
                f"TPA B: {tpa_breakpoint}\n")

    return response.strip()  # Remove any trailing whitespace

# ---------------------------
# MSP_FILTER_CONFIG
# ---------------------------
def decode_msp_filter_config_request(payload: bytes) -> str:
    """
    Decodes the request for filter configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request Filter Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_filter_config_response(payload: bytes) -> str:
    """
    Decodes the response for filter configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 40:  # Minimum expected length based on the parameters
        return MSG_INVALID_PAYLOAD

    index = 0
    gyro_lpf1_static_hz = payload[index]  # Gyro LPF1 static Hz
    index += 1
    dterm_lpf1_static_hz = int.from_bytes(payload[index:index + 2], 'little')  # D-term LPF1 static Hz
    index += 2
    yaw_lowpass_hz = int.from_bytes(payload[index:index + 2], 'little')  # Yaw lowpass Hz
    index += 2
    gyro_soft_notch_hz_1 = int.from_bytes(payload[index:index + 2], 'little')  # Gyro soft notch Hz 1
    index += 2
    gyro_soft_notch_cutoff_1 = int.from_bytes(payload[index:index + 2], 'little')  # Gyro soft notch cutoff 1
    index += 2
    dterm_notch_hz = int.from_bytes(payload[index:index + 2], 'little')  # D-term notch Hz
    index += 2
    dterm_notch_cutoff = int.from_bytes(payload[index:index + 2], 'little')  # D-term notch cutoff
    index += 2
    gyro_soft_notch_hz_2 = int.from_bytes(payload[index:index + 2], 'little')  # Gyro soft notch Hz 2
    index += 2
    gyro_soft_notch_cutoff_2 = int.from_bytes(payload[index:index + 2], 'little')  # Gyro soft notch cutoff 2
    index += 2
    dterm_lpf1_type = payload[index]  # D-term LPF1 type
    index += 1
    gyro_hardware_lpf = payload[index]  # Gyro hardware LPF
    index += 1
    index += 1  # Skip deprecated gyro_32khz_hardware_lpf
    # gyro_lpf1_static_hz = int.from_bytes(payload[index:index + 2], 'little')  # Gyro LPF1 static Hz (again)
    index += 2
    gyro_lpf2_static_hz = int.from_bytes(payload[index:index + 2], 'little')  # Gyro LPF2 static Hz
    index += 2
    gyro_lpf1_type = payload[index]  # Gyro LPF1 type
    index += 1
    gyro_lpf2_type = payload[index]  # Gyro LPF2 type
    index += 1
    dterm_lpf2_static_hz = int.from_bytes(payload[index:index + 2], 'little')  # D-term LPF2 static Hz
    index += 2

    # Added in MSP API 1.41
    dterm_lpf2_type = payload[index]  # D-term LPF2 type
    index += 1

    # Dynamic LPF settings
    gyro_lpf1_dyn_min_hz = int.from_bytes(payload[index:index + 2], 'little')
    index += 2
    gyro_lpf1_dyn_max_hz = int.from_bytes(payload[index:index + 2], 'little')
    index += 2
    dterm_lpf1_dyn_min_hz = int.from_bytes(payload[index:index + 2], 'little')
    index += 2
    dterm_lpf1_dyn_max_hz = int.from_bytes(payload[index:index + 2], 'little')
    index += 2

    # Dynamic notch filter settings
    index += 2  # Skip deprecated values
    dyn_notch_q = int.from_bytes(payload[index:index + 2], 'little')
    index += 2
    dyn_notch_min_hz = int.from_bytes(payload[index:index + 2], 'little')
    index += 2

    # RPM filter settings
    rpm_filter_harmonics = payload[index]
    index += 1
    rpm_filter_min_hz = payload[index]
    index += 1

    # Additional dynamic notch filter settings
    dyn_notch_max_hz = int.from_bytes(payload[index:index + 2], 'little')
    index += 2

    # Dynamic LPF settings
    dterm_lpf1_dyn_expo = payload[index]
    index += 1

    # Dynamic notch count
    dyn_notch_count = payload[index]

    # Construct the response string excluding reserved values
    response = (f"G LPF1: {gyro_lpf1_static_hz}\n"
                f"D LPF1: {dterm_lpf1_static_hz}\n"
                f"Y LP: {yaw_lowpass_hz}\n"
                f"G N Hz 1: {gyro_soft_notch_hz_1}\n"
                f"G N CO 1: {gyro_soft_notch_cutoff_1}\n"
                f"D N: {dterm_notch_hz}\n"
                f"D N CO: {dterm_notch_cutoff}\n"
                f"G S N Hz 2: {gyro_soft_notch_hz_2}\n"
                f"G S N Cutoff 2: {gyro_soft_notch_cutoff_2}\n"
                f"D LPF1 Type: {dterm_lpf1_type}\n"
                f"G HW LPF: {gyro_hardware_lpf}\n"
                f"G LPF2 S Hz: {gyro_lpf2_static_hz}\n"
                f"G LPF1 Type: {gyro_lpf1_type}\n"
                f"G LPF2 Type: {gyro_lpf2_type}\n"
                f"D LPF2 S Hz: {dterm_lpf2_static_hz}\n"
                f"D LPF2 Type: {dterm_lpf2_type}\n"
                f"G LPF1 Dyn Min: {gyro_lpf1_dyn_min_hz}\n"
                f"G LPF1 Dyn Max: {gyro_lpf1_dyn_max_hz}\n"
                f"D LPF1 Dyn Min: {dterm_lpf1_dyn_min_hz}\n"
                f"D LPF1 Dyn Max: {dterm_lpf1_dyn_max_hz}\n"
                f"Dyn N Q: {dyn_notch_q}\n"
                f"Dyn N Min: {dyn_notch_min_hz}\n"
                f"RPM Harm: {rpm_filter_harmonics}\n"
                f"RPM Min: {rpm_filter_min_hz}\n"
                f"Dyn N Max: {dyn_notch_max_hz}\n"
                f"D LPF1 Dyn Expo: {dterm_lpf1_dyn_expo}\n"
                f"Dyn N Count: {dyn_notch_count}\n")

    return response.strip()  # Remove any trailing whitespace

# ---------------------------
# MSP_MIXER_CONFIG
# ---------------------------
def decode_msp_mixer_config_request(payload: bytes) -> str:
    """
    Decodes the request for mixer configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request Mixer Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_mixer_config_response(payload: bytes) -> str:
    """
    Decodes the response for mixer configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 2:  # At least 2 bytes for mixer mode and yaw motors reversed
        return MSG_INVALID_PAYLOAD

    mixer_mode = payload[0]  # Mixer mode
    yaw_motors_reversed = payload[1]  # Yaw motors reversed

    # Construct the response string
    response = (f"Mixer Mode: {mixer_mode}\n"
                f"Yaw Motors Reversed: {yaw_motors_reversed}\n")

    return response.strip()  # Remove any trailing whitespace

# ---------------------------
# MSP_MODE_RANGES_EXTRA
# ---------------------------
def decode_msp_mode_ranges_extra_request(payload: bytes) -> str:
    """
    Decodes the request for mode ranges extra configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request Mode Ranges Extra Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_mode_ranges_extra_response(payload: bytes) -> str:
    """
    Decodes the response for mode ranges extra configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 1:  # At least 1 byte for the count of activation conditions
        return MSG_INVALID_PAYLOAD

    index = 0
    activation_condition_count = payload[index]  # Number of activation conditions
    index += 1

    response = "Mode: ID/Logic/Linked ID"
    for i in range(activation_condition_count):
        if index + 2 >= len(payload):  # Ensure there are enough bytes left
            return MSG_INVALID_PAYLOAD

        permanent_id = payload[index]  # Permanent ID of the box
        index += 1
        mode_logic = payload[index]  # Mode logic
        index += 1
        linked_permanent_id = payload[index]  # Permanent ID of the linked box
        index += 1

        response += (f", {i + 1}: {permanent_id}/{mode_logic}/{linked_permanent_id}\n")

    return response.strip()  # Remove any trailing whitespace

# ---------------------------
# MSP_OSD_CANVAS
# ---------------------------
def decode_msp_osd_canvas_request(payload: bytes) -> str:
    """
    Decodes the request for OSD canvas configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request OSD Canvas Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_osd_canvas_response(payload: bytes) -> str:
    """
    Decodes the response for OSD canvas configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 2:  # At least 2 bytes for canvas columns and rows
        return MSG_INVALID_PAYLOAD

    canvas_cols = payload[0]  # Number of canvas columns
    canvas_rows = payload[1]  # Number of canvas rows

    # Construct the response string
    response = (f"{canvas_cols} x {canvas_rows}\n")

    return response.strip()  # Remove any trailing whitespace

# ---------------------------
# MSP_OSD_CONFIG
# ---------------------------
def decode_msp_osd_config_request(payload: bytes) -> str:
    """
    Decodes the request for OSD configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request OSD Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_osd_config_response(payload: bytes) -> str:
    """
    Decodes the response for OSD configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 30:  # Minimum expected length based on the parameters
        return MSG_INVALID_PAYLOAD

    index = 0
    osd_flags = payload[index]  # OSD flags
    index += 1

    video_system = payload[index]  # Video system (AUTO/PAL/NTSC/HD)
    index += 1

    units = payload[index]  # OSD units
    index += 1

    rssi_alarm = payload[index]  # RSSI alarm
    index += 1

    cap_alarm = int.from_bytes(payload[index:index + 2], 'little')  # Capacitor alarm
    index += 2

    old_timer_alarm = payload[index]  # Old timer alarm (not used)
    index += 1

    osd_item_count = payload[index]  # OSD item count
    index += 1

    alt_alarm = int.from_bytes(payload[index:index + 2], 'little')  # Altitude alarm
    index += 2

    # Element position and visibility
    item_positions = []
    for i in range(osd_item_count):
        if index + 2 > len(payload):
            return MSG_INVALID_PAYLOAD
        item_positions.append(int.from_bytes(payload[index:index + 2], 'little'))
        index += 2

    # Post flight statistics
    osd_stat_count = payload[index]  # OSD stat count
    index += 1
    osd_stats = []
    for i in range(osd_stat_count):
        if index >= len(payload):
            return MSG_INVALID_PAYLOAD
        osd_stats.append(payload[index])
        index += 1

    # Timers
    osd_timer_count = payload[index]  # OSD timer count
    index += 1
    timers = []
    for i in range(osd_timer_count):
        if index + 2 > len(payload):
            return MSG_INVALID_PAYLOAD
        timers.append(int.from_bytes(payload[index:index + 2], 'little'))
        index += 2

    # Enabled warnings
    enabled_warnings_low = int.from_bytes(payload[index:index + 2], 'little')  # Low word of enabled warnings
    index += 2
    osd_warning_count = payload[index]  # OSD warning count
    index += 1
    enabled_warnings = int.from_bytes(payload[index:index + 4], 'little')  # 32-bit enabled warnings
    index += 4

    # OSD profiles
    if index < len(payload):
        osd_profile_count = payload[index]  # Available profiles
        index += 1
        osd_profile_index = payload[index]  # Selected profile
        index += 1
    else:
        osd_profile_count = 1
        osd_profile_index = 1

    # OSD stick overlay
    overlay_radio_mode = payload[index]  # Overlay radio mode
    index += 1

    # Camera frame element width/height
    camera_frame_width = payload[index]  # Camera frame width
    index += 1
    camera_frame_height = payload[index]  # Camera frame height
    index += 1

    # Link quality alarm
    link_quality_alarm = int.from_bytes(payload[index:index + 2], 'little')  # Link quality alarm
    index += 2

    # RSSI dBm alarm
    rssi_dbm_alarm = int.from_bytes(payload[index:index + 2], 'little')  # RSSI dBm alarm

    # Construct the response string
    response = (f"Flags: {osd_flags}\n"
                f"VS: {video_system}\n"
                f"Units: {units}\n"
                f"RSSI: {rssi_alarm}\n"
                f"Cap: {cap_alarm}\n"
                f"Altitude: {alt_alarm}\n"
                f"Count: {osd_item_count}\n"
                # f"Pos: {item_positions}\n"
                f"Stats: {osd_stat_count}\n"
                #f"Stats: {osd_stats}\n"
                f"Timer Count: {osd_timer_count}\n"
                f"Timers: {timers}\n"
                f"Warn L: {enabled_warnings_low}\n"
                f"Warn Count: {osd_warning_count}\n"
                f"Warn: {enabled_warnings}\n"
                f"Prof Count: {osd_profile_count}\n"
                f"Prof: {osd_profile_index}\n"
                f"Radio: {overlay_radio_mode}\n"
                f"Frame: {camera_frame_width} x {camera_frame_height}\n"
                f"LQ: {link_quality_alarm}\n"
                f"RSSI: {rssi_dbm_alarm}\n")

    return response.strip()  # Remove any trailing whitespace

# ---------------------------
# MSP_SDCARD_SUMMARY
# ---------------------------
def decode_msp_sdcard_summary_request(payload: bytes) -> str:
    """
    Decodes the request for SD card summary.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request SD Card Summary"
    return MSG_INVALID_PAYLOAD

def decode_msp_sdcard_summary_response(payload: bytes) -> str:
    """
    Decodes the response for SD card summary.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 11:  # Minimum expected length based on the parameters
        return MSG_INVALID_PAYLOAD

    index = 0
    flags = payload[index]  # SD card flags
    index += 1
    state = payload[index]  # SD card state
    index += 1
    last_error = payload[index]  # Last error code
    index += 1
    free_space = int.from_bytes(payload[index:index + 4], 'little')  # Free space in bytes
    index += 4
    total_space = int.from_bytes(payload[index:index + 4], 'little')  # Total space in bytes

    # Construct the response string
    response = (f"Flags: {flags}\n"
                f"State: {state}\n"
                f"Last Error: {last_error}\n"
                f"Free: {free_space} bytes\n"
                f"Total: {total_space} bytes\n")

    return response.strip()  # Remove any trailing whitespace

# ---------------------------
# MSP_UID
# ---------------------------
def decode_msp_uid_request(payload: bytes) -> str:
    """
    Decodes the request for UID information.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request UID"
    return MSG_INVALID_PAYLOAD

def decode_msp_uid_response(payload: bytes) -> str:
    """
    Decodes the response for UID information.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 12:  # Minimum expected length for three 32-bit values
        return MSG_INVALID_PAYLOAD

    index = 0
    uid_0 = int.from_bytes(payload[index:index + 4], 'little')  # First UID part
    index += 4
    uid_1 = int.from_bytes(payload[index:index + 4], 'little')  # Second UID part
    index += 4
    uid_2 = int.from_bytes(payload[index:index + 4], 'little')  # Third UID part

    # Construct the response string
    response = (f"UID : {uid_0:08x}.{uid_1:08x}.{uid_2:08x}\n")

    return response.strip()  # Remove any trailing whitespace

# ---------------------------
# MSP_SET_ARMING_DISABLED
# ---------------------------
def decode_msp_set_arming_disabled_request(payload: bytes) -> str:
    """
    Decodes the request to set arming disabled.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 1:
        return MSG_INVALID_PAYLOAD

    command = payload[0]  # Read the command
    disable_runaway_takeoff = 0

    # Check if there is an additional byte for disable runaway takeoff
    if len(payload) > 1:
        disable_runaway_takeoff = payload[1]  # Read the disable runaway takeoff flag

    # Construct the response string
    response = (f"{command == 1}\n"
                f", Disable Runaway Takeoff: {disable_runaway_takeoff == 1}\n")

    return response.strip()  # Remove any trailing whitespace


def decode_msp_set_arming_disabled_response(payload: bytes) -> str:
    """
    Decodes the response for setting arming disabled.

    :param payload: Payload bytes
    :return: Decoded string
    """
    # Assuming the response does not require a payload
    return "Done\n"

# ---------------------------
# MSP_SET_RTC (ID: 121)
# ---------------------------
def decode_msp_set_rtc_request(payload: bytes) -> str:
    """
    Decodes the request to set the RTC (Real-Time Clock).

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 6:  # Minimum length: 4 bytes for seconds + 2 bytes for milliseconds
        return MSG_INVALID_PAYLOAD

    # Read seconds and milliseconds from the payload
    secs = int.from_bytes(payload[0:4], 'little')  # Read 4 bytes for seconds
    millis = int.from_bytes(payload[4:6], 'little')  # Read 2 bytes for milliseconds

    # Construct the response string
    response = (f"Set RTC Request:\n"
                f"Seconds: {secs}\n"
                f"Milliseconds: {millis}\n")

    return response.strip()  # Remove any trailing whitespace


def decode_msp_set_rtc_response(payload: bytes) -> str:
    """
    Decodes the response for setting the RTC.

    :param payload: Payload bytes
    :return: Decoded string
    """
    # Assuming the response does not require a payload
    return "Done"

# ---------------------------
# MSP_ACC_TRIM
# ---------------------------
def decode_msp_acc_trim_request(payload: bytes) -> str:
    """
    Decodes the request for UID information.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request acc trim"
    return MSG_INVALID_PAYLOAD


def decode_msp_acc_trim_response(payload: bytes) -> str:
    """
    Decodes the request to set accelerometer trim values.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 4:  # Minimum length: 2 bytes for pitch + 2 bytes for roll
        return MSG_INVALID_PAYLOAD

    # Read pitch and roll trim values from the payload
    pitch_trim = int.from_bytes(payload[0:2], 'little')  # Read 2 bytes for pitch
    roll_trim = int.from_bytes(payload[2:4], 'little')  # Read 2 bytes for roll

    # Construct the response string
    response = (f"Pitch Trim: {pitch_trim}\n"
                f"Roll Trim: {roll_trim}\n")

    return response.strip()  # Remove any trailing whitespace

# ---------------------------
# MSP_BLACKBOX_CONFIG
# ---------------------------
def decode_msp_blackbox_config_request(payload: bytes) -> str:
    """
    Decodes the request for blackbox configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request Blackbox Configuration"
    return MSG_INVALID_PAYLOAD


def decode_msp_blackbox_config_response(payload: bytes) -> str:
    """
    Decodes the response for blackbox configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) < 10:  # Minimum expected length based on the parameters
        return MSG_INVALID_PAYLOAD

    index = 0
    blackbox_supported = payload[index]  # Blackbox supported (1 byte)
    index += 1
    device = payload[index]  # Blackbox device (1 byte)
    index += 1
    rate_numerator = payload[index]  # Rate numerator (1 byte, not used anymore)
    index += 1
    rate_denominator = payload[index]  # Rate denominator (1 byte)
    index += 1
    p_ratio = int.from_bytes(payload[index:index + 2], 'little')  # P ratio (2 bytes)
    index += 2
    sample_rate = payload[index]  # Sample rate (1 byte)
    index += 1

    # Check for fields disabled mask if present (added in API 1.45)
    fields_disabled_mask = 0
    if len(payload) > index:
        fields_disabled_mask = int.from_bytes(payload[index:index + 4], 'little')  # Fields disabled mask (4 bytes)

    # Construct the response string
    response = (f"Supported: {'Yes' if blackbox_supported == 1 else 'No'}\n"
                f"Device: {device}\n"
                f"Rate: {rate_numerator}/{rate_denominator}\n"
                f"Ratio: {p_ratio}\n"
                f"Sample: {sample_rate}\n"
                f"Field Mask: {fields_disabled_mask:08x}\n")

    return response.strip()  # Remove any trailing whitespace

# ---------------------------
# MSP_SET_OSD_CONFIG
# ---------------------------
def decode_msp_set_osd_config_request(payload: bytes) -> str:
    """
    Decodes the request to set OSD configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request to set OSD configuration."

    addr = payload[0]  # Read the address

    if addr == 0xFF:  # Equivalent to -1 in signed 8-bit
        # Set general OSD settings
        if len(payload) < 2:
            return MSG_INVALID_PAYLOAD

        video_system = payload[1]  # Read video system
        # Additional checks and settings based on video_system would go here...

        # Read other settings
        if len(payload) < 6:
            return MSG_INVALID_PAYLOAD

        units = payload[2]  # Read units
        rssi_alarm = payload[3]  # Read RSSI alarm
        cap_alarm = int.from_bytes(payload[4:6], 'little')  # Read capacitor alarm
        alt_alarm = int.from_bytes(payload[6:8], 'little')  # Read altitude alarm

        # Construct the response string
        response = (f"Video System: {video_system}\n"
                    f"Units: {units}\n"
                    f"RSSI Alarm: {rssi_alarm}\n"
                    f"Cap Alarm: {cap_alarm}\n"
                    f"Alt Alarm: {alt_alarm}\n")

        if len(payload) >= 8:
            enabledWarnings = int.from_bytes(payload[8:10], 'little')  # Low 16 bits
            response += (f"Enabled Warnings: {enabledWarnings:04x}\n")
        if len(payload) >= 12:
            enabledWarnings = int.from_bytes(payload[10:14], 'little')  # 32-bit version
            response += (f"Enabled Warnings: {enabledWarnings:08x}\n")

        # Read selected OSD profile
        profile_index = 0
        if len(payload) >= 13:
            profile_index = payload[12]  # Read selected profile index

        # Read OSD stick overlay mode
        overlay_radio_mode = 0
        if len(payload) >= 14:
            overlay_radio_mode = payload[13]  # Read overlay mode

        # Read camera frame width/height
        camera_frame_width = 0
        camera_frame_height = 0
        if len(payload) >= 16:
            camera_frame_width = payload[14]  # Read camera frame width
            camera_frame_height = payload[15]  # Read camera frame height

        # Read link quality alarm
        link_quality_alarm = 0
        if len(payload) >= 18:
            link_quality_alarm = int.from_bytes(payload[16:18], 'little')  # Read link quality alarm

        # Read RSSI dBm alarm
        rssi_dbm_alarm = 0
        if len(payload) >= 20:
            rssi_dbm_alarm = int.from_bytes(payload[18:20], 'little')  # Read RSSI dBm alarm

        # Here you would set the values to the appropriate configuration structure
        # For example:
        # set_osd_config(units, rssi_alarm, cap_alarm, alt_alarm, enabled_warnings, profile_index, overlay_radio_mode, camera_frame_width, camera_frame_height, link_quality_alarm, rssi_dbm_alarm)

        response += (f"Profile Index: {profile_index}\n"
                    f"Overlay Radio Mode: {overlay_radio_mode}\n"
                    f"Camera Frame Width: {camera_frame_width}\n"
                    f"Camera Frame Height: {camera_frame_height}\n"
                    f"Link Quality Alarm: {link_quality_alarm}\n"
                    f"RSSI dBm Alarm: {rssi_dbm_alarm}\n")

        return response

    elif addr == 0xFE:  # Equivalent to -2 in signed 8-bit
        # Timers
        if len(payload) < 3:
            return MSG_INVALID_PAYLOAD

        index = payload[1]  # Read timer index
        timer_value = int.from_bytes(payload[2:4], 'little')  # Read timer value

        return f"Timer {index} set to {timer_value}"

    else:
        # Handle setting of specific OSD elements or statistics
        if len(payload) < 3:
            return MSG_INVALID_PAYLOAD

        value = int.from_bytes(payload[1:3], 'little')  # Read value
        screen = payload[2] if len(payload) > 2 else 1  # Read screen index

        if screen == 0:
            # Set statistic item enable
            return f"Stat item {addr} enabled {value == 1}"
        else:
            return f"OSD element {addr} updated with value {value:04x}"



def decode_msp_set_osd_config_response(payload: bytes) -> str:
    """
    Decodes the response for setting OSD configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    # Assuming the response does not require a payload
    return "OSD configuration updated successfully."

# ---------------------------
# MSP2_GET_TEXT
# ---------------------------
def decode_msp2_get_text_request(payload: bytes) -> str:
    """
    Decodes the request for text data.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return "Request to get text data."

    # Assuming the payload may contain a specific request type or identifier
    request_type = payload[0] if len(payload) > 0 else None

    return f"Request to get text data with type: {request_type}"


def decode_msp2_get_text_response(payload: bytes) -> str:
    """
    Decodes the response for text data.

    :param payload: Payload bytes
    :return: Decoded string
    """
    if len(payload) == 0:
        return MSG_INVALID_PAYLOAD

    textType = payload[0]
    textLength = payload[1]
    textStr = payload[2:2 + textLength]
    return (f"Type/Length: {textType}/{textLength}\n"
            f"Text: \"{textStr.decode('utf-8')}\"\n")

# ---------------------------
# MSP2_SENSOR_CONFIG_ACTIVE
# ---------------------------

def decode_msp2_sensor_config_active_request(payload: bytes) -> str:
    """
    Decodes the request for active sensor configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    return "Request for active sensor configuration."


def decode_msp2_sensor_config_active_response(payload: bytes) -> str:
    """
    Decodes the response for active sensor configuration.

    :param payload: Payload bytes containing sensor statuses.
    :return: Decoded string indicating the active sensor configuration.
    """
    if len(payload) < 6:  # Expecting at least 6 bytes for the sensors
        return MSG_INVALID_PAYLOAD

    response = ""

    # Read each sensor status from the payload
    for i in range(6):  # Assuming 6 sensors: gyro, acc, baro, mag, rangefinder, optical flow
        sensor_status = payload[i]
        response += f"Sensor {i}: ID {sensor_status}\n"

    return response

# ---------------------------
# MSP_MOTOR
# ---------------------------

def decode_msp_motor_request(payload: bytes) -> str:
    """
    Decodes the request for motor configuration.

    :param payload: Payload bytes
    :return: Decoded string
    """
    return "Request for motor value"


def decode_msp_motor_response(payload: bytes) -> str:
    """
    Decodes the response for motor configuration.

    :param payload: Payload bytes containing motor value.
    :return: Decoded string indicating the motor values.
    """
    if len(payload) < 16:  # Expecting at least 16 bytes for the motors
        return MSG_INVALID_PAYLOAD

    response = ""

    # Read each motor value from the payload
    for i in range(8):
        offset = i * 2
        motor_value = int.from_bytes(payload[offset:offset + 2], 'little')
        response += f"{motor_value}\n"

    return response
# ---------------------------
# MSP_DEBUG
# ---------------------------

def decode_msp_debug_request(payload: bytes) -> str:
    """
    Decodes the request for debug info.

    :param payload: Payload bytes
    :return: Decoded string
    """
    return "Request for debug"


def decode_msp_debug_response(payload: bytes) -> str:
    """
    Decodes the response for debug

    :param payload: Payload bytes containing debug values.
    :return: Decoded string indicating the debug values.
    """
    if len(payload) < 16:  # Expecting at least 16 bytes for the debug
        return MSG_INVALID_PAYLOAD

    response = ""

    # Read each debug value from the payload
    for i in range(8):
        offset = i * 2
        debug_value = int.from_bytes(payload[offset:offset + 2], 'little')
        response += f"{debug_value}\n"

    return response

# ---------------------------
# MSP_VTX_CONFIG
# ---------------------------
def decode_msp_vtx_config_request(payload: bytes) -> str:
    """
    Decodes the request for VTX configuration.

    :param payload: Payload bytes
    :return: Decoded string indicating the request type.
    """
    return "Request to get VTX configuration."


def decode_msp_vtx_config_response(payload: bytes) -> str:
    """
    Decodes the response for VTX configuration.

    :param payload: Payload bytes containing VTX configuration data.
    :return: Decoded string indicating the VTX configuration.
    """
    if len(payload) < 10:  # Minimum expected length based on the provided data structure
        return MSG_INVALID_PAYLOAD

    vtx_type = payload[0]  # Read VTX type
    vtx_band = payload[1]  # Read VTX band
    vtx_channel = payload[2]  # Read VTX channel
    vtx_power = payload[3]  # Read VTX power level
    vtx_pit_mode = payload[4]  # Read VTX pit mode status
    vtx_freq = int.from_bytes(payload[5:7], 'little')  # Read VTX frequency (2 bytes)
    device_is_ready = payload[7]  # Read device ready status
    low_power_disarm = payload[8]  # Read low power disarm status
    pit_mode_freq = int.from_bytes(payload[9:11], 'little')  # Read pit mode frequency (2 bytes)

    # Check for VTX table availability
    if payload[11] == 1:  # Assuming the next byte indicates if the VTX table is available
        vtx_bands = payload[12]  # Read VTX table bands
        vtx_channels = payload[13]  # Read VTX table channels
        vtx_power_levels = payload[14]  # Read VTX table power levels
    else:
        vtx_bands = vtx_channels = vtx_power_levels = 0

    response = (f"Type: {vtx_type}\n"
                f"Band: {vtx_band}\n"
                f"Ch: {vtx_channel}\n"
                f"Pwr: {vtx_power}\n"
                f"Pit: {'Enabled' if vtx_pit_mode else 'Disabled'}\n"
                f"Freq: {vtx_freq} Hz\n"
                f"Rdy: {'Yes' if device_is_ready else 'No'}\n"
                f"LP Dis: {'Enabled' if low_power_disarm else 'Disabled'}\n"
                f"Pit Freq: {pit_mode_freq} Hz\n"
                f"TBnds: {vtx_bands}\n"
                f"Chls: {vtx_channels}\n"
                f"Lvls: {vtx_power_levels}")

    return response

# ---------------------------
# MSP2_GET_VTX_DEVICE_STATUS (ID: 0x3004)
# ---------------------------
MSG_INVALID_PAYLOAD = "Invalid payload length for VTX device status."

def decode_msp2_get_vtx_device_status_request(payload: bytes) -> str:
    """
    Decodes the request for VTX device status.

    :param payload: Payload bytes
    :return: Decoded string indicating the request type.
    """
    return "Request to get VTX device status."


def decode_msp2_get_vtx_device_status_response(payload: bytes) -> str:
    """
    Decodes the response for VTX device status.

    :param payload: Payload bytes containing VTX device status data.
    :return: Decoded string indicating the VTX device status.
    """
    if len(payload) < 12:  # Minimum expected length based on the provided data structure
        return MSG_INVALID_PAYLOAD

    # Extract VTX device status from the payload
    vtx_type = payload[0]  # Read VTX type
    vtx_status = payload[1]  # Read VTX status
    vtx_band = payload[2]  # Read VTX band
    vtx_channel = payload[3]  # Read VTX channel
    vtx_power = payload[4]  # Read VTX power level
    vtx_freq = int.from_bytes(payload[5:7], 'little')  # Read VTX frequency (2 bytes)
    device_is_ready = payload[7]  # Read device ready status
    low_power_disarm = payload[8]  # Read low power disarm status
    pit_mode_freq = int.from_bytes(payload[9:11], 'little')  # Read pit mode frequency (2 bytes)
    band_and_channel_available = payload[11]  # Read band and channel availability

    # Construct the response string
    response = (f"Type: {vtx_type}\n"
                f"Status: {'Active' if vtx_status else 'Inactive'}\n"
                f"Bnd: {vtx_band}\n"
                f"Ch: {vtx_channel}\n"
                f"Pwr: {vtx_power}\n"
                f"Freq: {vtx_freq} Hz\n"
                f"Rdy: {'Yes' if device_is_ready else 'No'}\n"
                f"LP Dis: {'Enabled' if low_power_disarm else 'Disabled'}\n"
                f"Pit F: {pit_mode_freq} Hz\n"
                f"Avail: {'Yes' if band_and_channel_available else 'No'}")

    return response

# ---------------------------
# Default Decoder
# ---------------------------

def decode_msp_default(command_name: str):
    def decoder(payload: bytes) -> str:
        if len(payload) == 0:
            return f"{command_name}"
        try:
            # Try to decode as ASCII first
            text = payload.decode('ascii', 'replace').rstrip('\x00')
            if text:
                return f"{command_name}: {text}"
            # If no text, show as hex
            return f"{command_name}: 0x{payload.hex()}"
        except:
            return f"{command_name}: 0x{payload.hex()}"
    return decoder

# ===========================
# Unified Command Dictionary
# ===========================

# MSP Protocol command definitions
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

MSP_COMMANDS_DICT = {
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
}

MSP_CMD_DICT = {
    MSP_API_VERSION: {
        "decoder_response": decode_msp_api_version_response,
        "decoder_request": decode_msp_api_version_request
    },
    MSP_FC_VARIANT: {
        "decoder_response": decode_msp_fc_variant_response,
        "decoder_request": decode_msp_fc_variant_request
    },
    MSP_FC_VERSION: {
        "decoder_response": decode_msp_fc_version_response,
        "decoder_request": decode_msp_fc_version_request
    },
    MSP_BOARD_INFO: {
        "decoder_response": decode_msp_board_info_response,
        "decoder_request": decode_msp_board_info_request
    },
    MSP_BUILD_INFO: {
        "decoder_response": decode_msp_build_info_response,
        "decoder_request": decode_msp_build_info_request
    },
    MSP_NAME: {
        "decoder_response": decode_msp_name_response,
        "decoder_request": decode_msp_name_request
    },
    MSP_SET_NAME: {
        "decoder_response": decode_msp_set_name_response,
        "decoder_request": decode_msp_set_name_request
    },
    MSP_BATTERY_CONFIG: {
        "decoder_response": decode_msp_battery_config_response,
        "decoder_request": decode_msp_battery_config_request
    },
    MSP_BOARD_ALIGNMENT_CONFIG: {
        "decoder_response": decode_msp_board_alignment_config_response,
        "decoder_request": decode_msp_board_alignment_config_request
    },
    MSP_SONAR_ALTITUDE: {
        "decoder_response": decode_msp_sonar_response,
        "decoder_request": decode_msp_sonar_request
    },
    MSP_PID_CONTROLLER: {
        "decoder_response": decode_msp_pid_controller_response,
        "decoder_request": decode_msp_pid_controller_request
    },
    MSP_REBOOT: {
        "decoder_response": decode_msp_reboot_response,
        "decoder_request": decode_msp_reboot_request
    },
    MSP_DATAFLASH_SUMMARY: {
        "decoder_response": decode_msp_dataflash_summary_response,
        "decoder_request": decode_msp_dataflash_summary_request
    },
    MSP_DATAFLASH_READ: {
        "decoder_response": decode_msp_dataflash_read_response,
        "decoder_request": decode_msp_dataflash_read_request
    },
    MSP_STATUS: {
        "decoder_response": decode_msp_status_response,
        "decoder_request": decode_msp_status_request
    },
    MSP_RAW_IMU: {
        "decoder_response": decode_msp_raw_imu_response,
        "decoder_request": decode_msp_raw_imu_request
    },
    MSP_RC: {
        "decoder_response": decode_msp_rc_response,
        "decoder_request": decode_msp_rc_request
    },
    MSP_ATTITUDE: {
        "decoder_response": decode_msp_attitude_response,
        "decoder_request": decode_msp_attitude_request
    },
    MSP_ALTITUDE: {
        "decoder_response": decode_msp_altitude_response,
        "decoder_request": decode_msp_altitude_request
    },
    MSP_ANALOG: {
        "decoder_response": decode_msp_analog_response,
        "decoder_request": decode_msp_analog_request
    },
    MSP_BOXNAMES: {
        "decoder_response": decode_msp_boxnames_response,
        "decoder_request": decode_msp_boxnames_request
    },
    MSP_BOXIDS: {
        "decoder_response": decode_msp_boxids_response,
        "decoder_request": decode_msp_boxids_request
    },
    MSP_RC_TUNING: {
        "decoder_response": decode_msp_rc_tuning_response,
        "decoder_request": decode_msp_rc_tuning_request
    },
    MSP_PID: {
        "decoder_response": decode_msp_pid_response,
        "decoder_request": decode_msp_pid_request
    },
    MSP_MOTOR_3D_CONFIG: {
        "decoder_response": decode_msp_motor_3d_config_response,
        "decoder_request": decode_msp_motor_3d_config_request
    },
    MSP_LED_STRIP_MODECOLOR: {
        "decoder_response": decode_msp_led_strip_modecolor_response,
        "decoder_request": decode_msp_led_strip_modecolor_request
    },
    MSP_BATTERY_STATE: {
        "decoder_response": decode_msp_battery_state_response,
        "decoder_request": decode_msp_battery_state_request
    },
    MSP_STATUS_EX: {
        "decoder_response": decode_msp_status_ex_response,
        "decoder_request": decode_msp_status_ex_request
    },
    MSP_DISPLAYPORT: {
        "decoder_response": decode_msp_displayport_response,
        "decoder_request": decode_msp_displayport_request
    },
    MSP_BEEPER_CONFIG: {
        "decoder_response": decode_msp_beeper_config_response,
        "decoder_request": decode_msp_beeper_config_request
    },
    MSP_MOTOR_CONFIG: {
        "decoder_response": decode_msp_motor_config_response,
        "decoder_request": decode_msp_motor_config_request
    },
    MSP_VTXTABLE_POWERLEVEL: {
        "decoder_response": decode_msp_vtxtable_powerlevel_response,
        "decoder_request": decode_msp_vtxtable_powerlevel_request
    },
    MSP_MOTOR_TELEMETRY: {
        "decoder_response": decode_msp_motor_telemetry_response,
        "decoder_request": decode_msp_motor_telemetry_request
    },
    MSP_ARMING_CONFIG: {
        "decoder_response": decode_msp_arming_config_response,
        "decoder_request": decode_msp_arming_config_request
    },
    MSP_RC_DEADBAND: {
        "decoder_response": decode_msp_rc_deadband_response,
        "decoder_request": decode_msp_rc_deadband_request
    },
    MSP_SENSOR_CONFIG: {
        "decoder_response": decode_msp_sensor_config_response,
        "decoder_request": decode_msp_sensor_config_request
    },
    MSP_ADVANCED_CONFIG: {
        "decoder_response": decode_msp_advanced_config_response,
        "decoder_request": decode_msp_advanced_config_request
    },
    MSP_VOLTAGE_METERS: {
        "decoder_response": decode_msp_voltage_meters_response,
        "decoder_request": decode_msp_voltage_meters_request
    },
    MSP_CURRENT_METERS: {
        "decoder_response": decode_msp_current_meters_response,
        "decoder_request": decode_msp_current_meters_request
    },
    MSP_CURRENT_METER_CONFIG: {
        "decoder_response": decode_msp_current_meter_config_response,
        "decoder_request": decode_msp_current_meter_config_request
    },
    MSP_VOLTAGE_METER_CONFIG: {
        "decoder_response": decode_msp_voltage_meter_config_response,
        "decoder_request": decode_msp_voltage_meter_config_request
    },
    MSP_RX_CONFIG: {
        "decoder_response": decode_msp_rx_config_response,
        "decoder_request": decode_msp_rx_config_request
    },
    MSP_FAILSAFE_CONFIG: {
        "decoder_response": decode_msp_failsafe_config_response,
        "decoder_request": decode_msp_failsafe_config_request
    },
    MSP_RXFAIL_CONFIG: {
        "decoder_response": decode_msp_rxfail_config_response,
        "decoder_request": decode_msp_rxfail_config_request
    },
    MSP_GPS_RESCUE: {
        "decoder_response": decode_msp_gps_rescue_response,
        "decoder_request": decode_msp_gps_rescue_request
    },
    MSP_RSSI_CONFIG: {
        "decoder_response": decode_msp_rssi_config_response,
        "decoder_request": decode_msp_rssi_config_request
    },
    MSP_FEATURE_CONFIG: {
        "decoder_response": decode_msp_feature_config_response,
        "decoder_request": decode_msp_feature_config_request
    },
    MSP_MOTOR_CONFIG: {
        "decoder_response": decode_msp_motor_config_response,
        "decoder_request": decode_msp_motor_config_request
    },
    MSP_PID_CONTROLLER: {
        "decoder_response": decode_msp_pid_controller_response,
        "decoder_request": decode_msp_pid_controller_request
    },
    MSP_PID: {
        "decoder_response": decode_msp_pid_response,
        "decoder_request": decode_msp_pid_request
    },
    MSP_PID_ADVANCED: {
        "decoder_response": decode_msp_pid_advanced_response,
        "decoder_request": decode_msp_pid_advanced_request
    },
    MSP_FILTER_CONFIG: {
        "decoder_response": decode_msp_filter_config_response,
        "decoder_request": decode_msp_filter_config_request
    },
    MSP_MIXER_CONFIG: {
        "decoder_response": decode_msp_mixer_config_response,
        "decoder_request": decode_msp_mixer_config_request
    },
    MSP_MODE_RANGES_EXTRA: {
        "decoder_response": decode_msp_mode_ranges_extra_response,
        "decoder_request": decode_msp_mode_ranges_extra_request
    },
    MSP_OSD_CANVAS: {
        "decoder_response": decode_msp_osd_canvas_response,
        "decoder_request": decode_msp_osd_canvas_request
    },
    MSP_SET_OSD_CANVAS: { # Use the same decoder as MSP_OSD_CANVAS
        "decoder_response": decode_msp_osd_canvas_response,
        "decoder_request": decode_msp_osd_canvas_request
    },
    MSP_OSD_CONFIG: {
        "decoder_response": decode_msp_osd_config_response,
        "decoder_request": decode_msp_osd_config_request
    },
    MSP_SDCARD_SUMMARY: {
        "decoder_response": decode_msp_sdcard_summary_response,
        "decoder_request": decode_msp_sdcard_summary_request
    },
    MSP_UID: {
        "decoder_response": decode_msp_uid_response,
        "decoder_request": decode_msp_uid_request
    },
    MSP_SET_ARMING_DISABLED: {
        "decoder_response": decode_msp_set_arming_disabled_response,
        "decoder_request": decode_msp_set_arming_disabled_request
    },
    MSP_SET_RTC: {
        "decoder_response": decode_msp_set_rtc_response,
        "decoder_request": decode_msp_set_rtc_request
    },
    MSP_ACC_TRIM: {
        "decoder_response": decode_msp_acc_trim_response,
        "decoder_request": decode_msp_acc_trim_request
    },
    MSP_BLACKBOX_CONFIG: {
        "decoder_response": decode_msp_blackbox_config_response,
        "decoder_request": decode_msp_blackbox_config_request
    },
    MSP_SET_OSD_CONFIG: {
        "decoder_response": decode_msp_set_osd_config_response,
        "decoder_request": decode_msp_set_osd_config_request
    },
    MSP2_GET_TEXT: {
        "decoder_response": decode_msp2_get_text_response,
        "decoder_request": decode_msp2_get_text_request
    },
    MSP2_SENSOR_CONFIG_ACTIVE: {
        "decoder_response": decode_msp2_sensor_config_active_response,
        "decoder_request": decode_msp2_sensor_config_active_request
    },
    MSP_MOTOR: {
        "decoder_response": decode_msp_motor_response,
        "decoder_request": decode_msp_motor_request
    },
    MSP_DEBUG: {
        "decoder_response": decode_msp_debug_response,
        "decoder_request": decode_msp_debug_request
    },
    MSP_VTX_CONFIG: {
        "decoder_response": decode_msp_vtx_config_response,
        "decoder_request": decode_msp_vtx_config_request
    },
    MSP2_GET_VTX_DEVICE_STATUS: {
        "decoder_response": decode_msp2_get_vtx_device_status_response,
        "decoder_request": decode_msp2_get_vtx_device_status_request
    },
}
# ===========================
# Payload Decoding Function
# ===========================

def decode_msp_payload(cmd: int, payload: bytes, direction: str) -> str:
    """
    Decodes the MSP payload based on command and direction.

    :param cmd: Command
    :param payload: Payload bytes
    :param direction: "response" or "request"
    :return: Decoded string
    """
    cmd_name = MSP_COMMANDS_DICT.get(cmd, "Unknown Command")
    cmd_info = MSP_CMD_DICT.get(cmd)

    if cmd_info is None:
        # Call the default handler if the command is not found
        return decode_msp_default(cmd_name)(payload)
    
    # Select the appropriate decoder based on direction
    if direction == "response":
        decode_func = cmd_info.get("decoder_response", decode_no_fields)
    else:
        decode_func = cmd_info.get("decoder_request", decode_no_fields)

    decoded_payload = decode_func(payload)
    return f"{cmd_name}: {decoded_payload}"

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
        'msp_frame': {'format': '{{data.info}}'},
        'msp_error': {'format': '{{data.error}}'}
    }

    def __init__(self):
        self.buffer = bytearray()
        self.start_time = None
        self.HEADERS = [b"$M<", b"$M>", b"$X<", b"$X>"]  # request and response headers

    def decode(self, frame: AnalyzerFrame):
        if frame.type != 'data':
            return None
        byte_val = frame.data['data'][0]
        if self.start_time is None:
            self.start_time = frame.start_time
        self.buffer.append(byte_val)
        results = []
        while True:
            if len(self.buffer) < 6:
                break
            # Find the earliest occurrence of any header
            header_positions = [self.buffer.find(h) for h in self.HEADERS]
            header_positions = [pos for pos in header_positions if pos != -1]
            if not header_positions:
                # No headers found, first discard character
                del self.buffer[:1]
                self.start_time = None
                break
            header_index = min(header_positions)
            if header_index > 0:
                # Discard bytes before the header
                del self.buffer[:header_index]

            if self.buffer[1] == ord('X'): # MSP2
                if len(self.buffer) < 8:
                    break
                found_header = self.buffer[:3]
                p_size = int.from_bytes(self.buffer[6:8], 'little')
                needed_len = 9 + p_size  # 3(header)+5(v2 header)+p_size+1(v2 chksum)
                if len(self.buffer) < needed_len:
                    break
                msp2_msg = self.buffer[3:8 + p_size]
                cmd = int.from_bytes(self.buffer[4:6], 'little')
                payload = self.buffer[8:8 + p_size]
                calc_sum = crc8_bf(msp2_msg)
                chksum = self.buffer[8 + p_size]
            else:
                if len(self.buffer) < 6:
                    break
                found_header = self.buffer[:3]
                p_size = self.buffer[3]
                needed_len = 6 + p_size  # 3(header)+1(size)+1(cmd)+p_size +1(chksum)
                if len(self.buffer) < needed_len:
                    break
                cmd = self.buffer[4]
                if cmd == MSP_V2_FRAME:
                    if len(self.buffer) < 11:
                        break
                    found_header = self.buffer[:3]
                    p_size = int.from_bytes(self.buffer[9:11], 'little')
                    needed_len = 3 + 9 + p_size  # 3(header)+1(size)+1(cmd)+5(v2 header)+p_size+1(v2 chksum)+1(v1 chksum)
                    if len(self.buffer) < needed_len:
                        break
                    msp2_msg = self.buffer[5:10 + p_size]
                    cmd = int.from_bytes(self.buffer[4:6], 'little')
                    payload = self.buffer[10+10 + p_size]
                    calc_sum = crc8_bf(msp2_msg)
                    chksum = self.buffer[10 + p_size]
                else:
                    payload = self.buffer[5:5 + p_size]
                    chksum = self.buffer[5 + p_size]
                    calc_sum = p_size ^ cmd
                    for bb in payload:
                        calc_sum ^= bb
                    calc_sum &= 0xFF

            direction = "response" if found_header[2] == ord('>') else "request"
            cmd_name = MSP_COMMANDS_DICT.get(cmd, "Unknown Command" + str(self.buffer[:2]))
            if (calc_sum == chksum) or (p_size == 255):
                decoded_info = decode_msp_payload(cmd, payload, direction)
                results.append(AnalyzerFrame(
                    'msp_frame',
                    self.start_time,
                    frame.end_time,
                    {"info": decoded_info, "cmd": cmd_name, "direction": direction}
                ))
            else:
                error_str = (f"{direction} {cmd_name} CRC Error: expected=0x{calc_sum:02X}, "
                            f"got=0x{chksum:02X}, size={p_size}")
                results.append(AnalyzerFrame(
                    'msp_error',
                    self.start_time,
                    frame.end_time,
                    {"error": error_str}
                ))
            del self.buffer[:needed_len]
            if len(self.buffer) == 0:
                self.start_time = None
            else:
                self.start_time = frame.end_time

        return results
