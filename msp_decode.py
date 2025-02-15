"""
This file contains decoder functions for MSP (MultiWii Serial Protocol) commands.
"""

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
    if len(payload) < 20:
        return MSG_INVALID_PAYLOAD

    index = 0
    board_id = payload[index:index+4].decode('ascii', 'replace').strip('\x00')
    index += 4
    
    hw_revision = int.from_bytes(payload[index:index+2], 'little')
    index += 2

    fc_type = payload[index]
    index += 1

    capabilities = payload[index]
    index += 1

    target_name_len = payload[index]
    index += 1
    target_name = payload[index:index+target_name_len].decode('ascii', 'replace').strip('\x00')
    index += target_name_len

    board_name_len = payload[index]
    index += 1
    board_name = payload[index:index+board_name_len].decode('ascii', 'replace').strip('\x00')
    index += board_name_len

    manufacturer_id_len = payload[index]
    index += 1
    manufacturer_id = payload[index:index+manufacturer_id_len].decode('ascii', 'replace').strip('\x00')
    index += manufacturer_id_len

    signature_len = 32
    signature = payload[index:index+signature_len].hex()
    index += signature_len

    mcu_type = payload[index]
    index += 1

    config_state = payload[index]

    # Decode capabilities
    cap_list = []
    if capabilities & (1 << 0): cap_list.append("DYNBAL")
    if capabilities & (1 << 1): cap_list.append("FLAPS")
    if capabilities & (1 << 2): cap_list.append("NAV")
    if capabilities & (1 << 3): cap_list.append("SERVO_TILT")
    if capabilities & (1 << 4): cap_list.append("SOFTSERIAL")
    if capabilities & (1 << 5): cap_list.append("GPU")
    if capabilities & (1 << 6): cap_list.append("UNWIRED_MAG")
    if capabilities & (1 << 7): cap_list.append("CUSTOM")
    
    # Decode MCU types
    mcu_types = {
        0: "SIMULATOR",
        1: "F103",
        2: "F303",
        3: "F40X",
        4: "F411",
        5: "F446",
        6: "F722",
        7: "F745",
        8: "F746",
        9: "F765",
        10: "H750",
        11: "H743_REV_UNKNOWN",
        12: "H743_REV_Y",
        13: "H743_REV_X",
        14: "H743_REV_V",
        15: "H7A3",
        16: "H723_725",
        17: "G474",
        18: "L431",
        19: "L432",
        20: "L433",
        21: "G491"
    }
    
    return (f"Board Information:\n"
            f"  ID: {board_id}\n"
            f"  Hardware Rev: {hw_revision}\n"
            f"  FC Type: {fc_type}\n"
            f"  Capabilities: {', '.join(cap_list)}\n"
            f"  Target: {target_name}\n"
            f"  Board: {board_name}\n"
            f"  Manufacturer: {manufacturer_id}\n"
            f"  MCU: {mcu_types.get(mcu_type, f'Unknown ({mcu_type})')}\n"
            f"  Config State: 0x{config_state:02X}\n"
            f"  Signature: {signature}")

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
    if len(payload) < 28:
        return MSG_INVALID_PAYLOAD

    date_len = 11  # "MMM DD YYYY"
    time_len = 8   # "HH:MM:SS"
    rev_len = 7    # Git short hash
    
    build_date = payload[0:date_len].decode('ascii', 'replace').strip('\x00')
    build_time = payload[date_len:date_len+time_len].decode('ascii', 'replace').strip('\x00')
    git_short = payload[date_len+time_len:date_len+time_len+rev_len].decode('ascii', 'replace').strip('\x00')
    
    # Additional build flags if present
    build_flags = None
    if len(payload) > date_len + time_len + rev_len:
        build_flags = payload[date_len + time_len + rev_len]
        
    response = (f"Build Information:\n"
                f"  Date: {build_date}\n"
                f"  Time: {build_time}\n"
                f"  Git Revision: {git_short}")
    
    if build_flags is not None:
        flag_list = []
        if build_flags & (1 << 0): flag_list.append("CLEAN_BUILD")
        if build_flags & (1 << 1): flag_list.append("DEVELOPMENT")
        if build_flags & (1 << 2): flag_list.append("CUSTOM_DEFAULTS")
        if flag_list:
            response += f"\n  Flags: {', '.join(flag_list)}"
    
    return response

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
    if len(payload) == 0:
        return "Request Board Alignment Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_board_alignment_config_response(payload: bytes) -> str:
    """
    Decodes the response for board alignment configuration.
    """
    if len(payload) < 6:  # 3 x uint16_t
        return MSG_INVALID_PAYLOAD

    roll = int.from_bytes(payload[0:2], 'little')  # Roll degrees
    pitch = int.from_bytes(payload[2:4], 'little')  # Pitch degrees
    yaw = int.from_bytes(payload[4:6], 'little')  # Yaw degrees

    return f"Board Alignment: Roll={roll}°, Pitch={pitch}°, Yaw={yaw}°"

# ---------------------------
# MSP_RC_TUNING
# ---------------------------
def decode_msp_rc_tuning_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for RC Tuning Data"
    return MSG_INVALID_PAYLOAD

def decode_msp_rc_tuning_response(payload: bytes) -> str:
    if len(payload) >= 14:
        rc_rate = payload[0]
        rc_expo = payload[1]
        roll_pitch_rate = int.from_bytes(payload[2:4], 'little')
        yaw_rate = int.from_bytes(payload[4:6], 'little')
        dynamic_thr_pid = payload[6]
        throttle_mid = payload[7]
        throttle_expo = payload[8]
        tpa_breakpoint = int.from_bytes(payload[9:11], 'little')
        rc_yaw_expo = payload[11]
        throttle_limit_type = payload[12]
        throttle_limit_percent = payload[13]
        return (f"RC Rate: {rc_rate/100.0}\n"
                f"RC Expo: {rc_expo/100.0}\n"
                f"Roll/Pitch Rate: {roll_pitch_rate/100.0}\n"
                f"Yaw Rate: {yaw_rate/100.0}\n"
                f"Dynamic Throttle PID: {dynamic_thr_pid/100.0}\n"
                f"Throttle Mid: {throttle_mid/100.0}\n"
                f"Throttle Expo: {throttle_expo/100.0}\n"
                f"TPA Breakpoint: {tpa_breakpoint}\n"
                f"RC Yaw Expo: {rc_yaw_expo/100.0}\n"
                f"Throttle Limit Type: {throttle_limit_type}\n"
                f"Throttle Limit: {throttle_limit_percent}%")
        return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP_ANALOG
# ---------------------------
def decode_msp_analog_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for Analog Data"
    return MSG_INVALID_PAYLOAD

def decode_msp_analog_response(payload: bytes) -> str:
    if len(payload) >= 7:
        battery_voltage = payload[0] / 10.0
        mah_drawn = int.from_bytes(payload[1:3], 'little')
        rssi = payload[3]
        amperage = int.from_bytes(payload[4:6], 'little')
        voltage = int.from_bytes(payload[6:8], 'little') / 100.0 if len(payload) >= 8 else 0
        return (f"Battery: {battery_voltage}V\n"
                f"Current: {amperage/100.0}A\n"
                f"Power Used: {mah_drawn}mAh\n"
                f"RSSI: {rssi}%\n"
                f"Voltage: {voltage}V")
        return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP_LED_STRIP_MODECOLOR
# ---------------------------
def decode_msp_led_strip_modecolor_request(payload: bytes) -> str:
    # This is a request-only command that expects no payload
    if len(payload) == 0:
        return "Request LED Strip Mode Colors"
    return f"Request LED Strip Mode Colors (unexpected payload: {[hex(b) for b in payload]})"

def decode_msp_led_strip_modecolor_response(payload: bytes) -> str:
    """
    Decodes the LED strip mode color configuration.
    """
    if len(payload) < 3:  # Need at least one complete entry
        return MSG_INVALID_PAYLOAD

    # Mode names
    mode_names = {
        0: "ORIENTATION",
        1: "HEADFREE",
        2: "HORIZON",
        3: "ANGLE",
        4: "MAG",
        5: "BARO"
    }

    # Direction names
    direction_names = {
        0: "NORTH",
        1: "EAST",
        2: "SOUTH",
        3: "WEST",
        4: "UP",
        5: "DOWN"
    }

    # Color names
    color_names = {
        0: "BLACK",
        1: "WHITE",
        2: "RED",
        3: "ORANGE",
        4: "YELLOW",
        5: "LIME_GREEN",
        6: "GREEN",
        7: "MINT_GREEN",
        8: "CYAN",
        9: "LIGHT_BLUE",
        10: "BLUE",
        11: "DARK_VIOLET",
        12: "MAGENTA",
        13: "DEEP_PINK"
    }

    # Special color names
    special_names = {
        0: "DISARMED",
        1: "ARMED",
        2: "ANIMATION",
        3: "BACKGROUND",
        4: "BLINK_BACKGROUND",
        5: "GPS_NO_SATS",
        6: "GPS_NO_LOCK",
        7: "GPS_LOCKED"
    }

    result = []
    index = 0

    # Process mode/direction colors
    result.append("Mode/Direction Colors:")
    LED_MODE_COUNT = 6
    LED_DIRECTION_COUNT = 6
    for mode in range(LED_MODE_COUNT):
        for direction in range(LED_DIRECTION_COUNT):
            if index + 2 >= len(payload):
                break
            mode_idx = payload[index]
            dir_idx = payload[index + 1]
            color = payload[index + 2]
            
            mode_name = mode_names.get(mode_idx, f"MODE_{mode_idx}")
            dir_name = direction_names.get(dir_idx, f"DIR_{dir_idx}")
            color_name = color_names.get(color, f"COLOR_{color}")
            
            result.append(f"  {mode_name}/{dir_name}: {color_name}")
            index += 3

    # Process special colors
    result.append("\nSpecial Colors:")
    LED_SPECIAL_COLOR_COUNT = 8
    for special in range(LED_SPECIAL_COLOR_COUNT):
        if index + 2 >= len(payload):
            break
        mode = payload[index]
        special_idx = payload[index + 1]
        color = payload[index + 2]

        if mode != LED_MODE_COUNT:  # Should always be LED_MODE_COUNT (6)
            break

        special_name = special_names.get(special_idx, f"SPECIAL_{special_idx}")
        color_name = color_names.get(color, f"COLOR_{color}")
        
        result.append(f"  {special_name}: {color_name}")
        index += 3

    # Process AUX channel
    if index + 2 < len(payload):
        aux_mode = payload[index]
        zero = payload[index + 1]
        aux_channel = payload[index + 2]
        result.append(f"\nAUX Channel: {aux_channel}")

    return "\n".join(result)

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
    """
    Decodes the VTX configuration response.
    
    Payload format from betaflight/src/main/io/vtx.h:
    uint8_t device_type;      // VTX type
    uint8_t band;            // Band (1-5)
    uint8_t channel;         // Channel (1-8)
    uint8_t power;          // Power level
    uint8_t pit_mode;       // Pit mode active
    uint16_t frequency;     // Frequency in MHz
    uint8_t device_ready;   // Device is ready
    uint8_t low_power_disarm; // Low power disarm active
    uint16_t pit_mode_frequency; // Pit mode frequency
    uint8_t table_size;     // Number of power levels
    uint8_t table_bands;    // Number of bands
    """
    if len(payload) < 13:
        return MSG_INVALID_PAYLOAD

    device_type = payload[0]
    band = payload[1]
    channel = payload[2]
    power = payload[3]
    pit_mode = payload[4]
    frequency = int.from_bytes(payload[5:7], 'little')
    device_ready = payload[7]
    low_power_disarm = payload[8]
    pit_mode_freq = int.from_bytes(payload[9:11], 'little')
    table_size = payload[11]
    table_bands = payload[12]

    # Device type names
    device_types = {
        0: "NONE",
        1: "RTC6705",
        2: "SA",  # SmartAudio
        3: "TRAMP",
        4: "MSP"
    }
    device_str = device_types.get(device_type, f"UNKNOWN ({device_type})")

    return (f"VTX Config: Device: {device_str}, "
            f"Band: {band}, "
            f"Channel: {channel}, "
            f"Power Level: {power}, "
            f"Pit Mode: {'Active' if pit_mode else 'Inactive'}, "
            f"Frequency: {frequency}MHz, "
            f"Device Ready: {'Yes' if device_ready else 'No'}, "
            f"Low Power on Disarm: {'Yes' if low_power_disarm else 'No'}, "
            f"Pit Mode Frequency: {pit_mode_freq}MHz, "
            f"Power Levels: {table_size}, "
            f"Bands: {table_bands}")

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
        return "Request for Sonar Data"
    return MSG_INVALID_PAYLOAD

def decode_msp_sonar_response(payload: bytes) -> str:
    if len(payload) >= 4:
        distance = int.from_bytes(payload[0:2], 'little')
        quality = int.from_bytes(payload[2:4], 'little')
        return f"Distance: {distance}cm, Quality: {quality}"
        return MSG_INVALID_PAYLOAD

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
    """
    Decodes the dataflash summary response.
    
    Payload format from Betaflight:
    uint8_t  flags;                 // MSP_FLASHFS_FLAG_READY | MSP_FLASHFS_FLAG_SUPPORTED
    uint32_t sectors;               // Number of 128KB sectors
    uint32_t totalSize;            // Total size in bytes
    uint32_t usedSize;             // Used size in bytes
    """
    if len(payload) < 13:  # 1 byte flags + 3x 4-byte values
        return MSG_INVALID_PAYLOAD

    flags = payload[0]
    total_size = int.from_bytes(payload[5:9], 'little')  # Total size in bytes
    used_size = int.from_bytes(payload[9:13], 'little')  # Used size in bytes

    # Format sizes in a human-readable way
    def format_size(size_bytes):
        if size_bytes >= 1024*1024:
            return f"{size_bytes/(1024*1024):.0f}M"
        elif size_bytes >= 1024:
            return f"{size_bytes/1024:.0f}K"
        else:
            return f"{size_bytes} bytes"

    # Decode flags
    flag_list = []
    if flags & 0x01:  # MSP_FLASHFS_FLAG_SUPPORTED
        flag_list.append("Supported")
    if flags & 0x02:  # MSP_FLASHFS_FLAG_READY
        flag_list.append("Ready")

    return f"Dataflash Summary: {', '.join(flag_list)}, Total Size: {format_size(total_size)}, Used Size: {format_size(used_size)}"

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
    """
    Decodes the MSP_STATUS response.
    
    Payload format:
    uint16 cycle_time              // Cycle time in microseconds
    uint16 i2c_errors             // I2C errors count
    uint16 sensors                // Active sensors
    uint32 flight_mode_flags      // Flight mode flags
    uint8  current_pid_profile    // Current PID profile index
    uint16 avg_system_load       // Average system load (percentage * 10)
    uint16 gps_mode_flags        // GPS mode flags (removed in newer versions)
    uint8  current_rate_profile  // Current rate profile index
    uint8  arming_disable_flags_count  // Count of arming disable flags
    uint32 arming_disable_flags  // Arming disable flags
    """
    if len(payload) < 15:  # Minimum length for essential fields
        return MSG_INVALID_PAYLOAD

    index = 0
    cycle_time = int.from_bytes(payload[index:index + 2], 'little')
    index += 2
    i2c_errors = int.from_bytes(payload[index:index + 2], 'little')
    index += 2
    sensors = int.from_bytes(payload[index:index + 2], 'little')
    index += 2
    flight_mode_flags = int.from_bytes(payload[index:index + 4], 'little')
    index += 4
    current_pid_profile = payload[index]
    index += 1
    avg_system_load = int.from_bytes(payload[index:index + 2], 'little')
    index += 2
    current_rate_profile = payload[index] if index < len(payload) else 0
    index += 1

    # Decode sensors
    active_sensors = []
    if sensors & (1 << 0): active_sensors.append("ACC")
    if sensors & (1 << 1): active_sensors.append("BARO")
    if sensors & (1 << 2): active_sensors.append("MAG")
    if sensors & (1 << 3): active_sensors.append("GPS")
    if sensors & (1 << 4): active_sensors.append("SONAR")
    if sensors & (1 << 5): active_sensors.append("GYRO")
    if sensors & (1 << 6): active_sensors.append("PITOT")
    if sensors & (1 << 7): active_sensors.append("RANGEMETER")
    if sensors & (1 << 8): active_sensors.append("COMPASS")
    if sensors & (1 << 9): active_sensors.append("OPFLOW")

    # Decode flight mode flags
    modes = []
    if flight_mode_flags & (1 << 0): modes.append("ARM")
    if flight_mode_flags & (1 << 1): modes.append("ANGLE")
    if flight_mode_flags & (1 << 2): modes.append("HORIZON")
    if flight_mode_flags & (1 << 3): modes.append("NAV ALTHOLD")
    if flight_mode_flags & (1 << 4): modes.append("NAV RTH")
    if flight_mode_flags & (1 << 5): modes.append("NAV POSHOLD")
    if flight_mode_flags & (1 << 6): modes.append("HEADFREE")
    if flight_mode_flags & (1 << 7): modes.append("HEADADJ")
    if flight_mode_flags & (1 << 8): modes.append("CAMSTAB")
    if flight_mode_flags & (1 << 9): modes.append("NAV CRUISE")
    if flight_mode_flags & (1 << 10): modes.append("AUTOTUNE")
    if flight_mode_flags & (1 << 11): modes.append("NAV WP")
    if flight_mode_flags & (1 << 12): modes.append("MANUAL")
    if flight_mode_flags & (1 << 13): modes.append("BEEPER")
    if flight_mode_flags & (1 << 14): modes.append("OSD")
    if flight_mode_flags & (1 << 15): modes.append("TELEMETRY")
    if flight_mode_flags & (1 << 16): modes.append("GTUNE")
    if flight_mode_flags & (1 << 17): modes.append("SONAR")
    if flight_mode_flags & (1 << 18): modes.append("SERVO1")
    if flight_mode_flags & (1 << 19): modes.append("SERVO2")
    if flight_mode_flags & (1 << 20): modes.append("SERVO3")
    if flight_mode_flags & (1 << 21): modes.append("BLACKBOX")
    if flight_mode_flags & (1 << 22): modes.append("FAILSAFE")
    if flight_mode_flags & (1 << 23): modes.append("AIRMODE")
    if flight_mode_flags & (1 << 24): modes.append("3D")
    if flight_mode_flags & (1 << 25): modes.append("FPV ANGLE MIX")
    if flight_mode_flags & (1 << 26): modes.append("BLACKBOX ERR")
    if flight_mode_flags & (1 << 27): modes.append("CAMERA1")
    if flight_mode_flags & (1 << 28): modes.append("CAMERA2")
    if flight_mode_flags & (1 << 29): modes.append("CAMERA3")
    if flight_mode_flags & (1 << 30): modes.append("OSD DISABLED")
    if flight_mode_flags & (1 << 31): modes.append("VTXPID")

    # Check for arming disable flags if available
    arming_disable_flags = None
    arming_disable_flags_count = None
    if index + 5 <= len(payload):  # We have arming disable flags
        arming_disable_flags_count = payload[index]
        index += 1
        arming_disable_flags = int.from_bytes(payload[index:index + 4], 'little')

    response = (f"Cycle Time: {cycle_time}µs\n"
                f"I2C Errors: {i2c_errors}\n"
                f"Sensors: {', '.join(active_sensors)}\n"
                f"Flight Modes: {', '.join(modes)}\n"
                f"PID Profile: {current_pid_profile}\n"
                f"Rate Profile: {current_rate_profile}\n"
                f"System Load: {avg_system_load/10}%")

    if arming_disable_flags is not None:
        response += f"\nArming Disabled: {arming_disable_flags_count} flags set ({arming_disable_flags:08x})"

    return response

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
    if len(payload) == 0:
        return "Request for RC Channel Values"
    return MSG_INVALID_PAYLOAD

def decode_msp_rc_response(payload: bytes) -> str:
    if len(payload) >= 16:  # 8 channels * 2 bytes each
        channels = []
        for i in range(0, min(len(payload), 16), 2):
            channel_value = int.from_bytes(payload[i:i+2], 'little')
            channels.append(f"Channel {i//2 + 1}: {channel_value}")
        return "\n".join(channels)
        return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP_ATTITUDE
# ---------------------------
def decode_msp_attitude_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for Attitude Data"
    return MSG_INVALID_PAYLOAD

def decode_msp_attitude_response(payload: bytes) -> str:
    if len(payload) >= 6:
        roll = int.from_bytes(payload[0:2], 'little', signed=True) / 10.0
        pitch = int.from_bytes(payload[2:4], 'little', signed=True) / 10.0
        yaw = int.from_bytes(payload[4:6], 'little', signed=True)
        return f"Roll: {roll}°, Pitch: {pitch}°, Yaw: {yaw}°"
        return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP_ALTITUDE
# ---------------------------
def decode_msp_altitude_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for Altitude Data"
    return MSG_INVALID_PAYLOAD

def decode_msp_altitude_response(payload: bytes) -> str:
    if len(payload) >= 6:
        altitude = int.from_bytes(payload[0:4], 'little', signed=True)
        vario = int.from_bytes(payload[4:6], 'little', signed=True)
        return f"Altitude: {altitude/100.0}m, Vario: {vario}cm/s"
        return MSG_INVALID_PAYLOAD

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
    The payload is a semicolon-separated ASCII string containing box names.
    Each box name is terminated by a semicolon, including the last one.
    The payload continues until the next MSP header ($M or $X).
    """
    try:
        # Convert bytes to ASCII string
        text = payload.decode('ascii', 'replace')
        
        # Split on semicolons and filter out empty strings
        box_names = [name for name in text.split(';') if name]
        
        if not box_names:
            return "No box names found"
            
        return f"Box Names Count: {len(box_names)}"
        
    except Exception as e:
        # If decoding fails, show raw payload
        return f"Failed to decode box names: {payload.hex()}"

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

    box_ids = []
    for i in range(len(payload)):
        box_id = payload[i]
        box_ids.append(f"{box_id}")

    return ", ".join(box_ids)

# ---------------------------
# MSP_SET_LED_STRIP_CONFIG
# ---------------------------
def decode_msp_set_led_strip_config_request(payload):
    """Decode MSP_SET_LED_STRIP_CONFIG request."""
    if len(payload) < 5:
        return MSG_INVALID_PAYLOAD

    # LED strip configuration is a 32-bit value with the following structure:
    # - Position (bits 0-7): LED position (X,Y coordinates)
    # - Function (bits 8-11): Base function (4 bits)
    # - Overlay (bits 12-21): Overlay functions (10 bits)
    # - Color (bits 22-25): Color index (4 bits)
    # - Direction (bits 26-31): Direction flags (6 bits)

    led_index = payload[0]
    mask = (payload[4] << 24) | (payload[3] << 16) | (payload[2] << 8) | payload[1]

    # Extract each component from the mask
    position = mask & 0xFF
    function = (mask >> 8) & 0x0F
    overlay = (mask >> 12) & 0x3FF
    color = (mask >> 22) & 0x0F
    direction = (mask >> 26) & 0x3F

    # Position is split into X and Y coordinates
    x = (position >> 4) & 0x0F
    y = position & 0x0F

    # Base function names
    function_names = [
        "COLOR", "FLIGHT_MODE", "ARM_STATE", "BATTERY",
        "RSSI", "GPS", "THRUST_RING", "GPS_BAR",
        "BATTERY_BAR", "ALTITUDE"
    ]

    # Overlay function names (each bit represents a different overlay)
    overlay_names = [
        "THROTTLE", "RAINBOW", "LARSON_SCANNER", "BLINK",
        "VTX", "INDICATOR", "WARNING"
    ]

    # Color names
    color_names = [
        "BLACK", "WHITE", "RED", "ORANGE", "YELLOW",
        "LIME_GREEN", "GREEN", "MINT_GREEN", "CYAN",
        "LIGHT_BLUE", "BLUE", "DARK_VIOLET", "MAGENTA",
        "DEEP_PINK"
    ]

    # Direction names (each bit represents a different direction)
    direction_names = [
        "NORTH", "EAST", "SOUTH", "WEST", "UP", "DOWN"
    ]

    # Format the output
    output = []
    output.append(f"LED {led_index} Configuration:")
    output.append(f"Position: X={x}, Y={y}")
    
    # Function
    if function < len(function_names):
        output.append(f"Function: {function_names[function]} ({function})")
    else:
        output.append(f"Function: INVALID_FUNCTION_{function}")
    
    # Overlays (multiple can be active)
    active_overlays = []
    for i in range(len(overlay_names)):
        if overlay & (1 << i):
            active_overlays.append(overlay_names[i])
    output.append(f"Overlays: {', '.join(active_overlays) if active_overlays else 'None'} (0x{overlay:03X})")
    
    # Color
    if color < len(color_names):
        output.append(f"Color: {color_names[color]} ({color})")
    else:
        output.append(f"Color: INVALID_COLOR_{color}")
    
    # Directions (multiple can be active)
    active_directions = []
    for i in range(len(direction_names)):
        if direction & (1 << i):
            active_directions.append(direction_names[i])
    output.append(f"Directions: {', '.join(active_directions) if active_directions else 'None'} (0x{direction:02X})")

    # Debug output
    output.append(f"Raw Mask: 0x{mask:08X}")
    output.append(f"Raw Bytes: {' '.join([f'0x{b:02X}' for b in payload[1:5]])}")

    return ", ".join(output)

def decode_msp_set_led_strip_config_response(payload: bytes) -> str:
    if len(payload) == 0:
        return "LED Strip Configuration Set"
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP_STATUS_EX
# ---------------------------
def decode_msp_status_ex_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Extended Status Data"
    return MSG_INVALID_PAYLOAD

def decode_msp_status_ex_response(payload: bytes) -> str:
    """
    Decodes the response for extended status data.
    """
    if len(payload) < 13:  # Minimum required bytes
        return MSG_INVALID_PAYLOAD

    index = 0
    cycle_time = int.from_bytes(payload[index:index+2], 'little')  # Task delta time in µs
    index += 2
    i2c_errors = int.from_bytes(payload[index:index+2], 'little')
    index += 2
    sensor_flags = int.from_bytes(payload[index:index+2], 'little')
    index += 2
    flight_mode_flags = int.from_bytes(payload[index:index+4], 'little')
    index += 4
    pid_profile = payload[index]
    index += 1
    system_load = int.from_bytes(payload[index:index+2], 'little')
    index += 2

    # Decode sensor flags
    sensors = []
    if sensor_flags & (1 << 0): sensors.append("ACC")
    if sensor_flags & (1 << 1): sensors.append("BARO")
    if sensor_flags & (1 << 2): sensors.append("MAG")
    if sensor_flags & (1 << 3): sensors.append("GPS")
    if sensor_flags & (1 << 4): sensors.append("RANGEFINDER")
    if sensor_flags & (1 << 5): sensors.append("GYRO")
    if sensor_flags & (1 << 6): sensors.append("OPTICALFLOW")

    # Decode flight mode flags (same as MSP_STATUS)
    modes = []
    if flight_mode_flags & (1 << 0): modes.append("ARM")
    if flight_mode_flags & (1 << 1): modes.append("ANGLE")
    if flight_mode_flags & (1 << 2): modes.append("HORIZON")
    if flight_mode_flags & (1 << 3): modes.append("NAV ALTHOLD")
    # ... (rest of mode flags same as MSP_STATUS)

    return (f"Cycle Time: {cycle_time}µs, "
            f"I2C Errors: {i2c_errors}, "
            f"Active Sensors: {', '.join(sensors)}, "
            f"Flight Modes: {', '.join(modes)}, "
            f"PID Profile: {pid_profile}, "
            f"System Load: {system_load/10.0}%")

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
    if len(payload) == 0:
        return "Request Beeper Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_beeper_config_response(payload: bytes) -> str:
    """
    Decodes the response for beeper configuration.
    """
    if len(payload) < 9:  # uint32 + uint8 + uint32
        return MSG_INVALID_PAYLOAD

    beeper_off_flags = int.from_bytes(payload[0:4], 'little')
    dshot_beacon_tone = payload[4]
    dshot_beacon_off_flags = int.from_bytes(payload[5:9], 'little')

    return (f"Beeper Off Flags: 0x{beeper_off_flags:08X}, "
            f"DShot Beacon Tone: {dshot_beacon_tone}, "
            f"DShot Beacon Off Flags: 0x{dshot_beacon_off_flags:08X}")

# ---------------------------
# MSP_MOTOR_3D_CONFIG
# ---------------------------
def decode_msp_motor_3d_config_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request 3D Motor Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_motor_3d_config_response(payload: bytes) -> str:
    """
    Decodes the 3D motor configuration response.
    
    Payload format:
    uint16_t deadband3d_low;        // Low value of 3D deadband
    uint16_t deadband3d_high;       // High value of 3D deadband
    uint16_t neutral3d;             // Center value of 3D deadband
    """
    if len(payload) < 6:
        return MSG_INVALID_PAYLOAD

    deadband3d_low = int.from_bytes(payload[0:2], 'little')
    deadband3d_high = int.from_bytes(payload[2:4], 'little')
    neutral3d = int.from_bytes(payload[4:6], 'little')

    return (f"Deadband Low: {deadband3d_low}, "
            f"Deadband High: {deadband3d_high}, "
            f"Neutral: {neutral3d}")

# ---------------------------
# MSP_MIXER_CONFIG
# ---------------------------
def decode_msp_mixer_config_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Mixer Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_mixer_config_response(payload: bytes) -> str:
    """
    Decodes the mixer configuration response.

    Payload format:
    uint8_t mixer_mode;  // Mixer mode (0=Quad X, etc)
    uint8_t yaw_motors_reversed;  // Whether yaw motor direction is reversed
    """
    if len(payload) < 2:
        return MSG_INVALID_PAYLOAD

    mixer_mode = payload[0]
    yaw_motors_reversed = payload[1]

    # Mixer mode names
    mixer_modes = {
        0: "TRI",
        1: "QUADP",
        2: "QUADX",
        3: "BI",
        4: "GIMBAL",
        5: "Y6",
        6: "HEX6",
        7: "FLYING_WING",
        8: "Y4",
        9: "HEX6X",
        10: "OCTOX8",
        11: "OCTOFLATP",
        12: "OCTOFLATX",
        13: "AIRPLANE",
        14: "HELI_120_CCPM",
        15: "HELI_90_DEG",
        16: "VTAIL4",
        17: "HEX6H",
        18: "PPM_TO_SERVO",
        19: "DUALCOPTER",
        20: "SINGLECOPTER",
        21: "ATAIL4",
        22: "CUSTOM",
        23: "CUSTOM_AIRPLANE",
        24: "CUSTOM_TRI"
    }

    mixer_mode_name = mixer_modes.get(mixer_mode, f"UNKNOWN({mixer_mode})")
    
    return (f"Mode: {mixer_mode_name}, "
            f"Yaw Motors Reversed: {'Yes' if yaw_motors_reversed else 'No'}")

# ---------------------------
# MSP_MOTOR_CONFIG
# ---------------------------
def decode_msp_motor_config_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for Motor Config"
    return MSG_INVALID_PAYLOAD

def decode_msp_motor_config_response(payload: bytes) -> str:
    """Decode MSP_MOTOR_CONFIG response.
    """
    if len(payload) >= 6:  # Basic config (3 x uint16_t)
        min_throttle = int.from_bytes(payload[0:2], 'little')  # Always 0 after 4.5
        max_throttle = int.from_bytes(payload[2:4], 'little')
        min_command = int.from_bytes(payload[4:6], 'little')
        
        response = (f"Min Throttle: {min_throttle}, "
                   f"Max Throttle: {max_throttle}, "
                   f"Min Command: {min_command}")
        
        # API 1.42 additions
        if len(payload) >= 10:
            motor_count = payload[6]
            motor_pole_count = payload[7]
            use_dshot_telemetry = bool(payload[8])
            has_esc_sensor = bool(payload[9])
            
            response += (f", Motor Count: {motor_count}, "
                        f"Motor Pole Count: {motor_pole_count}, "
                        f"DShot Telemetry: {use_dshot_telemetry}, "
                        f"ESC Sensor: {has_esc_sensor}")
        
        return response
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP_MOTOR_TELEMETRY
# ---------------------------
def decode_msp_motor_telemetry_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Motor Telemetry"
    return MSG_INVALID_PAYLOAD

def decode_msp_motor_telemetry_response(payload: bytes) -> str:
    """
    Decodes the motor telemetry response.
    
    Payload format:
    uint8_t count;                  // Number of motors
    struct {
        uint16_t rpm;              // Motor RPM
        uint16_t invalidPercent;   // Percentage of invalid DShot telemetry packets
        uint16_t temperature;      // Temperature in 0.1 degrees Celsius
        uint16_t voltage;          // Voltage in 0.01V
        uint16_t current;          // Current in 0.01A
        uint16_t consumption;      // Consumption in mAh
    } motors[count];
    """
    if len(payload) < 1:
        return MSG_INVALID_PAYLOAD

    count = payload[0]
    index = 1
    motors = []

    for i in range(count):
        if len(payload) < index + 12:  # Each motor needs 12 bytes
            break

        rpm = int.from_bytes(payload[index:index+2], 'little')
        invalid_percent = int.from_bytes(payload[index+2:index+4], 'little')
        temperature = int.from_bytes(payload[index+4:index+6], 'little')
        voltage = int.from_bytes(payload[index+6:index+8], 'little')
        current = int.from_bytes(payload[index+8:index+10], 'little')
        consumption = int.from_bytes(payload[index+10:index+12], 'little')

        motors.append(f"Motor {i+1}: RPM: {rpm}, "
                     f"Invalid DShot: {invalid_percent}%, "
                     f"Temperature: {temperature/10.0:.1f}°C, "
                     f"Voltage: {voltage/100.0:.2f}V, "
                     f"Current: {current/100.0:.2f}A, "
                     f"Consumption: {consumption}mAh")
        index += 12

    return " | ".join(motors)

# ---------------------------
# MSP2_MOTOR_OUTPUT_REORDERING
# ---------------------------
def decode_msp2_motor_output_reordering_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Motor Output Reordering"
    return MSG_INVALID_PAYLOAD

def decode_msp2_motor_output_reordering_response(payload: bytes) -> str:
    """Decode MSP2_MOTOR_OUTPUT_REORDERING response."""
    if len(payload) < 1:
        return MSG_INVALID_PAYLOAD

    count = payload[0]
    if len(payload) < 1 + count:
        return MSG_INVALID_PAYLOAD

    reordering = []
    for i in range(count):
        reordering.append(f"Motor {i+1} -> {payload[i+1]+1}")

    return "Motor Output Reordering:\n  " + "\n  ".join(reordering)

# ---------------------------
# MSP2_SEND_DSHOT_COMMAND
# ---------------------------
def decode_msp2_send_dshot_command_request(payload: bytes) -> str:
    """Decode MSP2_SEND_DSHOT_COMMAND request."""
    if len(payload) < 3:
        return MSG_INVALID_PAYLOAD

    command_type = payload[0]
    motor_index = payload[1]
    command_count = payload[2]

    if len(payload) < 3 + command_count:
        return MSG_INVALID_PAYLOAD

    # Command type names
    command_type_names = {
        0: "INLINE",
        1: "BLOCKING"
    }

    # Command names
    command_names = {
        0: "MOTOR_STOP",
        1: "BEACON1",
        2: "BEACON2",
        3: "BEACON3",
        4: "BEACON4",
        5: "BEACON5",
        6: "ESC_INFO",
        7: "SPIN_DIRECTION_1",
        8: "SPIN_DIRECTION_2",
        9: "3D_MODE_OFF",
        10: "3D_MODE_ON",
        11: "SETTINGS_REQUEST",
        12: "SAVE_SETTINGS",
        13: "EXTENDED_TELEMETRY_ENABLE",
        14: "EXTENDED_TELEMETRY_DISABLE",
        20: "SPIN_DIRECTION_NORMAL",
        21: "SPIN_DIRECTION_REVERSED",
        22: "LED0_ON",
        23: "LED1_ON",
        24: "LED2_ON",
        25: "LED3_ON",
        26: "LED0_OFF",
        27: "LED1_OFF",
        28: "LED2_OFF",
        29: "LED3_OFF",
        30: "AUDIO_STREAM_MODE_ON_OFF",
        31: "SILENT_MODE_ON_OFF"
    }

    command_type_name = command_type_names.get(command_type, f"UNKNOWN({command_type})")
    target = "All Motors" if motor_index == 255 else f"Motor {motor_index + 1}"

    # Get all commands
    commands = []
    for i in range(command_count):
        cmd = payload[3 + i]
        cmd_name = command_names.get(cmd, f"UNKNOWN({cmd})")
        commands.append(cmd_name)

    return (f"Send DShot Command:\n"
            f"  Type: {command_type_name}\n"
            f"  Target: {target}\n"
            f"  Commands: {', '.join(commands)}")

def decode_msp2_send_dshot_command_response(payload: bytes) -> str:
    """Decode MSP2_SEND_DSHOT_COMMAND response."""
    if len(payload) < 1:
        return MSG_INVALID_PAYLOAD

    success = payload[0]
    return f"DShot Command {'Sent Successfully' if success else 'Failed'}"

# ---------------------------
# MSP_MOTOR
# ---------------------------
def decode_msp_motor_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for Motor Values"
    return MSG_INVALID_PAYLOAD

def decode_msp_motor_response(payload: bytes) -> str:
    if len(payload) >= 16:  # 8 motors * 2 bytes each
        motors = []
        for i in range(0, min(len(payload), 16), 2):
            motor_value = int.from_bytes(payload[i:i+2], 'little')
            motors.append(f"Motor {i//2 + 1}: {motor_value}")
        return "\n".join(motors)
        return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP_UID
# ---------------------------
def decode_msp_uid_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for Device Unique ID"
    return MSG_INVALID_PAYLOAD

def decode_msp_uid_response(payload: bytes) -> str:
    """
    Decodes the device unique ID response.
    """
    if len(payload) >= 12:  # 3 x uint32_t
        uid0 = int.from_bytes(payload[0:4], 'little')
        uid1 = int.from_bytes(payload[4:8], 'little')
        uid2 = int.from_bytes(payload[8:12], 'little')
        return f"Device UID: {uid0:08X}-{uid1:08X}-{uid2:08X}"
        return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP_SET_ARMING_DISABLED
# ---------------------------
def decode_msp_set_arming_disabled_request(payload: bytes) -> str:
    """Decode MSP_SET_ARMING_DISABLED request."""
    if len(payload) < 1:
        return MSG_INVALID_PAYLOAD

    arming_disabled = payload[0]
    return f"Set Arming {'Disabled' if arming_disabled else 'Enabled'}"

def decode_msp_set_arming_disabled_response(payload: bytes) -> str:
    if len(payload) == 0:
        return "Arming state updated successfully"
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP_FEATURE_CONFIG
# ---------------------------
def decode_msp_feature_config_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Feature Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_feature_config_response(payload: bytes) -> str:
    if len(payload) < 4:
        return MSG_INVALID_PAYLOAD

    features = int.from_bytes(payload[0:4], 'little')
    active_features = []
    
    # Feature flags from betaflight/src/main/fc/feature.h
    if features & (1 << 0): active_features.append("RX_PPM")
    if features & (1 << 2): active_features.append("INFLIGHT_ACC_CAL")
    if features & (1 << 3): active_features.append("RX_SERIAL")
    if features & (1 << 4): active_features.append("MOTOR_STOP")
    if features & (1 << 5): active_features.append("SERVO_TILT")
    if features & (1 << 6): active_features.append("SOFTSERIAL")
    if features & (1 << 7): active_features.append("GPS")
    if features & (1 << 9): active_features.append("SONAR")
    if features & (1 << 10): active_features.append("TELEMETRY")
    if features & (1 << 12): active_features.append("3D")
    if features & (1 << 13): active_features.append("RX_PARALLEL_PWM")
    if features & (1 << 14): active_features.append("RX_MSP")
    if features & (1 << 15): active_features.append("RSSI_ADC")
    if features & (1 << 16): active_features.append("LED_STRIP")
    if features & (1 << 17): active_features.append("DISPLAY")
    if features & (1 << 20): active_features.append("CHANNEL_FORWARDING")
    if features & (1 << 21): active_features.append("TRANSPONDER")
    if features & (1 << 22): active_features.append("AIRMODE")
    if features & (1 << 25): active_features.append("RX_SPI")
    if features & (1 << 26): active_features.append("ESC_SENSOR")
    if features & (1 << 27): active_features.append("ANTI_GRAVITY")
    if features & (1 << 28): active_features.append("DYNAMIC_FILTER")
    
    return f"Active Features: {', '.join(active_features) if active_features else 'None'} (0x{features:08X})"

# ---------------------------
# MSP_SDCARD_SUMMARY
# ---------------------------
def decode_msp_sdcard_summary_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request SD Card Summary"
    return MSG_INVALID_PAYLOAD

def decode_msp_sdcard_summary_response(payload: bytes) -> str:
    if len(payload) < 11:
        return MSG_INVALID_PAYLOAD

    flags = payload[0]
    state = payload[1]
    sectors = int.from_bytes(payload[2:6], 'little')
    sector_size = int.from_bytes(payload[6:10], 'little')
    free_space = int.from_bytes(payload[10:], 'little')
    
    # Decode flags
    flag_list = []
    if flags & (1 << 0): flag_list.append("SUPPORTED")
    if flags & (1 << 1): flag_list.append("PRESENT")
    
    # Decode state
    states = {
        0: "NOT_PRESENT",
        1: "READY",
        2: "NOT_READY",
        3: "FATAL"
    }
    state_str = states.get(state, f"UNKNOWN ({state})")
    
    total_size = sectors * sector_size
    
    def format_size(size_bytes):
        if size_bytes >= 1024*1024*1024:
            return f"{size_bytes/(1024*1024*1024):.1f}GB"
        elif size_bytes >= 1024*1024:
            return f"{size_bytes/(1024*1024):.1f}MB"
        elif size_bytes >= 1024:
            return f"{size_bytes/1024:.1f}KB"
        else:
            return f"{size_bytes} bytes"
    
    return (f"SD Card Status: {', '.join(flag_list)}\n"
            f"State: {state_str}\n"
            f"Total Size: {format_size(total_size)}\n"
            f"Free Space: {format_size(free_space)}")

# ---------------------------
# MSP_ACC_TRIM
# ---------------------------
def decode_msp_acc_trim_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Accelerometer Trim Values"
    return MSG_INVALID_PAYLOAD

def decode_msp_acc_trim_response(payload: bytes) -> str:
    """Decode MSP_ACC_TRIM response."""
    if len(payload) < 4:
        return MSG_INVALID_PAYLOAD

    pitch_trim = int.from_bytes(payload[0:2], 'little', signed=True)
    roll_trim = int.from_bytes(payload[2:4], 'little', signed=True)
    
    return f"Accelerometer Trim: Pitch={pitch_trim}, Roll={roll_trim}"
    
# ---------------------------
# MSP_BLACKBOX_CONFIG
# ---------------------------
def decode_msp_blackbox_config_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Blackbox Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_blackbox_config_response(payload: bytes) -> str:
    if len(payload) < 7:
        return MSG_INVALID_PAYLOAD

    device = payload[0]
    rate_num = payload[1]
    rate_denom = payload[2]
    p_denom = payload[3]
    i_denom = payload[4]
    d_denom = payload[5]
    sample_rate = payload[6]
    
    # Decode device type
    devices = {
        0: "NONE",
        1: "ONBOARD FLASH",
        2: "SDCARD",
        3: "SERIAL"
    }
    device_str = devices.get(device, f"UNKNOWN ({device})")
    
    return (f"Blackbox Device: {device_str}\n"
            f"Rate: {rate_num}/{rate_denom}\n"
            f"PID Sampling: P={p_denom}, I={i_denom}, D={d_denom}\n"
            f"Sample Rate: {sample_rate}Hz")

# ---------------------------
# MSP_SET_RTC
# ---------------------------
def decode_msp_set_rtc_request(payload: bytes) -> str:
    """
    Decodes the request to set RTC time.
    """
    if len(payload) >= 6:  # uint32_t + uint16_t
        secs = int.from_bytes(payload[0:4], 'little')
        millis = int.from_bytes(payload[4:6], 'little')
        
        # Convert Unix timestamp to UTC time string
        from datetime import datetime, timezone
        utc_time = datetime.fromtimestamp(secs, tz=timezone.utc)
        
        return f"Set RTC Time: {utc_time.strftime('%Y-%m-%d %H:%M:%S')} UTC + {millis}ms"
        return MSG_INVALID_PAYLOAD

def decode_msp_set_rtc_response(payload: bytes) -> str:
    if len(payload) == 0:
        return "RTC Time Set Successfully"
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP_ARMING_CONFIG
# ---------------------------
def decode_msp_arming_config_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Arming Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_arming_config_response(payload: bytes) -> str:
    """
    Decodes the arming configuration response.
    
    Payload format from betaflight/src/main/fc/rc.h:
    uint8_t auto_disarm_delay;      // Time in seconds before disarming when no activity
    uint8_t disarm_kill_switch;     // Whether disarm switch should be immediate
    uint8_t small_angle;            // Maximum angle for arming
    """
    if len(payload) < 3:
        return MSG_INVALID_PAYLOAD

    auto_disarm_delay = payload[0]
    disarm_kill_switch = payload[1]
    small_angle = payload[2]

    return (f"Auto Disarm Delay: {auto_disarm_delay}s, "
            f"Disarm Kill Switch: {'Enabled' if disarm_kill_switch else 'Disabled'}, "
            f"Small Angle: {small_angle}°")

# ---------------------------
# MSP_RC_DEADBAND
# ---------------------------
def decode_msp_rc_deadband_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request RC Deadband Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_rc_deadband_response(payload: bytes) -> str:
    """
    Decodes the RC deadband configuration response.
    
    Payload format from betaflight/src/main/fc/rc.h:
    uint8_t deadband;               // Deadband for sticks
    uint8_t yaw_deadband;          // Deadband for yaw stick
    uint8_t alt_hold_deadband;     // Deadband for altitude hold
    uint16_t deadband3d_throttle;  // Deadband for 3D throttle
    """
    if len(payload) < 5:
        return MSG_INVALID_PAYLOAD

    deadband = payload[0]
    yaw_deadband = payload[1]
    alt_hold_deadband = payload[2]
    deadband3d_throttle = int.from_bytes(payload[3:5], 'little')

    return (f"Deadband: {deadband}, "
            f"Yaw Deadband: {yaw_deadband}, "
            f"Alt Hold Deadband: {alt_hold_deadband}, "
            f"3D Throttle Deadband: {deadband3d_throttle}")

# ---------------------------
# MSP_SENSOR_CONFIG
# ---------------------------
def decode_msp_sensor_config_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Sensor Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_sensor_config_response(payload: bytes) -> str:
    """
    Decodes the sensor configuration response.
    
    Payload format from betaflight/src/main/sensors/sensors.h:
    uint8_t acc_hardware;           // Accelerometer hardware type
    uint8_t baro_hardware;         // Barometer hardware type
    uint8_t mag_hardware;          // Magnetometer hardware type
    uint8_t rangefinder_hardware;  // Rangefinder hardware type
    uint8_t pitot_hardware;        // Pitot tube hardware type
    uint8_t optical_flow_hardware; // Optical flow sensor hardware type
    """
    if len(payload) < 6:
        return MSG_INVALID_PAYLOAD

    # Hardware type names
    hardware_types = {
        0: "NONE",
        1: "AUTO",
        2: "ADXL345",
        3: "MPU6050",
        4: "MMA8452",
        5: "BMA280",
        6: "LSM303DLHC",
        7: "MPU6000",
        8: "MPU6500",
        9: "MPU9250",
        10: "ICM20601",
        11: "ICM20602",
        12: "ICM20608G",
        13: "ICM20649",
        14: "ICM20689",
        15: "BMI160",
        16: "FAKE"
    }

    acc_hardware = hardware_types.get(payload[0], f"UNKNOWN({payload[0]})")
    baro_hardware = hardware_types.get(payload[1], f"UNKNOWN({payload[1]})")
    mag_hardware = hardware_types.get(payload[2], f"UNKNOWN({payload[2]})")
    rangefinder_hardware = hardware_types.get(payload[3], f"UNKNOWN({payload[3]})")
    pitot_hardware = hardware_types.get(payload[4], f"UNKNOWN({payload[4]})")
    optical_flow_hardware = hardware_types.get(payload[5], f"UNKNOWN({payload[5]})")

    return (f"Accelerometer: {acc_hardware}, "
            f"Barometer: {baro_hardware}, "
            f"Magnetometer: {mag_hardware}, "
            f"Rangefinder: {rangefinder_hardware}, "
            f"Pitot: {pitot_hardware}, "
            f"Optical Flow: {optical_flow_hardware}")

# ---------------------------
# MSP_SENSOR_ALIGNMENT
# ---------------------------
def decode_msp_sensor_alignment_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Sensor Alignment Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_sensor_alignment_response(payload: bytes) -> str:
    """
    Decodes the sensor alignment configuration response.
    
    Payload format from betaflight/src/main/sensors/sensors.h:
    uint8_t gyro_alignment;         // Gyroscope sensor alignment
    uint8_t acc_alignment;          // Accelerometer sensor alignment
    uint8_t mag_alignment;          // Magnetometer sensor alignment
    uint8_t opflow_alignment;       // Optical flow sensor alignment
    """
    if len(payload) < 4:
        return MSG_INVALID_PAYLOAD

    # Alignment type names
    alignment_types = {
        0: "DEFAULT",
        1: "CW0",
        2: "CW90",
        3: "CW180",
        4: "CW270",
        5: "CW0FLIP",
        6: "CW90FLIP",
        7: "CW180FLIP",
        8: "CW270FLIP"
    }

    gyro_alignment = alignment_types.get(payload[0], f"UNKNOWN({payload[0]})")
    acc_alignment = alignment_types.get(payload[1], f"UNKNOWN({payload[1]})")
    mag_alignment = alignment_types.get(payload[2], f"UNKNOWN({payload[2]})")
    opflow_alignment = alignment_types.get(payload[3], f"UNKNOWN({payload[3]})")

    return (f"Gyro: {gyro_alignment}, "
            f"Accelerometer: {acc_alignment}, "
            f"Magnetometer: {mag_alignment}, "
            f"Optical Flow: {opflow_alignment}")

# ---------------------------
# MSP_RX_CONFIG
# ---------------------------
def decode_msp_rx_config_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request RX Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_rx_config_response(payload: bytes) -> str:
    """
    Decodes the RX configuration response.
    
    Payload format from betaflight/src/main/rx/rx.h:
    uint8_t serialrx_provider;      // SerialRX provider (SPEK, SBUS, etc)
    uint16_t maxcheck;              // Maximum value for stick inputs
    uint16_t midrc;                 // Mid position for sticks
    uint16_t mincheck;              // Minimum value for stick inputs
    uint8_t spektrum_sat_bind;      // Number of Spektrum bind pulses
    uint16_t rx_min_usec;           // Minimum channel value in µs
    uint16_t rx_max_usec;           // Maximum channel value in µs
    uint8_t rcInterpolation;        // RC interpolation type
    uint8_t rcInterpolationInterval;// RC interpolation interval
    uint8_t airModeActivateThreshold;// Air mode activate threshold
    uint16_t rx_spi_protocol;       // RX SPI protocol type
    uint32_t rx_spi_id;             // RX SPI ID
    uint8_t rx_spi_rf_channel_count;// Number of RX SPI RF channels
    """
    if len(payload) < 23:  # Minimum size for all fields
        return MSG_INVALID_PAYLOAD

    # SerialRX provider names
    serialrx_providers = {
        0: "SPEK1024",
        1: "SPEK2048",
        2: "SBUS",
        3: "SUMD",
        4: "SUMH",
        5: "XBUS_MODE_B",
        6: "XBUS_MODE_B_RJ01",
        7: "IBUS",
        8: "JETIEXBUS",
        9: "CRSF",
        10: "SRXL",
        11: "CUSTOM",
        12: "FPORT",
        13: "SRXL2"
    }

    # RC interpolation types
    rc_interpolation_types = {
        0: "OFF",
        1: "DEFAULT",
        2: "AUTO",
        3: "MANUAL"
    }

    # RX SPI protocols
    rx_spi_protocols = {
        0: "V202_250K",
        1: "V202_1M",
        2: "SYMA_X",
        3: "SYMA_X5C",
        4: "CX10",
        5: "CX10A",
        6: "H8_3D",
        7: "INAV",
        8: "FRSKY_D",
        9: "FRSKY_X",
        10: "FLYSKY",
        11: "FLYSKY_2A",
        12: "NRF24_V202_250K",
        13: "NRF24_V202_1M",
        14: "NRF24_SYMA_X",
        15: "NRF24_SYMA_X5C",
        16: "NRF24_CX10",
        17: "NRF24_CX10A",
        18: "NRF24_H8_3D",
        19: "NRF24_INAV",
        20: "SPEKTRUM",
        21: "FRSKY_X_LBT"
    }

    index = 0
    serialrx_provider = serialrx_providers.get(payload[index], f"UNKNOWN({payload[index]})")
    index += 1
    maxcheck = int.from_bytes(payload[index:index+2], 'little')
    index += 2
    midrc = int.from_bytes(payload[index:index+2], 'little')
    index += 2
    mincheck = int.from_bytes(payload[index:index+2], 'little')
    index += 2
    spektrum_sat_bind = payload[index]
    index += 1
    rx_min_usec = int.from_bytes(payload[index:index+2], 'little')
    index += 2
    rx_max_usec = int.from_bytes(payload[index:index+2], 'little')
    index += 2
    rcInterpolation = rc_interpolation_types.get(payload[index], f"UNKNOWN({payload[index]})")
    index += 1
    rcInterpolationInterval = payload[index]
    index += 1
    airModeActivateThreshold = payload[index]
    index += 1
    rx_spi_protocol = rx_spi_protocols.get(int.from_bytes(payload[index:index+2], 'little'), "UNKNOWN")
    index += 2
    rx_spi_id = int.from_bytes(payload[index:index+4], 'little')
    index += 4
    rx_spi_rf_channel_count = payload[index]

    return (f"SerialRX Provider: {serialrx_provider}, "
            f"Max Check: {maxcheck}, "
            f"Mid RC: {midrc}, "
            f"Min Check: {mincheck}, "
            f"Spektrum Sat Bind: {spektrum_sat_bind}, "
            f"RX Min µs: {rx_min_usec}, "
            f"RX Max µs: {rx_max_usec}, "
            f"RC Interpolation: {rcInterpolation}, "
            f"RC Interpolation Interval: {rcInterpolationInterval}, "
            f"Air Mode Threshold: {airModeActivateThreshold}, "
            f"RX SPI Protocol: {rx_spi_protocol}, "
            f"RX SPI ID: 0x{rx_spi_id:08X}, "
            f"RX SPI RF Channels: {rx_spi_rf_channel_count}")

# ---------------------------
# MSP_ADVANCED_CONFIG
# ---------------------------
def decode_msp_advanced_config_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Advanced Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_advanced_config_response(payload: bytes) -> str:
    """
    Decodes the advanced configuration response.
    
    Payload format from betaflight/src/main/fc/config.h:
    uint8_t gyro_sync_denom;        // Gyro sync denominator
    uint8_t pid_process_denom;      // PID process denominator
    uint8_t use_unsynced_pwm;       // Use unsynchronized PWM
    uint8_t fast_pwm_protocol;      // Fast PWM protocol
    uint16_t motor_pwm_rate;        // Motor PWM rate
    uint16_t digitalIdleOffset;     // Digital idle offset
    uint8_t gyroUse32kHz;          // Use 32kHz gyro sampling
    uint8_t motorPwmInversion;      // Motor PWM inversion
    uint8_t gyroHighFsr;           // High FSR gyro mode
    uint8_t gyroMovementCalibThreshold; // Gyro movement calibration threshold
    uint16_t gyroCalibDuration;    // Gyro calibration duration
    uint16_t gyroOffsetYaw;        // Gyro offset for yaw
    uint8_t gyroCheckOverflow;     // Check for gyro overflow
    uint8_t debugMode;             // Debug mode
    """
    if len(payload) < 15:  # Minimum size for all fields
        return MSG_INVALID_PAYLOAD

    index = 0
    gyro_sync_denom = payload[index]
    index += 1
    pid_process_denom = payload[index]
    index += 1
    use_unsynced_pwm = payload[index]
    index += 1
    fast_pwm_protocol = payload[index]
    index += 1
    motor_pwm_rate = int.from_bytes(payload[index:index+2], 'little')
    index += 2
    digital_idle_offset = int.from_bytes(payload[index:index+2], 'little')
    index += 2
    gyro_use_32khz = payload[index]
    index += 1
    motor_pwm_inversion = payload[index]
    index += 1
    gyro_high_fsr = payload[index]
    index += 1
    gyro_movement_calib_threshold = payload[index]
    index += 1
    gyro_calib_duration = int.from_bytes(payload[index:index+2], 'little')
    index += 2
    gyro_offset_yaw = int.from_bytes(payload[index:index+2], 'little')
    index += 2
    gyro_check_overflow = payload[index]
    index += 1
    debug_mode = payload[index]

    # Fast PWM protocol names
    pwm_protocols = {
        0: "OFF",
        1: "ONESHOT125",
        2: "ONESHOT42",
        3: "MULTISHOT",
        4: "BRUSHED",
        5: "DSHOT150",
        6: "DSHOT300",
        7: "DSHOT600",
        8: "DSHOT1200",
        9: "PROSHOT1000"
    }

    protocol_name = pwm_protocols.get(fast_pwm_protocol, f"UNKNOWN({fast_pwm_protocol})")

    return (f"Gyro Sync Denom: {gyro_sync_denom}, "
            f"PID Process Denom: {pid_process_denom}, "
            f"Unsynced PWM: {'Yes' if use_unsynced_pwm else 'No'}, "
            f"Fast PWM Protocol: {protocol_name}, "
            f"Motor PWM Rate: {motor_pwm_rate}Hz, "
            f"Digital Idle Offset: {digital_idle_offset}, "
            f"32kHz Gyro: {'Yes' if gyro_use_32khz else 'No'}, "
            f"Motor PWM Inversion: {'Yes' if motor_pwm_inversion else 'No'}, "
            f"High FSR Gyro: {'Yes' if gyro_high_fsr else 'No'}, "
            f"Gyro Cal Threshold: {gyro_movement_calib_threshold}, "
            f"Gyro Cal Duration: {gyro_calib_duration}ms, "
            f"Gyro Yaw Offset: {gyro_offset_yaw}, "
            f"Check Gyro Overflow: {'Yes' if gyro_check_overflow else 'No'}, "
            f"Debug Mode: {debug_mode}")

# ---------------------------
# MSP_COMPASS_CONFIG
# ---------------------------
def decode_msp_compass_config_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Compass Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_compass_config_response(payload: bytes) -> str:
    """
    Decodes the compass configuration response.
    
    Payload format from betaflight/src/main/sensors/compass.h:
    uint16_t mag_declination;        // Magnetic declination in decidegrees
    uint8_t mag_hardware;           // Magnetometer hardware type
    """
    if len(payload) < 3:
        return MSG_INVALID_PAYLOAD

    mag_declination = int.from_bytes(payload[0:2], 'little')
    mag_hardware = payload[2]

    # Hardware type names
    hardware_types = {
        0: "NONE",
        1: "AUTO",
        2: "HMC5883",
        3: "AK8975",
        4: "AK8963",
        5: "IST8310",
        6: "QMC5883",
        7: "MAG3110",
        8: "LIS3MDL"
    }

    hardware_name = hardware_types.get(mag_hardware, f"UNKNOWN({mag_hardware})")
    return (f"Magnetic Declination: {mag_declination/10.0}°, "
            f"Hardware: {hardware_name}")

# ---------------------------
# MSP_VOLTAGE_METERS
# ---------------------------
def decode_msp_voltage_meters_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Voltage Meters"
    return MSG_INVALID_PAYLOAD

def decode_msp_voltage_meters_response(payload: bytes) -> str:
    """
    Decodes the voltage meters response.
    
    Payload format from betaflight/src/main/sensors/voltage.h:
    struct {
        uint8_t id;                 // Voltage meter ID
        uint8_t voltage;            // Voltage in 0.1V steps
    } meters[];
    """
    if len(payload) < 2:
        return MSG_INVALID_PAYLOAD

    meters = []
    for i in range(0, len(payload), 2):
        if i + 1 >= len(payload):
            break
        meter_id = payload[i]
        voltage = payload[i + 1]
        meters.append(f"Meter {meter_id}: {voltage/10.0}V")

    return ", ".join(meters)

# ---------------------------
# MSP_CURRENT_METER_CONFIG
# ---------------------------
def decode_msp_current_meter_config_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Current Meter Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_current_meter_config_response(payload: bytes) -> str:
    """
    Decodes the current meter configuration response.
    
    Payload format from betaflight/src/main/sensors/current.h:
    uint16_t scale;              // Scale the raw ADC value to milliamps
    uint16_t offset;             // Offset in milliamps
    uint8_t type;               // Sensor type
    """
    if len(payload) < 5:
        return MSG_INVALID_PAYLOAD

    scale = int.from_bytes(payload[0:2], 'little')
    offset = int.from_bytes(payload[2:4], 'little')
    sensor_type = payload[4]

    # Sensor type names
    sensor_types = {
        0: "NONE",
        1: "ADC",
        2: "VIRTUAL",
        3: "ESC",
        4: "MSP"
    }

    type_name = sensor_types.get(sensor_type, f"UNKNOWN({sensor_type})")
    return (f"Scale: {scale}, "
            f"Offset: {offset}mA, "
            f"Type: {type_name}")

# ---------------------------
# MSP_VOLTAGE_METER_CONFIG
# ---------------------------
def decode_msp_voltage_meter_config_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Voltage Meter Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_voltage_meter_config_response(payload: bytes) -> str:
    """
    Decodes the voltage meter configuration response.
    
    Payload format from betaflight/src/main/sensors/voltage.h:
    uint8_t vbatscale;           // ADC to voltage multiplier in 0.1V steps
    uint8_t vbatresdivval;       // Resistor divider value
    uint8_t vbatresdivmultiplier;// Resistor divider multiplier
    uint8_t vbatmaxcellvoltage;  // Maximum cell voltage in 0.1V steps
    uint8_t vbatmincellvoltage;  // Minimum cell voltage in 0.1V steps
    uint8_t vbatwarningcellvoltage; // Warning cell voltage in 0.1V steps
    """
    if len(payload) < 6:
        return MSG_INVALID_PAYLOAD

    vbatscale = payload[0]
    vbatresdivval = payload[1]
    vbatresdivmultiplier = payload[2]
    vbatmaxcellvoltage = payload[3]
    vbatmincellvoltage = payload[4]
    vbatwarningcellvoltage = payload[5]

    return (f"Scale: {vbatscale/10.0}V, "
            f"Divider Value: {vbatresdivval}, "
            f"Divider Multiplier: {vbatresdivmultiplier}, "
            f"Max Cell: {vbatmaxcellvoltage/10.0}V, "
            f"Min Cell: {vbatmincellvoltage/10.0}V, "
            f"Warning Cell: {vbatwarningcellvoltage/10.0}V")

# ---------------------------
# MSP_FAILSAFE_CONFIG
# ---------------------------
def decode_msp_failsafe_config_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Failsafe Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_failsafe_config_response(payload: bytes) -> str:
    """
    Decodes the failsafe configuration response.
    
    Payload format from betaflight/src/main/fc/rc_modes.h:
    uint8_t failsafe_delay;                 // Guard time for failsafe activation
    uint8_t failsafe_off_delay;            // Delay before turning off motors
    uint16_t failsafe_throttle;            // Throttle level used for landing
    uint8_t failsafe_kill_switch;          // Enable failsafe kill switch
    uint16_t failsafe_throttle_low_delay;  // Delay before landing
    uint8_t failsafe_procedure;            // Failsafe procedure type
    """
    if len(payload) < 8:
        return MSG_INVALID_PAYLOAD

    failsafe_delay = payload[0]
    failsafe_off_delay = payload[1]
    failsafe_throttle = int.from_bytes(payload[2:4], 'little')
    failsafe_kill_switch = payload[4]
    failsafe_throttle_low_delay = int.from_bytes(payload[5:7], 'little')
    failsafe_procedure = payload[7]

    # Failsafe procedure types
    procedures = {
        0: "DROP",
        1: "LAND",
        2: "RTH"  # Return to home
    }

    procedure_name = procedures.get(failsafe_procedure, f"UNKNOWN({failsafe_procedure})")

    return (f"Delay: {failsafe_delay/10.0}s, "
            f"Off Delay: {failsafe_off_delay/10.0}s, "
            f"Throttle: {failsafe_throttle}, "
            f"Kill Switch: {'Enabled' if failsafe_kill_switch else 'Disabled'}, "
            f"Throttle Low Delay: {failsafe_throttle_low_delay/10.0}s, "
            f"Procedure: {procedure_name}")

# ---------------------------
# MSP_RXFAIL_CONFIG
# ---------------------------
def decode_msp_rxfail_config_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request RX Fail Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_rxfail_config_response(payload: bytes) -> str:
    """
    Decodes the RX fail configuration response.
    
    Payload format from betaflight/src/main/rx/rx.h:
    struct {
        uint8_t mode;           // Channel failsafe mode
        uint16_t value;         // Channel failsafe value
    } channels[];
    """
    if len(payload) < 3:
        return MSG_INVALID_PAYLOAD

    channels = []
    for i in range(0, len(payload), 3):
        if i + 2 >= len(payload):
            break
        mode = payload[i]
        value = int.from_bytes(payload[i+1:i+3], 'little')

        # Failsafe modes
        modes = {
            0: "AUTO",
            1: "HOLD",
            2: "SET",
            3: "INVALID"
        }

        mode_name = modes.get(mode, f"UNKNOWN({mode})")
        channels.append(f"CH{i//3 + 1}: {mode_name}={value}")

    return ", ".join(channels)

# ---------------------------
# MSP_GPS_RESCUE
# ---------------------------
def decode_msp_gps_rescue_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request GPS Rescue Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_gps_rescue_response(payload: bytes) -> str:
    """
    Decodes the GPS rescue configuration response.
    
    Payload format from betaflight/src/main/flight/gps_rescue.h:
    uint16_t angle;             // Max angle for GPS rescue
    uint16_t initialAltitude;   // Initial altitude in cm
    uint16_t descentDistance;   // Distance to start descent
    uint16_t groundSpeed;       // Ground speed during rescue
    uint16_t throttleMin;       // Minimum throttle during rescue
    uint16_t throttleMax;       // Maximum throttle during rescue
    uint16_t throttleHover;     // Hover throttle during rescue
    uint8_t sanityChecks;       // Enable sanity checks
    uint8_t minSats;           // Minimum number of satellites required
    """
    if len(payload) < 17:
        return MSG_INVALID_PAYLOAD

    angle = int.from_bytes(payload[0:2], 'little')
    initial_altitude = int.from_bytes(payload[2:4], 'little')
    descent_distance = int.from_bytes(payload[4:6], 'little')
    ground_speed = int.from_bytes(payload[6:8], 'little')
    throttle_min = int.from_bytes(payload[8:10], 'little')
    throttle_max = int.from_bytes(payload[10:12], 'little')
    throttle_hover = int.from_bytes(payload[12:14], 'little')
    sanity_checks = payload[14]
    min_sats = payload[15]

    # Sanity check flags
    checks = []
    if sanity_checks & (1 << 0): checks.append("THROTTLE")
    if sanity_checks & (1 << 1): checks.append("ALTITUDE")
    if sanity_checks & (1 << 2): checks.append("GPS_FIX")
    if sanity_checks & (1 << 3): checks.append("GPS_TIMEOUT")

    return (f"Max Angle: {angle/10.0}°, "
            f"Initial Alt: {initial_altitude}cm, "
            f"Descent Dist: {descent_distance}m, "
            f"Ground Speed: {ground_speed}cm/s, "
            f"Throttle Min: {throttle_min}, "
            f"Throttle Max: {throttle_max}, "
            f"Throttle Hover: {throttle_hover}, "
            f"Sanity Checks: {', '.join(checks) if checks else 'None'}, "
            f"Min Satellites: {min_sats}")

# ---------------------------
# MSP_MODE_RANGES
# ---------------------------
def decode_msp_mode_ranges_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Mode Ranges"
    return MSG_INVALID_PAYLOAD

def decode_msp_mode_ranges_response(payload: bytes) -> str:
    """
    Decodes the mode ranges response.
    
    Payload format from betaflight/src/main/fc/rc_modes.h:
    struct {
        uint8_t box_id;         // Mode ID
        uint8_t aux_channel_index; // AUX channel index (0 based)
        uint8_t start_step;     // Start step (0-48)
        uint8_t end_step;       // End step (0-48)
    } ranges[];
    """
    if len(payload) < 4:
        return MSG_INVALID_PAYLOAD

    ranges = []
    for i in range(0, len(payload), 4):
        if i + 3 >= len(payload):
            break
        box_id = payload[i]
        aux_channel = payload[i + 1]
        start_step = payload[i + 2]
        end_step = payload[i + 3]

        # Mode names (box IDs)
        modes = {
            0: "ARM",
            1: "ANGLE",
            2: "HORIZON",
            3: "BARO",
            4: "ANTIGRAVITY",
            5: "MAG",
            6: "HEADFREE",
            7: "HEADADJ",
            8: "CAMSTAB",
            9: "CAMTRIG",
            10: "GPSHOME",
            11: "GPSHOLD",
            12: "PASSTHRU",
            13: "BEEPER",
            14: "LEDMAX",
            15: "LEDLOW",
            16: "LLIGHTS",
            17: "CALIB",
            18: "GOV",
            19: "OSD",
            20: "TELEMETRY",
            21: "GTUNE",
            22: "SONAR",
            23: "SERVO1",
            24: "SERVO2",
            25: "SERVO3",
            26: "BLACKBOX",
            27: "FAILSAFE",
            28: "AIRMODE",
            29: "3D",
            30: "FPV_ANGLE_MIX",
            31: "BLACKBOX_ERASE",
            32: "CAMERA_CONTROL_1",
            33: "CAMERA_CONTROL_2",
            34: "CAMERA_CONTROL_3",
            35: "FLIP_OVER_AFTER_CRASH",
            36: "BOXPREARM",
            37: "BEEPER_MUTE"
        }

        mode_name = modes.get(box_id, f"MODE_{box_id}")
        ranges.append(f"{mode_name}: AUX{aux_channel + 1} [{start_step}-{end_step}]")

    return ", ".join(ranges)

# ---------------------------
# MSP_CURRENT_METERS
# ---------------------------
def decode_msp_current_meters_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Current Meters"
    return MSG_INVALID_PAYLOAD

def decode_msp_current_meters_response(payload: bytes) -> str:
    """
    Decodes the current meters response.
    
    Payload format from betaflight/src/main/sensors/current.h:
    struct {
        uint8_t id;                 // Current meter ID
        uint16_t amperage;          // Current in 0.01A steps
        uint16_t mAhDrawn;          // Capacity drawn in mAh
    } meters[];
    """
    if len(payload) < 5:  # Each meter needs 5 bytes
        return MSG_INVALID_PAYLOAD

    meters = []
    for i in range(0, len(payload), 5):
        if i + 4 >= len(payload):
            break
        meter_id = payload[i]
        amperage = int.from_bytes(payload[i+1:i+3], 'little')
        mah_drawn = int.from_bytes(payload[i+3:i+5], 'little')
        meters.append(f"Meter {meter_id}: Current={amperage/100.0:.2f}A, Drawn={mah_drawn}mAh")

    return ", ".join(meters)

# ---------------------------
# MSP_RSSI_CONFIG
# ---------------------------
def decode_msp_rssi_config_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request RSSI Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_rssi_config_response(payload: bytes) -> str:
    """
    Decodes the RSSI configuration response.
    
    Payload format from betaflight/src/main/rx/rx.h:
    uint8_t channel;           // RSSI ADC channel
    uint8_t scale;            // RSSI scale factor
    uint8_t offset;           // RSSI offset
    uint8_t type;            // RSSI type (ADC, PROTOCOL, etc)
    """
    if len(payload) < 4:
        return MSG_INVALID_PAYLOAD

    channel = payload[0]
    scale = payload[1]
    offset = payload[2]
    rssi_type = payload[3]

    # RSSI type names
    types = {
        0: "NONE",
        1: "ADC",
        2: "PROTOCOL",
        3: "RX_CHANNEL"
    }

    type_name = types.get(rssi_type, f"UNKNOWN({rssi_type})")
    return (f"Channel: {channel}, "
            f"Scale: {scale}, "
            f"Offset: {offset}, "
            f"Type: {type_name}")

# ---------------------------
# MSP_GPS_CONFIG
# ---------------------------
def decode_msp_gps_config_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request GPS Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_gps_config_response(payload: bytes) -> str:
    """
    Decodes the GPS configuration response.
    
    Payload format from betaflight/src/main/io/gps.h:
    uint8_t provider;          // GPS provider
    uint8_t sbas_mode;        // SBAS mode
    uint8_t auto_config;      // Auto configuration
    uint8_t auto_baud;        // Auto baud rate
    """
    if len(payload) < 4:
        return MSG_INVALID_PAYLOAD

    provider = payload[0]
    sbas_mode = payload[1]
    auto_config = payload[2]
    auto_baud = payload[3]

    # GPS provider names
    providers = {
        0: "NMEA",
        1: "UBLOX",
        2: "MSP"
    }

    # SBAS mode names
    sbas_modes = {
        0: "AUTO",
        1: "EGNOS",
        2: "WAAS",
        3: "MSAS",
        4: "GAGAN",
        5: "NONE"
    }

    provider_name = providers.get(provider, f"UNKNOWN({provider})")
    sbas_name = sbas_modes.get(sbas_mode, f"UNKNOWN({sbas_mode})")

    return (f"Provider: {provider_name}, "
            f"SBAS Mode: {sbas_name}, "
            f"Auto Config: {'Yes' if auto_config else 'No'}, "
            f"Auto Baud: {'Yes' if auto_baud else 'No'}")

# ---------------------------
# MSP_PIDNAMES
# ---------------------------
def decode_msp_pidnames_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request PID Names"
    return MSG_INVALID_PAYLOAD

def decode_msp_pidnames_response(payload: bytes) -> str:
    """
    Decodes the PID names response.
    The payload is a semicolon-separated ASCII string containing PID names.
    """
    try:
        text = payload.decode('ascii', 'replace').rstrip('\x00')
        names = [name for name in text.split(';') if name]
        return f"PID Names: {', '.join(names)}"
    except:
        return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP_PID
# ---------------------------
def decode_msp_pid_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request PID Values"
    return MSG_INVALID_PAYLOAD

def decode_msp_pid_response(payload: bytes) -> str:
    """
    Decodes the PID values response.
    
    Payload format:
    struct {
        uint8_t P;            // P term
        uint8_t I;            // I term
        uint8_t D;            // D term
    } pids[9];               // ROLL, PITCH, YAW, ALT, POS, POSR, NAVR, LEVEL, MAG
    """
    if len(payload) < 27:  # 9 PIDs * 3 values
        return MSG_INVALID_PAYLOAD

    pid_names = [
        "ROLL", "PITCH", "YAW",
        "ALT", "POS", "POSR",
        "NAVR", "LEVEL", "MAG"
    ]

    pids = []
    for i in range(0, min(len(payload), 27), 3):
        if i//3 >= len(pid_names):
            break
        p = payload[i]
        i_term = payload[i+1]
        d = payload[i+2]
        pids.append(f"{pid_names[i//3]}: P={p} I={i_term} D={d}")

    return ", ".join(pids)

# ---------------------------
# MSP_PID_ADVANCED
# ---------------------------
def decode_msp_pid_advanced_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Advanced PID Settings"
    return MSG_INVALID_PAYLOAD

def decode_msp_pid_advanced_response(payload: bytes) -> str:
    """
    Decodes the advanced PID settings response.
    
    Payload format from betaflight/src/main/fc/controlrate_profile.h:
    uint16_t rollPitchItermIgnoreRate;  // Iterm ignore rate for roll/pitch
    uint16_t yawItermIgnoreRate;        // Iterm ignore rate for yaw
    uint16_t yaw_p_limit;               // Yaw P limit
    uint8_t deltaMethod;                // Delta calculation method
    uint8_t vbatPidCompensation;        // VBAT PID compensation
    uint8_t setpointRelaxRatio;         // Setpoint relax ratio
    uint8_t dtermSetpointWeight;        // Dterm setpoint weight
    uint8_t levelAngleLimit;            // Level mode angle limit
    uint8_t levelSensitivity;           // Level mode sensitivity
    """
    if len(payload) < 11:
        return MSG_INVALID_PAYLOAD

    index = 0
    roll_pitch_iterm_ignore = int.from_bytes(payload[index:index+2], 'little')
    index += 2
    yaw_iterm_ignore = int.from_bytes(payload[index:index+2], 'little')
    index += 2
    yaw_p_limit = int.from_bytes(payload[index:index+2], 'little')
    index += 2
    delta_method = payload[index]
    index += 1
    vbat_compensation = payload[index]
    index += 1
    setpoint_relax = payload[index]
    index += 1
    dterm_setpoint = payload[index]
    index += 1
    level_angle_limit = payload[index]
    index += 1
    level_sensitivity = payload[index]

    # Delta method names
    methods = {
        0: "ERROR",
        1: "MEASUREMENT"
    }
    method_name = methods.get(delta_method, f"UNKNOWN({delta_method})")

    return (f"Roll/Pitch Iterm Ignore: {roll_pitch_iterm_ignore}, "
            f"Yaw Iterm Ignore: {yaw_iterm_ignore}, "
            f"Yaw P Limit: {yaw_p_limit}, "
            f"Delta Method: {method_name}, "
            f"VBAT Compensation: {'On' if vbat_compensation else 'Off'}, "
            f"Setpoint Relax: {setpoint_relax}, "
            f"Dterm Setpoint: {dterm_setpoint}, "
            f"Level Angle Limit: {level_angle_limit}°, "
            f"Level Sensitivity: {level_sensitivity}")

# ---------------------------
# MSP_FILTER_CONFIG
# ---------------------------
def decode_msp_filter_config_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Filter Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_filter_config_response(payload: bytes) -> str:
    """
    Decodes the filter configuration response.
    
    Payload format from betaflight/src/main/fc/config.h:
    uint8_t gyro_lowpass_hz;           // Gyro soft lowpass filter Hz
    uint16_t dterm_lowpass_hz;         // Dterm lowpass filter Hz
    uint16_t yaw_lowpass_hz;           // Yaw lowpass filter Hz
    uint8_t gyro_notch_hz;             // Gyro notch filter Hz
    uint8_t gyro_notch_cutoff;         // Gyro notch filter cutoff
    uint16_t dterm_notch_hz;           // Dterm notch filter Hz
    uint16_t dterm_notch_cutoff;       // Dterm notch filter cutoff
    uint16_t gyro_lowpass2_hz;         // Gyro soft lowpass 2 filter Hz
    uint8_t debug_mode;                // Debug mode
    """
    if len(payload) < 13:
        return MSG_INVALID_PAYLOAD

    index = 0
    gyro_lowpass = payload[index]
    index += 1
    dterm_lowpass = int.from_bytes(payload[index:index+2], 'little')
    index += 2
    yaw_lowpass = int.from_bytes(payload[index:index+2], 'little')
    index += 2
    gyro_notch = payload[index]
    index += 1
    gyro_notch_cutoff = payload[index]
    index += 1
    dterm_notch = int.from_bytes(payload[index:index+2], 'little')
    index += 2
    dterm_notch_cutoff = int.from_bytes(payload[index:index+2], 'little')
    index += 2
    gyro_lowpass2 = int.from_bytes(payload[index:index+2], 'little')
    index += 2
    debug_mode = payload[index]

    return (f"Gyro Lowpass: {gyro_lowpass}Hz, "
            f"Dterm Lowpass: {dterm_lowpass}Hz, "
            f"Yaw Lowpass: {yaw_lowpass}Hz, "
            f"Gyro Notch: {gyro_notch}Hz, "
            f"Gyro Notch Cutoff: {gyro_notch_cutoff}Hz, "
            f"Dterm Notch: {dterm_notch}Hz, "
            f"Dterm Notch Cutoff: {dterm_notch_cutoff}Hz, "
            f"Gyro Lowpass2: {gyro_lowpass2}Hz, "
            f"Debug Mode: {debug_mode}")

# ---------------------------
# MSP_LED_COLORS
# ---------------------------
def decode_msp_led_colors_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request LED Colors"
    return MSG_INVALID_PAYLOAD

def decode_msp_led_colors_response(payload: bytes) -> str:
    """
    Decodes the LED colors response.
    
    Payload format from betaflight/src/main/io/ledstrip.h:
    struct {
        uint16_t h;           // Hue
        uint8_t s;           // Saturation
        uint8_t v;           // Value
    } colors[16];
    """
    if len(payload) < 4:  # Each color needs 4 bytes
        return MSG_INVALID_PAYLOAD

    colors = []
    for i in range(0, len(payload), 4):
        if i + 3 >= len(payload):
            break
        hue = int.from_bytes(payload[i:i+2], 'little')
        sat = payload[i+2]
        val = payload[i+3]
        colors.append(f"Color {i//4}: H={hue}, S={sat}, V={val}")

    return ", ".join(colors)

# ---------------------------
# MSP_ADJUSTMENT_RANGES
# ---------------------------
def decode_msp_adjustment_ranges_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Adjustment Ranges"
    return MSG_INVALID_PAYLOAD

def decode_msp_adjustment_ranges_response(payload: bytes) -> str:
    """
    Decodes the adjustment ranges response.
    
    Payload format from betaflight/src/main/fc/rc_adjustments.h:
    struct {
        uint8_t adjustmentIndex;     // Index of the adjustment
        uint8_t auxChannelIndex;     // AUX channel index
        uint8_t range;               // Range (start/end)
        uint8_t adjustmentFunction;  // Function to adjust
        uint8_t auxSwitchChannelIndex; // Switch channel
    } ranges[];
    """
    if len(payload) < 5:  # Each range needs 5 bytes
        return MSG_INVALID_PAYLOAD

    # Adjustment function names
    functions = {
        0: "NONE",
        1: "RC_RATE",
        2: "RC_EXPO",
        3: "THROTTLE_EXPO",
        4: "PITCH_ROLL_RATE",
        5: "YAW_RATE",
        6: "PITCH_ROLL_P",
        7: "PITCH_ROLL_I",
        8: "PITCH_ROLL_D",
        9: "YAW_P",
        10: "YAW_I",
        11: "YAW_D",
        12: "RATE_PROFILE",
        13: "PITCH_RATE",
        14: "ROLL_RATE",
        15: "PITCH_P",
        16: "PITCH_I",
        17: "PITCH_D",
        18: "ROLL_P",
        19: "ROLL_I",
        20: "ROLL_D"
    }

    ranges = []
    for i in range(0, len(payload), 5):
        if i + 4 >= len(payload):
            break
        adj_index = payload[i]
        aux_channel = payload[i+1]
        range_val = payload[i+2]
        adj_function = payload[i+3]
        switch_channel = payload[i+4]

        function_name = functions.get(adj_function, f"UNKNOWN({adj_function})")
        ranges.append(f"Range {adj_index}: AUX{aux_channel+1}, {function_name}, Switch=AUX{switch_channel+1}, Range={range_val}")

    return ", ".join(ranges)

# ---------------------------
# MSP_CF_SERIAL_CONFIG
# ---------------------------
def decode_msp_cf_serial_config_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Serial Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_cf_serial_config_response(payload: bytes) -> str:
    """
    Decodes the serial configuration response.
    
    Payload format from betaflight/src/main/io/serial.h:
    struct {
        uint8_t identifier;        // Port identifier
        uint16_t functionMask;     // Function mask
        uint8_t mspBaudrate;      // MSP baudrate index
        uint8_t gpsBaudrate;      // GPS baudrate index
        uint8_t telemetryBaudrate;// Telemetry baudrate index
        uint8_t peripheralBaudrate;// Peripheral baudrate index
    } ports[];
    """
    if len(payload) < 7:  # Each port needs 7 bytes
        return MSG_INVALID_PAYLOAD

    # Port identifier names
    port_names = {
        0: "UART1",
        1: "UART2",
        2: "UART3",
        3: "UART4",
        4: "UART5",
        5: "UART6",
        20: "USB VCP"
    }

    # Baudrate names
    baudrates = {
        0: "AUTO",
        1: "9600",
        2: "19200",
        3: "38400",
        4: "57600",
        5: "115200",
        6: "230400",
        7: "250000",
        8: "400000",
        9: "460800",
        10: "500000",
        11: "921600",
        12: "1000000",
        13: "1500000",
        14: "2000000",
        15: "2470000"
    }

    ports = []
    for i in range(0, len(payload), 7):
        if i + 6 >= len(payload):
            break
        identifier = payload[i]
        functions = int.from_bytes(payload[i+1:i+3], 'little')
        msp_baud = payload[i+3]
        gps_baud = payload[i+4]
        telem_baud = payload[i+5]
        periph_baud = payload[i+6]

        # Decode function mask
        funcs = []
        if functions & (1 << 0): funcs.append("MSP")
        if functions & (1 << 1): funcs.append("GPS")
        if functions & (1 << 2): funcs.append("TELEMETRY")
        if functions & (1 << 3): funcs.append("BLACKBOX")
        if functions & (1 << 4): funcs.append("SERIAL_RX")
        if functions & (1 << 5): funcs.append("ESC_SENSOR")

        port_name = port_names.get(identifier, f"PORT_{identifier}")
        msp_baud_name = baudrates.get(msp_baud, f"{msp_baud}")
        gps_baud_name = baudrates.get(gps_baud, f"{gps_baud}")
        telem_baud_name = baudrates.get(telem_baud, f"{telem_baud}")
        periph_baud_name = baudrates.get(periph_baud, f"{periph_baud}")

        ports.append(f"{port_name}: {', '.join(funcs)}, MSP={msp_baud_name}, GPS={gps_baud_name}, "
                    f"Telem={telem_baud_name}, Periph={periph_baud_name}")

    return "\n".join(ports)

# ---------------------------
# MSP_RX_MAP
# ---------------------------
def decode_msp_rx_map_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request RX Channel Map"
    return MSG_INVALID_PAYLOAD

def decode_msp_rx_map_response(payload: bytes) -> str:
    """
    Decodes the RX channel mapping response.
    
    Payload format from betaflight/src/main/rx/rx.h:
    uint8_t map[4];  // Channel map (AETR1234)
    """
    if len(payload) < 4:
        return MSG_INVALID_PAYLOAD

    # Channel names
    channel_names = ["ROLL", "PITCH", "THROTTLE", "YAW"]
    
    mappings = []
    for i in range(4):
        channel = payload[i]
        mappings.append(f"{channel_names[i]} -> CH{channel+1}")

    return ", ".join(mappings)

# ---------------------------
# MSP_BF_CONFIG
# ---------------------------
def decode_msp_bf_config_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Betaflight Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_bf_config_response(payload: bytes) -> str:
    """
    Decodes the Betaflight configuration response.
    
    Payload format from betaflight/src/main/fc/config.h:
    uint8_t mixerMode;             // Mixer mode
    uint32_t features;             // Active features
    uint8_t serialrx_type;         // Serial RX type
    uint16_t board_align_roll;     // Board alignment roll
    uint16_t board_align_pitch;    // Board alignment pitch
    uint16_t board_align_yaw;      // Board alignment yaw
    uint16_t currentscale;         // Current meter scale
    uint16_t currentoffset;        // Current meter offset
    """
    if len(payload) < 15:
        return MSG_INVALID_PAYLOAD

    index = 0
    mixer_mode = payload[index]
    index += 1
    features = int.from_bytes(payload[index:index+4], 'little')
    index += 4
    serialrx_type = payload[index]
    index += 1
    board_align_roll = int.from_bytes(payload[index:index+2], 'little')
    index += 2
    board_align_pitch = int.from_bytes(payload[index:index+2], 'little')
    index += 2
    board_align_yaw = int.from_bytes(payload[index:index+2], 'little')
    index += 2
    currentscale = int.from_bytes(payload[index:index+2], 'little')
    index += 2
    currentoffset = int.from_bytes(payload[index:index+2], 'little')

    # Mixer mode names
    mixer_modes = {
        0: "TRI",
        1: "QUADP",
        2: "QUADX",
        3: "BI",
        4: "GIMBAL",
        5: "Y6",
        6: "HEX6",
        7: "FLYING_WING",
        8: "Y4",
        9: "HEX6X",
        10: "OCTOX8",
        11: "OCTOFLATP",
        12: "OCTOFLATX",
        13: "AIRPLANE",
        14: "HELI_120_CCPM",
        15: "HELI_90_DEG",
        16: "VTAIL4",
        17: "HEX6H",
        18: "PPM_TO_SERVO",
        19: "DUALCOPTER",
        20: "SINGLECOPTER",
        21: "ATAIL4",
        22: "CUSTOM",
        23: "CUSTOM_AIRPLANE",
        24: "CUSTOM_TRI"
    }

    # Serial RX type names
    serialrx_types = {
        0: "SPEK1024",
        1: "SPEK2048",
        2: "SBUS",
        3: "SUMD",
        4: "SUMH",
        5: "XBUS_MODE_B",
        6: "XBUS_MODE_B_RJ01",
        7: "IBUS",
        8: "JETIEXBUS",
        9: "CRSF",
        10: "SRXL",
        11: "CUSTOM",
        12: "FPORT"
    }

    # Decode features
    active_features = []
    if features & (1 << 0): active_features.append("RX_PPM")
    if features & (1 << 2): active_features.append("INFLIGHT_ACC_CAL")
    if features & (1 << 3): active_features.append("RX_SERIAL")
    if features & (1 << 4): active_features.append("MOTOR_STOP")
    if features & (1 << 5): active_features.append("SERVO_TILT")
    if features & (1 << 6): active_features.append("SOFTSERIAL")
    if features & (1 << 7): active_features.append("GPS")
    if features & (1 << 9): active_features.append("SONAR")
    if features & (1 << 10): active_features.append("TELEMETRY")
    if features & (1 << 12): active_features.append("3D")
    if features & (1 << 13): active_features.append("RX_PARALLEL_PWM")
    if features & (1 << 14): active_features.append("RX_MSP")
    if features & (1 << 15): active_features.append("RSSI_ADC")
    if features & (1 << 16): active_features.append("LED_STRIP")
    if features & (1 << 17): active_features.append("DISPLAY")
    if features & (1 << 20): active_features.append("CHANNEL_FORWARDING")
    if features & (1 << 21): active_features.append("TRANSPONDER")
    if features & (1 << 22): active_features.append("AIRMODE")

    mixer_name = mixer_modes.get(mixer_mode, f"UNKNOWN({mixer_mode})")
    serialrx_name = serialrx_types.get(serialrx_type, f"UNKNOWN({serialrx_type})")

    return (f"Mixer: {mixer_name}\n"
            f"Features: {', '.join(active_features)}\n"
            f"Serial RX: {serialrx_name}\n"
            f"Board Alignment: Roll={board_align_roll}°, Pitch={board_align_pitch}°, Yaw={board_align_yaw}°\n"
            f"Current Meter: Scale={currentscale}, Offset={currentoffset}")

# ---------------------------
# MSP_LOOP_TIME
# ---------------------------
def decode_msp_loop_time_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Loop Time"
    return MSG_INVALID_PAYLOAD

def decode_msp_loop_time_response(payload: bytes) -> str:
    """
    Decodes the loop time response.
    
    Payload format:
    uint16_t looptime;  // Main loop time in microseconds
    """
    if len(payload) < 2:
        return MSG_INVALID_PAYLOAD

    looptime = int.from_bytes(payload[0:2], 'little')
    return f"Loop Time: {looptime}µs"

# ---------------------------
# MSP_TRANSPONDER_CONFIG
# ---------------------------
def decode_msp_transponder_config_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Transponder Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_transponder_config_response(payload: bytes) -> str:
    """
    Decodes the transponder configuration response.
    
    Payload format from betaflight/src/main/io/transponder.h:
    uint8_t provider;              // Transponder provider
    uint8_t data[32];             // Transponder data
    """
    if len(payload) < 33:
        return MSG_INVALID_PAYLOAD

    provider = payload[0]
    data = payload[1:33]

    # Provider names
    providers = {
        0: "NONE",
        1: "ILAP",
        2: "ARCITIMER",
        3: "ERLT"
    }

    provider_name = providers.get(provider, f"UNKNOWN({provider})")
    return f"Provider: {provider_name}, Data: {data.hex()}"

# ---------------------------
# MSP_OSD_CONFIG
# ---------------------------
def decode_msp_osd_config_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request OSD Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_osd_config_response(payload: bytes) -> str:
    """
    Decodes the OSD configuration response.
    
    Payload format from betaflight/src/main/io/osd.h:
    uint8_t osdFlags;             // OSD feature flags
    uint8_t videoSystem;          // Video system (PAL/NTSC)
    uint8_t units;                // Units (metric/imperial)
    uint8_t rssi_alarm;          // RSSI alarm threshold
    uint16_t cap_alarm;          // Capacity alarm threshold
    uint8_t timer[OSD_TIMER_COUNT];// OSD timers
    uint16_t alt_alarm;          // Altitude alarm threshold
    uint16_t osd_items[OSD_ITEM_COUNT];// OSD item positions
    uint16_t alarms;             // OSD alarms
    """
    if len(payload) < 10:  # Minimum size for basic config
        return MSG_INVALID_PAYLOAD

    index = 0
    osd_flags = payload[index]
    index += 1
    video_system = payload[index]
    index += 1
    units = payload[index]
    index += 1
    rssi_alarm = payload[index]
    index += 1
    cap_alarm = int.from_bytes(payload[index:index+2], 'little')
    index += 2

    # Video system names
    video_systems = {
        0: "AUTO",
        1: "PAL",
        2: "NTSC"
    }

    # Decode flags
    flags = []
    if osd_flags & (1 << 0): flags.append("ENABLED")
    if osd_flags & (1 << 1): flags.append("VIDEO_TYPES")
    if osd_flags & (1 << 2): flags.append("DISPLAY_VOLTAGE")
    if osd_flags & (1 << 3): flags.append("DISPLAY_RSSI")
    if osd_flags & (1 << 4): flags.append("DISPLAY_TIMER")
    if osd_flags & (1 << 5): flags.append("DISPLAY_PID")
    if osd_flags & (1 << 6): flags.append("DISPLAY_RC")
    if osd_flags & (1 << 7): flags.append("DISPLAY_CURRENT")

    video_name = video_systems.get(video_system, f"UNKNOWN({video_system})")

    return (f"Flags: {', '.join(flags)}\n"
            f"Video System: {video_name}\n"
            f"Units: {'Metric' if units == 0 else 'Imperial'}\n"
            f"RSSI Alarm: {rssi_alarm}%\n"
            f"Capacity Alarm: {cap_alarm}mAh")

# ---------------------------
# MSP_CAMERA_CONTROL
# ---------------------------
def decode_msp_camera_control_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Camera Control"
    return MSG_INVALID_PAYLOAD

def decode_msp_camera_control_response(payload: bytes) -> str:
    """
    Decodes the camera control response.
    
    Payload format from betaflight/src/main/io/camera.h:
    uint8_t key;                  // Camera control key
    """
    if len(payload) < 1:
        return MSG_INVALID_PAYLOAD

    key = payload[0]

    # Key names
    keys = {
        0: "NONE",
        1: "ENTER",
        2: "LEFT",
        3: "RIGHT",
        4: "UP",
        5: "DOWN",
        6: "POWER"
    }

    key_name = keys.get(key, f"UNKNOWN({key})")
    return f"Camera Key: {key_name}"

# ---------------------------
# MSP_SIMPLIFIED_TUNING
# ---------------------------
def decode_msp_simplified_tuning_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Simplified Tuning Values"
    return MSG_INVALID_PAYLOAD

def decode_msp_simplified_tuning_response(payload: bytes) -> str:
    """
    Decodes the simplified tuning response.
    
    Payload format from betaflight/src/main/fc/rc_modes.h:
    uint8_t simplified_pids_mode;  // 0=OFF, 1=RP, 2=RPY
    uint8_t simplified_master_multiplier;  // 0-200%
    uint8_t simplified_roll_pitch_ratio;  // 0-200%
    uint8_t simplified_i_gain;  // 0-200%
    uint8_t simplified_d_gain;  // 0-200%
    uint8_t simplified_pi_gain;  // 0-200%
    uint8_t simplified_dmin_ratio;  // 0-200%
    uint8_t simplified_feedforward_gain;  // 0-200%
    uint8_t simplified_pitch_pi_gain;  // 0-200%
    uint8_t simplified_dterm_filter;  // 0-200%
    uint8_t simplified_dterm_filter_multiplier;  // 0-200%
    uint8_t simplified_gyro_filter;  // 0-200%
    uint8_t simplified_gyro_filter_multiplier;  // 0-200%
    """
    if len(payload) < 13:
        return MSG_INVALID_PAYLOAD

    # PID mode names
    pid_modes = {
        0: "OFF",
        1: "ROLL_PITCH",
        2: "ROLL_PITCH_YAW"
    }

    mode = payload[0]
    master_mult = payload[1]
    roll_pitch_ratio = payload[2]
    i_gain = payload[3]
    d_gain = payload[4]
    pi_gain = payload[5]
    dmin_ratio = payload[6]
    ff_gain = payload[7]
    pitch_pi_gain = payload[8]
    dterm_filter = payload[9]
    dterm_filter_mult = payload[10]
    gyro_filter = payload[11]
    gyro_filter_mult = payload[12]

    mode_name = pid_modes.get(mode, f"UNKNOWN({mode})")

    return (f"Mode: {mode_name}\n"
            f"Master Multiplier: {master_mult}%\n"
            f"Roll/Pitch Ratio: {roll_pitch_ratio}%\n"
            f"I Gain: {i_gain}%\n"
            f"D Gain: {d_gain}%\n"
            f"PI Gain: {pi_gain}%\n"
            f"D Min Ratio: {dmin_ratio}%\n"
            f"Feedforward Gain: {ff_gain}%\n"
            f"Pitch PI Gain: {pitch_pi_gain}%\n"
            f"D Term Filter: {dterm_filter}%\n"
            f"D Term Filter Multiplier: {dterm_filter_mult}%\n"
            f"Gyro Filter: {gyro_filter}%\n"
            f"Gyro Filter Multiplier: {gyro_filter_mult}%")

# ---------------------------
# MSP_SET_SIMPLIFIED_TUNING
# ---------------------------
def decode_msp_set_simplified_tuning_request(payload: bytes) -> str:
    if len(payload) < 13:
        return MSG_INVALID_PAYLOAD

    mode = payload[0]
    master_mult = payload[1]
    roll_pitch_ratio = payload[2]
    i_gain = payload[3]
    d_gain = payload[4]
    pi_gain = payload[5]
    dmin_ratio = payload[6]
    ff_gain = payload[7]

    return f"Set Simplified Tuning: Mode={mode}, Master Mult={master_mult}%, Roll/Pitch Ratio={roll_pitch_ratio}%, I Gain={i_gain}%, D Gain={d_gain}%, PI Gain={pi_gain}%, D Min Ratio={dmin_ratio}%, Feedforward Gain={ff_gain}%"

# ---------------------------
# MSP_VALIDATE_SIMPLIFIED_TUNING
# ---------------------------
def decode_msp_validate_simplified_tuning_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for Simplified Tuning Validation"
    return MSG_INVALID_PAYLOAD

def decode_msp_validate_simplified_tuning_response(payload: bytes) -> str:
    """
    Decodes the simplified tuning validation response.
    Returns three validation results:
    1. PID validation (P, I, D, D_max, F for all axes)
    2. Gyro filter validation (static LPF1/2 and dynamic LPF)
    3. D-term filter validation (static LPF1/2 and dynamic LPF)
    """
    if len(payload) == 3:
        pid_valid = bool(payload[0])
        gyro_valid = bool(payload[1])
        dterm_valid = bool(payload[2])
        
        return (f"PID Validation: {'Valid' if pid_valid else 'Invalid'} (0x{payload[0]:02X})\n"
                f"Gyro Filter Validation: {'Valid' if gyro_valid else 'Invalid'} (0x{payload[1]:02X})\n"
                f"D-term Filter Validation: {'Valid' if dterm_valid else 'Invalid'} (0x{payload[2]:02X})")
    return MSG_INVALID_PAYLOAD

def decode_msp_mode_ranges_extra_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Mode Ranges Extra"
    return MSG_INVALID_PAYLOAD

def decode_msp_mode_ranges_extra_response(payload: bytes) -> str:
    """
    Decodes the mode ranges extra response.
    
    Payload format from betaflight/src/main/fc/rc_modes.h:
    struct {
        uint8_t id;                  // Mode ID
        uint8_t auxChannelIndex;     // AUX channel index (0 based)
        uint8_t startStep;           // Start step (0-48)
        uint8_t endStep;             // End step (0-48)
        uint8_t modeLogic;          // Mode logic (AND, OR)
        uint8_t linkedTo;           // Linked to another mode
    } ranges[];
    """
    if len(payload) < 6:  # Each range needs 6 bytes
        return MSG_INVALID_PAYLOAD

    ranges = []
    for i in range(0, len(payload), 6):
        if i + 5 >= len(payload):
            break
        mode_id = payload[i]
        aux_channel = payload[i + 1]
        start_step = payload[i + 2]
        end_step = payload[i + 3]
        mode_logic = payload[i + 4]
        linked_to = payload[i + 5]

        # Mode names (box IDs)
        modes = {
            0: "ARM",
            1: "ANGLE",
            2: "HORIZON",
            3: "BARO",
            4: "ANTIGRAVITY",
            5: "MAG",
            6: "HEADFREE",
            7: "HEADADJ",
            8: "CAMSTAB",
            9: "CAMTRIG",
            10: "GPSHOME",
            11: "GPSHOLD",
            12: "PASSTHRU",
            13: "BEEPER",
            14: "LEDMAX",
            15: "LEDLOW",
            16: "LLIGHTS",
            17: "CALIB",
            18: "GOV",
            19: "OSD",
            20: "TELEMETRY",
            21: "GTUNE",
            22: "SONAR",
            23: "SERVO1",
            24: "SERVO2",
            25: "SERVO3",
            26: "BLACKBOX",
            27: "FAILSAFE",
            28: "AIRMODE",
            29: "3D",
            30: "FPV_ANGLE_MIX",
            31: "BLACKBOX_ERASE",
            32: "CAMERA_CONTROL_1",
            33: "CAMERA_CONTROL_2",
            34: "CAMERA_CONTROL_3",
            35: "FLIP_OVER_AFTER_CRASH",
            36: "BOXPREARM",
            37: "BEEPER_MUTE"
        }

        mode_name = modes.get(mode_id, f"MODE_{mode_id}")
        logic_str = "AND" if mode_logic == 1 else "OR"
        linked_str = modes.get(linked_to, f"MODE_{linked_to}") if linked_to != 0 else "NONE"
        
        ranges.append(f"Mode {mode_name}: AUX{aux_channel+1} [{start_step}-{end_step}], {logic_str}, Linked: {linked_str}")

    return ", ".join(ranges)

def decode_msp_servo_configurations_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Servo Configurations"
    return MSG_INVALID_PAYLOAD

def decode_msp_servo_configurations_response(payload: bytes) -> str:
    """
    Decodes the servo configurations response.
    
    Payload format from betaflight/src/main/fc/servo.h:
    struct {
        uint16_t min;                // Minimum value
        uint16_t max;                // Maximum value
        uint16_t middle;             // Middle value
        uint8_t rate;               // Rate (%)
        uint8_t angleAtMin;         // Angle at minimum
        uint8_t angleAtMax;         // Angle at maximum
        uint8_t forwardFromChannel; // Forward from channel
        uint32_t reversedSources;   // Reversed input sources
    } servos[];
    """
    if len(payload) < 12:  # Each servo config needs 12 bytes
        return MSG_INVALID_PAYLOAD

    servos = []
    for i in range(0, len(payload), 12):
        if i + 11 >= len(payload):
            break
        min_val = int.from_bytes(payload[i:i+2], 'little')
        max_val = int.from_bytes(payload[i+2:i+4], 'little')
        middle = int.from_bytes(payload[i+4:i+6], 'little')
        rate = payload[i+6]
        angle_min = payload[i+7]
        angle_max = payload[i+8]
        forward_ch = payload[i+9]
        reversed_sources = int.from_bytes(payload[i+10:i+12], 'little')

        servos.append(f"Servo {i//12}: Min={min_val}, Max={max_val}, Mid={middle}, Rate={rate}%, "
                     f"Angles={angle_min}-{angle_max}, Forward=CH{forward_ch+1}, Rev=0x{reversed_sources:04X}")

    return ", ".join(servos)

def decode_msp_servo_mix_rules_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Servo Mix Rules"
    return MSG_INVALID_PAYLOAD

def decode_msp_servo_mix_rules_response(payload: bytes) -> str:
    """
    Decodes the servo mix rules response.
    
    Payload format from betaflight/src/main/fc/servo_mix.h:
    struct {
        uint8_t targetChannel;      // Target servo channel
        uint8_t inputSource;        // Input source
        uint8_t rate;              // Mix rate (%)
        uint8_t speed;             // Speed (degrees/10ms)
        uint8_t min;               // Minimum value
        uint8_t max;               // Maximum value
        uint8_t box;               // Box ID (0=no box)
    } rules[];
    """
    if len(payload) < 7:  # Each rule needs 7 bytes
        return MSG_INVALID_PAYLOAD

    rules = []
    for i in range(0, len(payload), 7):
        if i + 6 >= len(payload):
            break
        target = payload[i]
        input_src = payload[i+1]
        rate = payload[i+2]
        speed = payload[i+3]
        min_val = payload[i+4]
        max_val = payload[i+5]
        box = payload[i+6]

        # Input source abbreviations
        sources = {
            0: "STAB_R",
            1: "STAB_P",
            2: "STAB_Y",
            3: "STAB_T",
            4: "RC_R",
            5: "RC_P",
            6: "RC_Y",
            7: "RC_T",
            8: "RC5",
            9: "RC6",
            10: "RC7",
            11: "RC8",
            12: "GIM_P",
            13: "GIM_R",
            14: "FEAT"
        }

        source_name = sources.get(input_src, f"S{input_src}")
        rules.append(f"S{target+1}:{source_name},R{rate}%,Spd{speed},{min_val}-{max_val},B{box}")

    return ", ".join(rules)

def decode_msp_servo_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Servo Values"
    return MSG_INVALID_PAYLOAD

def decode_msp_servo_response(payload: bytes) -> str:
    """
    Decodes the servo values response.
    Each servo value is a uint16_t representing the PWM value in microseconds.
    """
    if len(payload) < 2:  # Need at least one servo value (2 bytes)
        return MSG_INVALID_PAYLOAD

    servos = []
    for i in range(0, len(payload), 2):
        if i + 1 >= len(payload):
            break
        value = int.from_bytes(payload[i:i+2], 'little')
        servos.append(f"Servo {i//2 + 1}: {value}µs")

    return ", ".join(servos)

# ---------------------------
# MSP_LED_STRIP_CONFIG
# ---------------------------
def decode_msp_led_strip_config_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request LED Strip Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp_led_strip_config_response(payload: bytes) -> str:
    """
    Decodes the LED strip configuration response.
    
    Format from betaflight/src/main/io/ledstrip.h:
    struct {
        uint8_t led_index;          // LED index
        uint32_t mask;              // Mask containing LED configuration
    } leds[];
    
    Mask format (32 bits):
    - Position (bits 0-7): LED position (X,Y coordinates)
    - Function (bits 8-11): Base function (4 bits)
    - Overlay (bits 12-21): Overlay functions (10 bits)
    - Color (bits 22-25): Color index (4 bits)
    - Direction (bits 26-31): Direction flags (6 bits)
    """
    if len(payload) < 5:  # Need at least one LED config (1 byte index + 4 bytes mask)
        return MSG_INVALID_PAYLOAD

    # Function names
    function_names = [
        "COLOR", "FLIGHT_MODE", "ARM_STATE", "BATTERY",
        "RSSI", "GPS", "THRUST_RING", "GPS_BAR",
        "BATTERY_BAR", "ALTITUDE"
    ]

    # Overlay function names (each bit represents a different overlay)
    overlay_names = [
        "THROTTLE", "RAINBOW", "LARSON_SCANNER", "BLINK",
        "VTX", "INDICATOR", "WARNING"
    ]

    # Color names
    color_names = [
        "BLACK", "WHITE", "RED", "ORANGE", "YELLOW",
        "LIME_GREEN", "GREEN", "MINT_GREEN", "CYAN",
        "LIGHT_BLUE", "BLUE", "DARK_VIOLET", "MAGENTA",
        "DEEP_PINK"
    ]

    # Direction names (each bit represents a different direction)
    direction_names = [
        "NORTH", "EAST", "SOUTH", "WEST", "UP", "DOWN"
    ]

    leds = []
    for i in range(0, len(payload), 5):
        if i + 4 >= len(payload):
            break

        led_index = payload[i]
        mask = int.from_bytes(payload[i+1:i+5], 'little')

        # Extract each component from the mask
        position = mask & 0xFF
        function = (mask >> 8) & 0x0F
        overlay = (mask >> 12) & 0x3FF
        color = (mask >> 22) & 0x0F
        direction = (mask >> 26) & 0x3F

        # Position is split into X and Y coordinates
        x = (position >> 4) & 0x0F
        y = position & 0x0F

        # Format the output
        output = []
        output.append(f"LED {led_index}:")
        output.append(f"Position: X={x}, Y={y}")
        
        # Function
        if function < len(function_names):
            output.append(f"Function: {function_names[function]} ({function})")
        else:
            output.append(f"Function: INVALID_FUNCTION_{function}")
        
        # Overlays (multiple can be active)
        active_overlays = []
        for i in range(len(overlay_names)):
            if overlay & (1 << i):
                active_overlays.append(overlay_names[i])
        output.append(f"Overlays: {', '.join(active_overlays) if active_overlays else 'None'} (0x{overlay:03X})")
        
        # Color
        if color < len(color_names):
            output.append(f"Color: {color_names[color]} ({color})")
        else:
            output.append(f"Color: INVALID_COLOR_{color}")
        
        # Directions (multiple can be active)
        active_directions = []
        for i in range(len(direction_names)):
            if direction & (1 << i):
                active_directions.append(direction_names[i])
        output.append(f"Directions: {', '.join(active_directions) if active_directions else 'None'} (0x{direction:02X})")

        # Debug output
        output.append(f"Raw Mask: 0x{mask:08X}")

        leds.append(" | ".join(output))

    return "\n".join(leds)

# ---------------------------
# MSP_DEBUG
# ---------------------------
def decode_msp_debug_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Debug Values"
    return MSG_INVALID_PAYLOAD

def decode_msp_debug_response(payload: bytes) -> str:
    """
    Decodes debug values response.
    Format: 4 x int16_t debug values
    """
    if len(payload) < 8:  # Need 4 x 2 bytes
        return MSG_INVALID_PAYLOAD

    debug_values = []
    for i in range(0, 8, 2):
        value = int.from_bytes(payload[i:i+2], 'little')
        debug_values.append(value)

    return f"Debug Values: {debug_values[0]}, {debug_values[1]}, {debug_values[2]}, {debug_values[3]}"

# ---------------------------
# MSP2_SENSOR_OPTICALFLOW_MT
# ---------------------------
def decode_msp2_sensor_opticalflow_mt_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Optical Flow MT Data"
    return MSG_INVALID_PAYLOAD

def decode_msp2_sensor_opticalflow_mt_response(payload: bytes) -> str:
    """
    Decodes optical flow MT sensor data.
    Format:
    typedef struct __attribute__((packed)) {
        uint8_t quality;    // [0;255]
        int32_t motionX;
        int32_t motionY;
    } mtOpticalflowDataMessage_t;
    """
    if len(payload) < 9:  # 1 byte quality + 4 bytes X + 4 bytes Y
        return MSG_INVALID_PAYLOAD

    quality = payload[0]
    motion_x = int.from_bytes(payload[1:5], 'little', signed=True)
    motion_y = int.from_bytes(payload[5:9], 'little', signed=True)

    return f"Quality: {quality/2.55:.1f}%, X Motion: {motion_x}, Y Motion: {motion_y}"
