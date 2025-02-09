"""
This file contains decoder functions for MSP2 (MultiWii Serial Protocol 2) commands.
Each decoder function has a source location comment indicating where it is implemented in the Betaflight codebase.
"""

from typing import Dict, Any

MSG_INVALID_PAYLOAD = "Invalid payload"

def decode_no_fields(payload: bytes) -> str:
    if len(payload) == 0:
        return f"Unknown command"
    try:
        # Try to decode as ASCII first
        text = payload.decode('ascii', 'replace').rstrip('\x00')
        if text:
            return f"Unknown command: {text}"
        # If no text, show as hex
        return f"Unknown command: 0x{payload.hex()}"
    except:
        return f"Unknown command: 0x{payload.hex()}"

# ---------------------------
# MSP2_BETAFLIGHT_BIND
# Betaflight: src/main/msp/msp2_betaflight.c:50
# ---------------------------

# ---------------------------
# MSP2_GET_TEXT
# Betaflight: src/main/msp/msp2_common.c:200
# ---------------------------
def decode_msp2_get_text_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for text"
    return MSG_INVALID_PAYLOAD

def decode_msp2_get_text_response(payload: bytes) -> str:
    try:
        text = payload.decode('ascii', 'replace').rstrip('\x00')
        return f'Text: "{text}"'
    except:
        return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP2_SENSOR_CONFIG_ACTIVE
# Command: src/main/msp/msp_protocol_v2_betaflight.h
# Implementation: src/main/msp/msp.c:2100 (processOutCommand)
# ---------------------------
def decode_msp2_sensor_config_active_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for active sensor config"
    return MSG_INVALID_PAYLOAD

def decode_msp2_sensor_config_active_response(payload: bytes) -> str:
    if len(payload) >= 1:
        active_sensors = payload[0]
        return f"Active Sensors: {active_sensors}"
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP2_GET_VTX_DEVICE_STATUS
# Betaflight: src/main/msp/msp2_vtx.c:50
# ---------------------------
def decode_msp2_get_vtx_device_status_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for VTX device status"
    return MSG_INVALID_PAYLOAD

def decode_msp2_get_vtx_device_status_response(payload: bytes) -> str:
    if len(payload) == 0:
        return "No VTX device detected"
    elif len(payload) >= 12:
        device_type = payload[0]
        band = payload[1]
        channel = payload[2]
        power = payload[3]
        pit_mode = payload[4]
        frequency = int.from_bytes(payload[5:7], 'little')
        device_ready = payload[7]
        low_power_disarm = payload[8]
        pit_mode_frequency = int.from_bytes(payload[9:11], 'little')
        table_size = payload[11]
        
        response = (f"Type: {device_type}\n"
                f"Band: {band}\n"
                   f"Channel: {channel}\n"
                   f"Power: {power}\n"
                f"Pit Mode: {pit_mode}\n"
                f"Frequency: {frequency}\n"
                f"Ready: {device_ready}\n"
                   f"Low Power Disarm: {low_power_disarm}\n"
                f"Pit Mode Freq: {pit_mode_frequency}\n"
                   f"Table Size: {table_size}")
        return response
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP2_COMMON_SERIAL_CONFIG
# Betaflight: src/main/msp/msp2_common.c:400
# ---------------------------
def decode_msp2_common_serial_config_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for Serial Configuration"
    return MSG_INVALID_PAYLOAD

def decode_msp2_common_serial_config_response(payload: bytes) -> str:
    if len(payload) >= 1:
        count = payload[0]
        index = 1
        ports = []

        # Baud rate mapping
        baud_rates = {
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

        # Port identifier mapping
        port_names = {
            0x14: "USB VCP",  # 20
            0x33: "UART1",    # 51
            0x34: "UART2",    # 52
            0x35: "UART3",    # 53
            0x36: "UART4",    # 54
            0x37: "UART5",    # 55
            0x38: "UART6"     # 56
        }

        for i in range(count):
            if len(payload) < index + 9:  # Each port needs 9 bytes (1+4+1+1+1+1)
                break
                
            identifier = payload[index]
            function_mask = int.from_bytes(payload[index+1:index+5], 'little')
            msp_baudrateIndex = payload[index+5]
            gps_baudrateIndex = payload[index+6]
            telemetry_baudrateIndex = payload[index+7]
            blackbox_baudrateIndex = payload[index+8]

            port_name = port_names.get(identifier, f"Port 0x{identifier:02X}")
            
            # Build list of enabled functions with their baud rates
            functions = []
            # Check function mask bits according to serialPortFunction_e
            if function_mask & 0x01:  # FUNCTION_MSP
                functions.append(f"MSP ({baud_rates.get(msp_baudrateIndex, 'Unknown')})")
            if function_mask & 0x02:  # FUNCTION_GPS
                functions.append(f"GPS ({baud_rates.get(gps_baudrateIndex, 'Unknown')})")
            if function_mask & 0x04:  # FUNCTION_TELEMETRY_FRSKY
                functions.append(f"TELEMETRY ({baud_rates.get(telemetry_baudrateIndex, 'Unknown')})")
            if function_mask & 0x08:  # FUNCTION_TELEMETRY_HOTT
                functions.append(f"HOTT")
            if function_mask & 0x10:  # FUNCTION_TELEMETRY_LTM
                functions.append("LTM")
            if function_mask & 0x20:  # FUNCTION_TELEMETRY_SMARTPORT
                functions.append("SMARTPORT")
            if function_mask & 0x40:  # FUNCTION_RX_SERIAL
                functions.append("SERIAL RX")
            if function_mask & 0x80:  # FUNCTION_BLACKBOX
                functions.append(f"BLACKBOX ({baud_rates.get(blackbox_baudrateIndex, 'Unknown')})")
            if function_mask & 0x100:  # FUNCTION_TELEMETRY_MAVLINK
                functions.append("MAVLINK")
            if function_mask & 0x200:  # FUNCTION_ESC_SENSOR
                functions.append("ESC SENSOR")
            if function_mask & 0x400:  # FUNCTION_VTX_SMARTAUDIO
                functions.append("TBS SMARTAUDIO")
            if function_mask & 0x800:  # FUNCTION_VTX_TRAMP
                functions.append("IRC TRAMP")
            if function_mask & 0x1000:  # FUNCTION_RUNCAM_DEVICE_CONTROL
                functions.append("RUNCAM")
            if function_mask & 0x2000:  # FUNCTION_LIDAR_TF
                functions.append("LIDAR TF")
            if function_mask & 0x4000:  # FUNCTION_OPFLOW
                functions.append("OPFLOW")
            if function_mask & 0x8000:  # FUNCTION_DEBUG
                functions.append("DEBUG")
            if function_mask & 0x10000:  # FUNCTION_VTX_MSP
                functions.append("VTX MSP")
            if function_mask & 0x20000:  # FUNCTION_ESCSERIAL
                functions.append("ESCSERIAL")
            if function_mask & 0x40000:  # FUNCTION_TELEMETRY_IBUS
                functions.append("IBUS")
            
            # Format port info
            if functions:
                ports.append(f"{port_name}: {', '.join(functions)}")
            else:
                ports.append(f"{port_name}: No functions enabled")
            
            index += 9  # Move to next port

        return "\n".join(ports)
    return MSG_INVALID_PAYLOAD

def decode_msp2_common_set_serial_config_request(payload: bytes) -> str:
    if len(payload) >= 1:
        count = payload[0]
        index = 1
        ports = []
        for i in range(count):
            if len(payload) < index + 24:  # Each port needs 24 bytes
                break
            identifier = int.from_bytes(payload[index:index+4], 'little')
            function_mask = int.from_bytes(payload[index+4:index+8], 'little')
            msp_baudrate = int.from_bytes(payload[index+8:index+12], 'little')
            gps_baudrate = int.from_bytes(payload[index+12:index+16], 'little')
            telemetry_baudrate = int.from_bytes(payload[index+16:index+20], 'little')
            peripheral_baudrate = int.from_bytes(payload[index+20:index+24], 'little')
            
            # Convert identifier to port name
            port_names = {
                0: "UART1",
                1: "UART2",
                2: "UART3",
                3: "UART4",
                4: "UART5",
                5: "UART6",
                20: "USB VCP"
            }
            port_name = port_names.get(identifier, f"Port {identifier}")
            
            # Convert function mask to readable flags
            functions = []
            if function_mask & (1 << 0): functions.append("MSP")
            if function_mask & (1 << 1): functions.append("GPS")
            if function_mask & (1 << 2): functions.append("TELEMETRY")
            if function_mask & (1 << 3): functions.append("BLACKBOX")
            if function_mask & (1 << 4): functions.append("SERIAL RX")
            if function_mask & (1 << 5): functions.append("ESC SENSOR")
            if function_mask & (1 << 6): functions.append("TBS SMARTAUDIO")
            if function_mask & (1 << 7): functions.append("IRC TRAMP")
            if function_mask & (1 << 8): functions.append("RUNCAM")
            if function_mask & (1 << 9): functions.append("LIDAR TF")
            if function_mask & (1 << 10): functions.append("OPFLOW")
            if function_mask & (1 << 11): functions.append("DEBUG")
            if function_mask & (1 << 12): functions.append("VTX")
            if function_mask & (1 << 13): functions.append("ESCSERIAL")
            if function_mask & (1 << 14): functions.append("FRSKY")
            if function_mask & (1 << 15): functions.append("HOTT")
            if function_mask & (1 << 16): functions.append("SMARTPORT")
            if function_mask & (1 << 17): functions.append("LTM")
            if function_mask & (1 << 18): functions.append("MAVLINK")
            
            # Only show baudrates for enabled functions
            baud_info = []
            if function_mask & (1 << 0): baud_info.append(f"MSP: {msp_baudrate}")
            if function_mask & (1 << 1): baud_info.append(f"GPS: {gps_baudrate}")
            if function_mask & (1 << 2): baud_info.append(f"Telemetry: {telemetry_baudrate}")
            if peripheral_baudrate != 0: baud_info.append(f"Peripheral: {peripheral_baudrate}")
            
            ports.append(f"Set {port_name}:\n"
                        f"  Functions: {', '.join(functions) if functions else 'None'}"
                        + (f"\n  Baud: {', '.join(baud_info)}" if baud_info else ""))
            index += 24
        return "\n".join(ports)
    return MSG_INVALID_PAYLOAD

def decode_msp2_common_set_serial_config_response(payload: bytes) -> str:
    if len(payload) == 0:
        return "Serial Configuration Set"
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP2_SENSOR_GPS
# Command: src/main/msp/msp_protocol_v2_common.h
# Implementation: src/main/msp/msp.c:1500 (processOutCommand)
# ---------------------------
def decode_msp2_sensor_gps_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for GPS Data"
    return MSG_INVALID_PAYLOAD

def decode_msp2_sensor_gps_response(payload: bytes) -> str:
    if len(payload) >= 20:
        fix = payload[0]
        num_sat = payload[1]
        lat = int.from_bytes(payload[2:6], 'little', signed=True)
        lon = int.from_bytes(payload[6:10], 'little', signed=True)
        altitude = int.from_bytes(payload[10:14], 'little', signed=True)
        speed = int.from_bytes(payload[14:16], 'little')
        ground_course = int.from_bytes(payload[16:18], 'little')
        hdop = int.from_bytes(payload[18:20], 'little')
        return (f"Fix: {fix}\n"
                f"Satellites: {num_sat}\n"
                f"Lat: {lat/10000000.0}°\n"
                f"Lon: {lon/10000000.0}°\n"
                f"Alt: {altitude/100.0}m\n"
                f"Speed: {speed}cm/s\n"
                f"Course: {ground_course/10.0}°\n"
                f"HDOP: {hdop/100.0}")
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP2_SENSOR_RANGEFINDER_LIDARMT
# Command: src/main/msp/msp_protocol_v2_common.h
# Implementation: src/main/msp/msp.c:1600 (processOutCommand)
# ---------------------------
def decode_msp2_sensor_rangefinder_lidarmt_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Empty LIDARMT Rangefinder Request"
    return MSG_INVALID_PAYLOAD

def decode_msp2_sensor_rangefinder_lidarmt_response(payload: bytes) -> str:
    """
    Decode MSP2_SENSOR_RANGEFINDER_LIDARMT response.
    """
    if len(payload) == 0:
        return "Empty LIDARMT Rangefinder Response"
        
    # Show raw response values since we don't have the protocol spec
    values = [f"0x{b:02X}" for b in payload]
    return f"LIDARMT Response: {' '.join(values)}"

def decode_msp2_common_esc_sensor_data_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for ESC Sensor Data"
    return MSG_INVALID_PAYLOAD

def decode_msp2_common_esc_sensor_data_response(payload: bytes) -> str:
    if len(payload) >= 2:
        count = payload[0]
        index = 1
        escs = []
        for i in range(count):
            if len(payload) < index + 14:
                break
            temperature = int.from_bytes(payload[index:index+2], 'little')
            rpm = int.from_bytes(payload[index+2:index+6], 'little')
            voltage = int.from_bytes(payload[index+6:index+10], 'little')
            current = int.from_bytes(payload[index+10:index+14], 'little')
            escs.append(f"ESC {i}:\n"
                       f"  Temp: {temperature}°C\n"
                       f"  RPM: {rpm}\n"
                       f"  Voltage: {voltage/100.0}V\n"
                       f"  Current: {current/100.0}A")
            index += 14
        return "\n".join(escs)
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP2_COMMON_MOTOR_MIXER
# Betaflight: src/main/msp/msp2_common.c:200
# ---------------------------
def decode_msp2_common_motor_mixer_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for Motor Mixer"
    return MSG_INVALID_PAYLOAD

def decode_msp2_common_motor_mixer_response(payload: bytes) -> str:
    if len(payload) >= 1:
        count = payload[0]
        index = 1
        mixers = []
        for i in range(count):
            if len(payload) < index + 8:
                break
            throttle = int.from_bytes(payload[index:index+2], 'little')
            roll = int.from_bytes(payload[index+2:index+4], 'little')
            pitch = int.from_bytes(payload[index+4:index+6], 'little')
            yaw = int.from_bytes(payload[index+6:index+8], 'little')
            mixers.append(f"Motor {i}:\n"
                         f"  Throttle: {throttle/1000.0}\n"
                         f"  Roll: {roll/1000.0}\n"
                         f"  Pitch: {pitch/1000.0}\n"
                         f"  Yaw: {yaw/1000.0}")
            index += 8
        return "\n".join(mixers)
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP2_COMMON_SETTING
# Betaflight: src/main/msp/msp2_common.c:500
# ---------------------------
def decode_msp2_common_setting_request(payload: bytes) -> str:
    if len(payload) >= 2:
        index = int.from_bytes(payload[0:2], 'little')
        return f"Request for Setting {index}"
    return MSG_INVALID_PAYLOAD

def decode_msp2_common_setting_response(payload: bytes) -> str:
    if len(payload) >= 3:
        index = int.from_bytes(payload[0:2], 'little')
        value = payload[2:]
        try:
            text = value.decode('ascii', 'replace').rstrip('\x00')
            return f"Setting {index}: {text}"
        except:
            return f"Setting {index}: 0x{value.hex()}"
    return MSG_INVALID_PAYLOAD

def decode_msp2_common_setting_info_request(payload: bytes) -> str:
    if len(payload) >= 2:
        index = int.from_bytes(payload[0:2], 'little')
        return f"Request for Setting Info {index}"
    return MSG_INVALID_PAYLOAD

def decode_msp2_common_setting_info_response(payload: bytes) -> str:
    if len(payload) >= 3:
        index = int.from_bytes(payload[0:2], 'little')
        value_type = payload[2]
        name_length = payload[3]
        if len(payload) >= 4 + name_length:
            name = payload[4:4+name_length].decode('ascii', 'replace').rstrip('\x00')
            min_val = None
            max_val = None
            default_val = None
            
            pos = 4 + name_length
            if len(payload) >= pos + 4:
                min_val = int.from_bytes(payload[pos:pos+4], 'little')
                pos += 4
            if len(payload) >= pos + 4:
                max_val = int.from_bytes(payload[pos:pos+4], 'little')
                pos += 4
            if len(payload) >= pos + 4:
                default_val = int.from_bytes(payload[pos:pos+4], 'little')
            
            info = f"Setting {index}:\n"
            info += f"  Name: {name}\n"
            info += f"  Type: {value_type}"
            if min_val is not None:
                info += f"\n  Min: {min_val}"
            if max_val is not None:
                info += f"\n  Max: {max_val}"
            if default_val is not None:
                info += f"\n  Default: {default_val}"
            return info
    return MSG_INVALID_PAYLOAD

def decode_msp2_common_pg_list_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for Parameter Group List"
    return MSG_INVALID_PAYLOAD

def decode_msp2_common_pg_list_response(payload: bytes) -> str:
    if len(payload) >= 2:
        groups = []
        index = 0
        while index < len(payload):
            if len(payload) < index + 2:
                break
            pg_id = int.from_bytes(payload[index:index+2], 'little')
            groups.append(f"PG ID: {pg_id}")
            index += 2
        return "\n".join(groups)
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP2_BETAFLIGHT_DEBUG
# Betaflight: src/main/msp/msp2_betaflight.c:150
# ---------------------------
def decode_msp2_betaflight_debug_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for Debug Data"
    return MSG_INVALID_PAYLOAD

def decode_msp2_betaflight_debug_response(payload: bytes) -> str:
    if len(payload) >= 1:
        count = len(payload) // 4
        values = []
        for i in range(count):
            value = int.from_bytes(payload[i*4:(i+1)*4], 'little')
            values.append(f"Debug[{i}]: {value}")
        return "\n".join(values)
    return MSG_INVALID_PAYLOAD

def decode_msp2_blackbox_config_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for Blackbox Config"
    return MSG_INVALID_PAYLOAD

def decode_msp2_blackbox_config_response(payload: bytes) -> str:
    if len(payload) >= 12:
        supported = payload[0]
        active = payload[1]
        device = payload[2]
        rate_num = payload[3]
        rate_denom = payload[4]
        p_denom = payload[5]
        sample_rate = int.from_bytes(payload[6:8], 'little')
        device_size = int.from_bytes(payload[8:12], 'little')
        return (f"Supported: {supported}\n"
                f"Active: {active}\n"
                f"Device: {device}\n"
                f"Rate: {rate_num}/{rate_denom}\n"
                f"P Denom: {p_denom}\n"
                f"Sample Rate: {sample_rate}\n"
                f"Device Size: {device_size}")
    return MSG_INVALID_PAYLOAD

def decode_msp2_motor_config_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for Motor Config"
    return MSG_INVALID_PAYLOAD

def decode_msp2_motor_config_response(payload: bytes) -> str:
    """Decode MSP2_MOTOR_CONFIG response.
    Protocol definition from betaflight/src/main/pg/motor.h:
    
    typedef struct motorDevConfig_s {
        uint16_t motorPwmRate;               // The update rate of motor outputs (50-498Hz)
        uint8_t  motorProtocol;              // Pwm Protocol
        uint8_t  motorInversion;             // Active-High vs Active-Low. Useful for brushed FCs converted for brushless operation
        uint8_t  useContinuousUpdate;
        uint8_t  useBurstDshot;
        uint8_t  useDshotTelemetry;
        uint8_t  useDshotEdt;
        ioTag_t  ioTags[MAX_SUPPORTED_MOTORS];
        uint8_t  motorTransportProtocol;
        uint8_t  useDshotBitbang;
        uint8_t  useDshotBitbangedTimer;
        uint8_t  motorOutputReordering[MAX_SUPPORTED_MOTORS]; // Reindexing motors for "remap motors" feature in Configurator
    } motorDevConfig_t;

    typedef struct motorConfig_s {
        motorDevConfig_t dev;
        uint16_t motorIdle;                     // When motors are idling, the percentage of the motor range added above the disarmed value, in percent * 100.
        uint16_t maxthrottle;                   // This is the maximum value for the ESCs at full power. This value can be increased up to 2000
        uint16_t mincommand;                    // This is the value for the ESCs when they are not armed. In some cases, this value must be lowered down to 900 for some specific ESCs
        uint16_t kv;                            // Motor velocity constant (Kv) to estimate RPM under no load (unloadedRpm = Kv * batteryVoltage)
        uint8_t motorPoleCount;                 // Number of magnetic poles in the motor bell for calculating actual RPM from eRPM provided by ESC telemetry
    } motorConfig_t;
    """
    if len(payload) >= 9:  # Minimum size for basic config
        index = 0
        
        # Read motorDevConfig
        motor_pwm_rate = int.from_bytes(payload[index:index+2], 'little')
        index += 2
        motor_protocol = payload[index]
        index += 1
        motor_inversion = payload[index]
        index += 1
        use_continuous_update = payload[index]
        index += 1
        use_burst_dshot = payload[index]
        index += 1
        use_dshot_telemetry = payload[index]
        index += 1
        use_dshot_edt = payload[index]
        index += 1
        
        # Skip ioTags array for now
        
        motor_transport_protocol = payload[index] if len(payload) > index else 0
        index += 1
        use_dshot_bitbang = payload[index] if len(payload) > index else 0
        index += 1
        use_dshot_bitbanged_timer = payload[index] if len(payload) > index else 0
        index += 1
        
        # Skip motorOutputReordering array for now
        
        # Read motorConfig
        motor_idle = int.from_bytes(payload[index:index+2], 'little') if len(payload) > index+1 else 0
        index += 2
        max_throttle = int.from_bytes(payload[index:index+2], 'little') if len(payload) > index+1 else 0
        index += 2
        min_command = int.from_bytes(payload[index:index+2], 'little') if len(payload) > index+1 else 0
        index += 2
        kv = int.from_bytes(payload[index:index+2], 'little') if len(payload) > index+1 else 0
        index += 2
        motor_pole_count = payload[index] if len(payload) > index else 0
        
        # Convert protocol to string
        protocol_str = {
            0: "PROTOCOL_DISABLED",
            1: "PROTOCOL_STANDARD_PWM",
            2: "PROTOCOL_ONESHOT125",
            3: "PROTOCOL_ONESHOT42",
            4: "PROTOCOL_MULTISHOT",
            5: "PROTOCOL_BRUSHED",
            6: "PROTOCOL_DSHOT150",
            7: "PROTOCOL_DSHOT300",
            8: "PROTOCOL_DSHOT600",
            9: "PROTOCOL_DSHOT1200",
            10: "PROTOCOL_PROSHOT1000"
        }.get(motor_protocol, f"UNKNOWN ({motor_protocol})")
        
        return (f"PWM Rate: {motor_pwm_rate}Hz\n"
                f"Protocol: {protocol_str}\n"
                f"Inversion: {bool(motor_inversion)}\n"
                f"Continuous Update: {bool(use_continuous_update)}\n"
                f"Burst DShot: {bool(use_burst_dshot)}\n"
                f"DShot Telemetry: {bool(use_dshot_telemetry)}\n"
                f"DShot EDT: {bool(use_dshot_edt)}\n"
                f"Transport Protocol: {motor_transport_protocol}\n"
                f"DShot Bitbang: {bool(use_dshot_bitbang)}\n"
                f"DShot Bitbanged Timer: {use_dshot_bitbanged_timer}\n"
                f"Motor Idle: {motor_idle/1000.0}%\n"
                f"Max Throttle: {max_throttle}\n"
                f"Min Command: {min_command}\n"
                f"KV: {kv}\n"
                f"Pole Count: {motor_pole_count}")
    
    # If not the expected format, show raw values
    values = [f"0x{b:02X}" for b in payload]
    return f"Raw payload: {' '.join(values)}"

def decode_msp2_vtx_config_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for VTX Config"
    return MSG_INVALID_PAYLOAD

def decode_msp2_vtx_config_response(payload: bytes) -> str:
    if len(payload) >= 13:
        vtx_type = payload[0]
        band = payload[1]
        channel = payload[2]
        power = payload[3]
        pit_mode = payload[4]
        freq = int.from_bytes(payload[5:7], 'little')
        device_ready = payload[7]
        low_power_disarm = payload[8]
        pit_mode_freq = int.from_bytes(payload[9:11], 'little')
        table_size = payload[11]
        table_bands = payload[12]
        return (f"Type: {vtx_type}\n"
                f"Band: {band}\n"
                f"Channel: {channel}\n"
                f"Power: {power}\n"
                f"Pit Mode: {pit_mode}\n"
                f"Frequency: {freq}\n"
                f"Device Ready: {device_ready}\n"
                f"Low Power Disarm: {low_power_disarm}\n"
                f"Pit Mode Freq: {pit_mode_freq}\n"
                f"Table Size: {tablesize}\n"
                f"Table Bands: {table_bands}")
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP2_RC_COMMAND
# Betaflight: src/main/msp/msp2_rc.c:50
# ---------------------------
def decode_msp2_rc_command_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for RC Commands"
    return MSG_INVALID_PAYLOAD

def decode_msp2_rc_command_response(payload: bytes) -> str:
    if len(payload) >= 8:
        roll = int.from_bytes(payload[0:2], 'little')
        pitch = int.from_bytes(payload[2:4], 'little')
        yaw = int.from_bytes(payload[4:6], 'little')
        throttle = int.from_bytes(payload[6:8], 'little')
        return (f"Roll: {roll}\n"
                f"Pitch: {pitch}\n"
                f"Yaw: {yaw}\n"
                f"Throttle: {throttle}")
    return MSG_INVALID_PAYLOAD

def decode_msp2_status_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for Status"
    return MSG_INVALID_PAYLOAD

def decode_msp2_status_response(payload: bytes) -> str:
    if len(payload) >= 20:
        task_mode = payload[0]
        profile_index = payload[1]
        profile_count = payload[2]
        rateprofile_index = payload[3]
        armed_time = int.from_bytes(payload[4:8], 'little')
        arming_disabled_flags = int.from_bytes(payload[8:12], 'little')
        packet_rate = int.from_bytes(payload[12:14], 'little')
        packet_count = int.from_bytes(payload[14:16], 'little')
        cpu_load = int.from_bytes(payload[16:18], 'little')
        num_profiles = payload[18]
        avg_system_load = int.from_bytes(payload[19:21], 'little')
        return (f"Task Mode: {task_mode}\n"
                f"Profile: {profile_index}/{profile_count}\n"
                f"Rate Profile: {rateprofile_index}\n"
                f"Armed Time: {armed_time}s\n"
                f"Arming Disabled: 0x{arming_disabled_flags:08X}\n"
                f"Packet Rate: {packet_rate}\n"
                f"Packet Count: {packet_count}\n"
                f"CPU Load: {cpu_load/10.0}%\n"
                f"Profiles: {num_profiles}\n"
                f"Avg System Load: {avg_system_load/10.0}%")
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP2_BETAFLIGHT_PID
# Betaflight: src/main/msp/msp2_betaflight.c:300
# ---------------------------
def decode_msp2_betaflight_pid_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for PID Config"
    return MSG_INVALID_PAYLOAD

def decode_msp2_betaflight_pid_response(payload: bytes) -> str:
    if len(payload) >= 16:
        pid_roll = [payload[0], payload[1], payload[2]]
        pid_pitch = [payload[3], payload[4], payload[5]]
        pid_yaw = [payload[6], payload[7], payload[8]]
        pid_level = [payload[9], payload[10], payload[11]]
        pid_mag = payload[12]
        pid_vel = [payload[13], payload[14], payload[15]]
        return (f"Roll PID: P={pid_roll[0]} I={pid_roll[1]} D={pid_roll[2]}\n"
                f"Pitch PID: P={pid_pitch[0]} I={pid_pitch[1]} D={pid_pitch[2]}\n"
                f"Yaw PID: P={pid_yaw[0]} I={pid_yaw[1]} D={pid_yaw[2]}\n"
                f"Level PID: P={pid_level[0]} I={pid_level[1]} D={pid_level[2]}\n"
                f"Mag P: {pid_mag}\n"
                f"Velocity: P={pid_vel[0]} I={pid_vel[1]} D={pid_vel[2]}")
    return MSG_INVALID_PAYLOAD

def decode_msp2_betaflight_rates_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for Rate Config"
    return MSG_INVALID_PAYLOAD

def decode_msp2_betaflight_rates_response(payload: bytes) -> str:
    if len(payload) >= 18:
        roll_rate = int.from_bytes(payload[0:2], 'little')
        pitch_rate = int.from_bytes(payload[2:4], 'little')
        yaw_rate = int.from_bytes(payload[4:6], 'little')
        roll_super = int.from_bytes(payload[6:8], 'little')
        pitch_super = int.from_bytes(payload[8:10], 'little')
        yaw_super = int.from_bytes(payload[10:12], 'little')
        roll_expo = int.from_bytes(payload[12:14], 'little')
        pitch_expo = int.from_bytes(payload[14:16], 'little')
        yaw_expo = int.from_bytes(payload[16:18], 'little')
        return (f"Roll Rate: {roll_rate}\n"
                f"Pitch Rate: {pitch_rate}\n"
                f"Yaw Rate: {yaw_rate}\n"
                f"Roll Super: {roll_super}\n"
                f"Pitch Super: {pitch_super}\n"
                f"Yaw Super: {yaw_super}\n"
                f"Roll Expo: {roll_expo}\n"
                f"Pitch Expo: {pitch_expo}\n"
                f"Yaw Expo: {yaw_expo}")
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP2_BETAFLIGHT_MODE_RANGES
# Betaflight: src/main/msp/msp2_betaflight.c:250
# ---------------------------
def decode_msp2_betaflight_mode_ranges_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for Mode Ranges"
    return MSG_INVALID_PAYLOAD

def decode_msp2_betaflight_mode_ranges_response(payload: bytes) -> str:
    if len(payload) >= 4:
        ranges = []
        index = 0
        while index + 4 <= len(payload):
            box_id = payload[index]
            aux_channel = payload[index + 1]
            start_step = payload[index + 2]
            end_step = payload[index + 3]
            ranges.append(f"Mode {box_id}: AUX{aux_channel + 1} [{start_step}-{end_step}]")
            index += 4
        return "\n".join(ranges)
    return MSG_INVALID_PAYLOAD

def decode_msp2_betaflight_rx_map_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for RX Channel Map"
    return MSG_INVALID_PAYLOAD

def decode_msp2_betaflight_rx_map_response(payload: bytes) -> str:
    if len(payload) >= 4:
        channels = []
        for i, ch in enumerate(payload[:4]):
            channels.append(f"CH{i+1} -> {ch+1}")
        return "\n".join(channels)
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP2_BETAFLIGHT_FEATURE_CONFIG
# Betaflight: src/main/msp/msp2_betaflight.c:200
# ---------------------------
def decode_msp2_betaflight_feature_config_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for Feature Config"
    return MSG_INVALID_PAYLOAD

def decode_msp2_betaflight_feature_config_response(payload: bytes) -> str:
    if len(payload) >= 4:
        features = int.from_bytes(payload[0:4], 'little')
        return f"Features: 0x{features:08X}"
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP2_BETAFLIGHT_BOARD_CONFIG
# Betaflight: src/main/msp/msp2_betaflight.c:100
# ---------------------------
def decode_msp2_betaflight_board_config_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for Board Config"
    return MSG_INVALID_PAYLOAD

def decode_msp2_betaflight_board_config_response(payload: bytes) -> str:
    if len(payload) >= 20:
        name = payload[0:4].decode('ascii', 'replace').rstrip('\x00')
        version = payload[4]
        target_capabilities = payload[5]
        target_name = payload[6:14].decode('ascii', 'replace').rstrip('\x00')
        board_name = payload[14:22].decode('ascii', 'replace').rstrip('\x00')
        manufacturer_id = payload[22:27].decode('ascii', 'replace').rstrip('\x00')
        signature = payload[27:59].decode('ascii', 'replace').rstrip('\x00')
        mcuTypeId = payload[59]
        configurationState = payload[60]
        return (f"Name: {name}\n"
                f"Version: {version}\n"
                f"Capabilities: 0x{target_capabilities:02X}\n"
                f"Target: {target_name}\n"
                f"Board: {board_name}\n"
                f"Manufacturer: {manufacturer_id}\n"
                f"Signature: {signature}\n"
                f"MCU Type: {mcuTypeId}\n"
                f"Config State: {configurationState}")
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP2_SENSOR_OPTICALFLOW
# Command: src/main/msp/msp_protocol_v2_betaflight.h
# Implementation: src/main/msp/msp.c:1700 (processOutCommand)
# ---------------------------
def decode_msp2_sensor_opticalflow_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for Optical Flow Data"
    return MSG_INVALID_PAYLOAD

def decode_msp2_sensor_opticalflow_response(payload: bytes) -> str:
    if len(payload) >= 8:
        raw_x = int.from_bytes(payload[0:2], 'little', signed=True)
        raw_y = int.from_bytes(payload[2:4], 'little', signed=True)
        quality = payload[4]
        raw_motion_x = int.from_bytes(payload[5:6], 'little', signed=True)
        raw_motion_y = int.from_bytes(payload[6:7], 'little', signed=True)
        raw_motion_quality = payload[7]
        return (f"Raw X: {raw_x}\n"
                f"Raw Y: {raw_y}\n"
                f"Quality: {quality}\n"
                f"Motion X: {raw_motion_x}\n"
                f"Motion Y: {raw_motion_y}\n"
                f"Motion Quality: {raw_motion_quality}")
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP2_COMMON_UID
# Betaflight: src/main/msp/msp2_common.c:650
# ---------------------------
def decode_msp2_common_uid_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for Device UID"
    return MSG_INVALID_PAYLOAD

def decode_msp2_common_uid_response(payload: bytes) -> str:
    if len(payload) >= 12:
        uid = "".join(f"{b:02X}" for b in payload[:12])
        return f"Device UID: {uid}"
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP2_COMMON_SERVO
# Betaflight: src/main/msp/msp2_common.c:450
# ---------------------------
def decode_msp2_common_servo_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for Servo Values"
    return MSG_INVALID_PAYLOAD

def decode_msp2_common_servo_response(payload: bytes) -> str:
    if len(payload) >= 2:
        servos = []
        for i in range(0, len(payload), 2):
            servo_value = int.from_bytes(payload[i:i+2], 'little')
            servos.append(f"Servo {i//2 + 1}: {servo_value}")
        return "\n".join(servos)
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP2_COMMON_RC
# Betaflight: src/main/msp/msp2_common.c:350
# ---------------------------
def decode_msp2_common_rc_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for RC Channel Values"
    return MSG_INVALID_PAYLOAD

def decode_msp2_common_rc_response(payload: bytes) -> str:
    if len(payload) >= 2:
        channels = []
        for i in range(0, len(payload), 2):
            channel_value = int.from_bytes(payload[i:i+2], 'little')
            channels.append(f"Channel {i//2 + 1}: {channel_value}")
        return "\n".join(channels)
    return MSG_INVALID_PAYLOAD

def decode_msp2_common_attitude_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for Attitude Values"
    return MSG_INVALID_PAYLOAD

def decode_msp2_common_attitude_response(payload: bytes) -> str:
    if len(payload) >= 6:
        roll = int.from_bytes(payload[0:2], 'little', signed=True) / 10.0
        pitch = int.from_bytes(payload[2:4], 'little', signed=True) / 10.0
        yaw = int.from_bytes(payload[4:6], 'little', signed=True)
        return f"Roll: {roll}°, Pitch: {pitch}°, Yaw: {yaw}°"
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP2_COMMON_RAW_IMU
# Betaflight: src/main/msp/msp2_common.c:300
# ---------------------------
def decode_msp2_common_raw_imu_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for Raw IMU Data"
    return MSG_INVALID_PAYLOAD

def decode_msp2_common_raw_imu_response(payload: bytes) -> str:
    if len(payload) >= 18:
        acc = []
        gyro = []
        mag = []
        for i in range(0, 6, 2):
            acc.append(int.from_bytes(payload[i:i+2], 'little', signed=True))
        for i in range(6, 12, 2):
            gyro.append(int.from_bytes(payload[i:i+2], 'little', signed=True))
        for i in range(12, 18, 2):
            mag.append(int.from_bytes(payload[i:i+2], 'little', signed=True))
        return (f"Acc: X:{acc[0]} Y:{acc[1]} Z:{acc[2]}\n"
                f"Gyro: X:{gyro[0]} Y:{gyro[1]} Z:{gyro[2]}\n"
                f"Mag: X:{mag[0]} Y:{mag[1]} Z:{mag[2]}")
    return MSG_INVALID_PAYLOAD

def decode_msp2_common_analog_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for Analog Values"
    return MSG_INVALID_PAYLOAD

def decode_msp2_common_analog_response(payload: bytes) -> str:
    if len(payload) >= 7:
        battery_voltage = payload[0] / 10.0
        mah_drawn = int.from_bytes(payload[1:3], 'little')
        rssi = payload[3]
        amperage = int.from_bytes(payload[4:6], 'little')
        voltage = int.from_bytes(payload[6:8], 'little') / 100.0
        return (f"Battery: {battery_voltage}V\n"
                f"Capacity Used: {mah_drawn}mAh\n"
                f"RSSI: {rssi}\n"
                f"Current: {amperage/100.0}A\n"
                f"Voltage: {voltage}V")
    return MSG_INVALID_PAYLOAD

def decode_msp2_common_status_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for Flight Controller Status"
    return MSG_INVALID_PAYLOAD

def decode_msp2_common_status_response(payload: bytes) -> str:
    if len(payload) >= 3:
        cycle_time = int.from_bytes(payload[0:2], 'little')
        i2c_errors = int.from_bytes(payload[2:4], 'little')
        active_sensors = int.from_bytes(payload[4:6], 'little')
        mode = int.from_bytes(payload[6:10], 'little')
        profile = payload[10]
        return (f"Cycle Time: {cycle_time}µs\n"
                f"I2C Errors: {i2c_errors}\n"
                f"Active Sensors: 0x{active_sensors:04X}\n"
                f"Mode: 0x{mode:08X}\n"
                f"Profile: {profile}")
    return MSG_INVALID_PAYLOAD

def decode_msp2_sensor_opticalflow_mt_request(payload: bytes) -> str:
    if len(payload) == 9:
        status = payload[0]
        motion_x = int.from_bytes(payload[1:3], 'little', signed=True)
        motion_y = int.from_bytes(payload[3:5], 'little', signed=True)
        surface_quality = int.from_bytes(payload[5:7], 'little')
        return (f"Status: {status}, Motion X: {motion_x}, Motion Y: {motion_y}, "
                f"Surface Quality: {surface_quality}")
    return MSG_INVALID_PAYLOAD

def decode_msp2_sensor_opticalflow_mt_response(payload: bytes) -> str:
    """Decode MSP2_SENSOR_OPTICALFLOW_MT response"""
    if len(payload) >= 9:  # Payload should be exactly 9 bytes
        status = payload[0]
        # Status values:
        # 0x40 = Normal operation (64)
        # 0x41 = Warning (65)
        # 0x42 = Error/Special (66)
        status_desc = {
            0x40: "Normal - No Motion",
            0x41: "Normal - Motion Detected",
            0x42: "Warning - High Motion"
        }.get(status, "Unknown")
        
        # Extract motion data (signed 16-bit values)
        motion_x = int.from_bytes(payload[1:3], 'little', signed=True)
        motion_y = int.from_bytes(payload[3:5], 'little', signed=True)
        motion_quality = payload[5]
        raw_x = int.from_bytes(payload[6:7], 'little', signed=True)
        raw_y = int.from_bytes(payload[7:8], 'little', signed=True)
        raw_quality = payload[8]
            
        return (f"Status: 0x{status:02X} ({status_desc})\n"
                f"Motion X: {motion_x} pixels\n"
                f"Motion Y: {motion_y} pixels\n"
                f"Motion Quality: {motion_quality}%\n"
                f"Raw X: {raw_x}\n"
                f"Raw Y: {raw_y}\n"
                f"Raw Quality: {raw_quality}%")
    return MSG_INVALID_PAYLOAD

def decode_msp2_motor_output_reordering_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request Motor Output Reordering"
    return MSG_INVALID_PAYLOAD

def decode_msp2_motor_output_reordering_response(payload: bytes) -> str:
    if len(payload) >= 1:  # At least need the length byte
        num_motors = payload[0]  # First byte is number of motors
        if len(payload) >= num_motors + 1:  # Make sure we have enough bytes for all motors
            motor_order = [payload[i+1] for i in range(num_motors)]  # Get motor order starting after length byte
            return f"Motor Output Reordering ({num_motors} motors): {motor_order}"
    return MSG_INVALID_PAYLOAD

def decode_msp2_get_led_strip_config_values_request(payload: bytes) -> str:
    if len(payload) == 0:
        return "Request for LED Strip Configuration Values"
    return MSG_INVALID_PAYLOAD

def decode_msp2_get_led_strip_config_values_response(payload: bytes) -> str:
    if len(payload) >= 5:  # 1 byte brightness + 2 bytes delta + 2 bytes freq
        brightness = payload[0]
        rainbow_delta = int.from_bytes(payload[1:3], 'little')
        rainbow_freq = int.from_bytes(payload[3:5], 'little')
        
        return (f"LED Strip Config Values:\n"
                f"  Brightness: {brightness}\n"
                f"  Rainbow Delta: {rainbow_delta}\n"
                f"  Rainbow Frequency: {rainbow_freq}")
    return MSG_INVALID_PAYLOAD

def decode_msp2_set_led_strip_config_values_request(payload: bytes) -> str:
    if len(payload) >= 5:  # 1 byte brightness + 2 bytes delta + 2 bytes freq
        brightness = payload[0]
        rainbow_delta = int.from_bytes(payload[1:3], 'little')
        rainbow_freq = int.from_bytes(payload[3:5], 'little')
        
        return (f"Set LED Strip Config Values:\n"
                f"  Brightness: {brightness}\n"
                f"  Rainbow Delta: {rainbow_delta}\n"
                f"  Rainbow Frequency: {rainbow_freq}")
    return MSG_INVALID_PAYLOAD

def decode_msp2_set_led_strip_config_values_response(payload: bytes) -> str:
    if len(payload) == 0:
        return "LED Strip Configuration Values Set"
    return MSG_INVALID_PAYLOAD

def decode_msp2_send_dshot_command_request(payload: bytes) -> str:
    """
    Decodes the request to send a DSHOT command.
    
    Payload format from Betaflight source:
    uint8_t commandType (INLINE/BLOCKING)
    uint8_t motorIndex (255/0xFF means all motors)
    uint8_t commandCount
    uint8_t commands[commandCount]
    """
    if len(payload) >= 3:
        command_type = payload[0]
        motor_index = payload[1]
        command_count = payload[2]
        
        if len(payload) < 3 + command_count:
            return MSG_INVALID_PAYLOAD

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

        # Command type names
        command_type_names = {
            0: "INLINE",
            1: "BLOCKING"
        }

        command_type_name = command_type_names.get(command_type, f"UNKNOWN({command_type})")
        target = "All Motors" if motor_index == 255 else f"Motor {motor_index + 1}"

        # Get all commands
        commands = []
        for i in range(command_count):
            cmd = payload[3 + i]
            cmd_name = command_names.get(cmd, f"UNKNOWN({cmd})")
            commands.append(cmd_name)

        result = f"Target: {target}\n"
        result += f"Type: {command_type_name}\n"
        result += f"Commands({command_count}): {', '.join(commands)}"
        return result
    return MSG_INVALID_PAYLOAD

def decode_msp2_send_dshot_command_response(payload: bytes) -> str:
    """
    Decodes the response from sending a DSHOT command.
    The response is empty for success.
    """
    if len(payload) == 0:
        return "Command sent successfully"
    return MSG_INVALID_PAYLOAD

def decode_msp2_set_motor_output_reordering_request(payload: bytes) -> str:
    """
    Decodes the request to set motor output reordering.
    
    Payload format:
    uint8_t count;                  // Number of motors
    uint8_t reordering[count];      // Motor output reordering array
    """
    if len(payload) < 1:
        return MSG_INVALID_PAYLOAD

    count = payload[0]
    if len(payload) < 1 + count:
        return MSG_INVALID_PAYLOAD

    reordering = []
    for i in range(count):
        reordering.append(f"Motor {i+1} -> {payload[i+1]+1}")

    return "Set Motor Output Reordering:\n  " + "\n  ".join(reordering)

def decode_msp2_set_motor_output_reordering_response(payload: bytes) -> str:
    """
    Decodes the response from setting motor output reordering.
    The response is empty for success.
    """
    if len(payload) == 0:
        return "Motor output reordering set successfully"
    return MSG_INVALID_PAYLOAD

def decode_msp2_get_osd_warnings_request(payload: bytes) -> str:
    """
    Decodes the request for OSD warnings.
    """
    if len(payload) == 0:
        return "Request for OSD warnings"
    return MSG_INVALID_PAYLOAD

def decode_msp2_get_osd_warnings_response(payload: bytes) -> str:
    """
    Decodes the OSD warnings response.
    
    Payload format:
    uint32_t warnings;  // Bitfield of active warnings
    """
    if len(payload) >= 4:
        warnings = int.from_bytes(payload[0:4], 'little')
        active_warnings = []
        
        # Warning flags from betaflight/src/main/osd/osd.h
        if warnings & (1 << 0): active_warnings.append("ARMING DISABLED")
        if warnings & (1 << 1): active_warnings.append("BATTERY CRITICAL")
        if warnings & (1 << 2): active_warnings.append("BATTERY WARNING")
        if warnings & (1 << 3): active_warnings.append("FAIL-SAFE")
        if warnings & (1 << 4): active_warnings.append("CRASH FLIP")
        if warnings & (1 << 5): active_warnings.append("ESC FAIL")
        if warnings & (1 << 6): active_warnings.append("CORE TEMP")
        if warnings & (1 << 7): active_warnings.append("RC SMOOTHING")
        if warnings & (1 << 8): active_warnings.append("FAIL-SAFE")
        if warnings & (1 << 9): active_warnings.append("LAUNCH CONTROL")
        if warnings & (1 << 10): active_warnings.append("GPS RESCUE")
        if warnings & (1 << 11): active_warnings.append("RESC FAIL")
        if warnings & (1 << 12): active_warnings.append("FAIL-SAFE")
        if warnings & (1 << 13): active_warnings.append("RPM FILTER")
        if warnings & (1 << 14): active_warnings.append("BATTERY CRITICAL")
        if warnings & (1 << 15): active_warnings.append("CRASH RECOVERY")
        if warnings & (1 << 16): active_warnings.append("ESC RPM")
        if warnings & (1 << 17): active_warnings.append("ESC RPM")
        if warnings & (1 << 18): active_warnings.append("RSSI")
        if warnings & (1 << 19): active_warnings.append("SERVO")
        if warnings & (1 << 20): active_warnings.append("GOVERNOR")
        if warnings & (1 << 21): active_warnings.append("ESC RPM")
        if warnings & (1 << 22): active_warnings.append("ESC RPM")
        if warnings & (1 << 23): active_warnings.append("ESC RPM")
        if warnings & (1 << 24): active_warnings.append("ESC RPM")
        if warnings & (1 << 25): active_warnings.append("ESC RPM")
        if warnings & (1 << 26): active_warnings.append("ESC RPM")
        if warnings & (1 << 27): active_warnings.append("ESC RPM")
        if warnings & (1 << 28): active_warnings.append("ESC RPM")
        if warnings & (1 << 29): active_warnings.append("ESC RPM")
        if warnings & (1 << 30): active_warnings.append("ESC RPM")
        if warnings & (1 << 31): active_warnings.append("ESC RPM")
        
        if active_warnings:
            return "Active OSD Warnings:\n  " + "\n  ".join(active_warnings)
        return "No active OSD warnings"
    return MSG_INVALID_PAYLOAD

def decode_msp2_set_text_request(payload: bytes) -> str:
    """
    Decodes the request to set text.
    
    Payload format:
    char text[];  // Null-terminated string
    """
    try:
        text = payload.decode('ascii', 'replace').rstrip('\x00')
        return f'Set Text: "{text}"'
    except:
        return MSG_INVALID_PAYLOAD

def decode_msp2_set_text_response(payload: bytes) -> str:
    """
    Decodes the response from setting text.
    The response is empty for success.
    """
    if len(payload) == 0:
        return "Text set successfully"
    return MSG_INVALID_PAYLOAD

def decode_msp2_mcu_info_request(payload: bytes) -> str:
    """
    Decodes the request for MCU information.
    """
    if len(payload) == 0:
        return "Request for MCU information"
    return MSG_INVALID_PAYLOAD

def decode_msp2_mcu_info_response(payload: bytes) -> str:
    """
    Decodes the MCU information response.
    
    Payload format:
    uint8_t mcuTypeId;             // MCU type ID
    uint32_t configurationState;    // Configuration state
    uint8_t mcuType[4];            // MCU type string (e.g., "F7  ")
    """
    if len(payload) >= 6:
        mcu_type_id = payload[0]
        config_state = int.from_bytes(payload[1:5], 'little')
        mcu_type = payload[5:9].decode('ascii', 'replace').rstrip('\x00') if len(payload) >= 9 else "Unknown"
        
        return (f"MCU Information:\n"
                f"  Type ID: {mcu_type_id}\n"
                f"  Config State: 0x{config_state:08X}\n"
                f"  MCU Type: {mcu_type}")
    return MSG_INVALID_PAYLOAD

def decode_msp2_betaflight_bind_request(payload: bytes) -> str:
    """
    Decodes the request to bind receiver.
    """
    if len(payload) == 0:
        return "Request to bind receiver"
    return MSG_INVALID_PAYLOAD

def decode_msp2_betaflight_bind_response(payload: bytes) -> str:
    """
    Decodes the response from binding receiver.
    The response is empty for success.
    """
    if len(payload) == 0:
        return "Bind command sent successfully"
    return MSG_INVALID_PAYLOAD

# ---------------------------
# MSP2_GET_OSD_WARNINGS
# Betaflight: src/main/msp/msp2_osd.c:50
# ---------------------------

# ---------------------------
# MSP2_GET_LED_STRIP_CONFIG_VALUES
# Betaflight: src/main/msp/msp2_led.c:50
# ---------------------------

# ---------------------------
# MSP2_SET_LED_STRIP_CONFIG_VALUES
# Betaflight: src/main/msp/msp2_led.c:100
# ---------------------------

# ---------------------------
# MSP2_MOTOR_OUTPUT_REORDERING
# Betaflight: src/main/msp/msp2_motor.c:50
# ---------------------------

# ---------------------------
# MSP2_RC_COMMAND
# Betaflight: src/main/msp/msp2_rc.c:50
# ---------------------------

# ---------------------------
# MSP2_SEND_DSHOT_COMMAND
# Betaflight: src/main/msp/msp2_motor.c:100
# ---------------------------

# ---------------------------
# MSP2_SENSOR_CONFIG_ACTIVE
# Command: src/main/msp/msp_protocol_v2_betaflight.h
# Implementation: src/main/msp/msp.c:2100 (processOutCommand)
# ---------------------------

# ---------------------------
# MSP2_SENSOR_GPS
# Command: src/main/msp/msp_protocol_v2_common.h
# Implementation: src/main/msp/msp.c:1500 (processOutCommand)
# ---------------------------

# ---------------------------
# MSP2_SENSOR_RANGEFINDER_LIDARMT
# Command: src/main/msp/msp_protocol_v2_common.h
# Implementation: src/main/msp/msp.c:1600 (processOutCommand)
# ---------------------------

# ---------------------------
# MSP2_SENSOR_OPTICALFLOW
# Command: src/main/msp/msp_protocol_v2_betaflight.h
# Implementation: src/main/msp/msp.c:1700 (processOutCommand)
# ---------------------------

# ---------------------------
# MSP2_SENSOR_OPTICALFLOW_MT
# Command: src/main/msp/msp_protocol_v2_common.h
# Implementation: src/main/msp/msp.c:1800 (processOutCommand)
# ---------------------------

# ---------------------------
# MSP2_SET_LED_STRIP_CONFIG_VALUES
# Betaflight: src/main/msp/msp2_led.c:100
# ---------------------------

# ---------------------------
# MSP2_SET_MOTOR_OUTPUT_REORDERING
# Betaflight: src/main/msp/msp2_motor.c:150
# ---------------------------

# ---------------------------
# MSP2_SET_TEXT
# Betaflight: src/main/msp/msp2_common.c:800
# ---------------------------

# ---------------------------
# MSP2_STATUS
# Betaflight: src/main/msp/msp2_status.c:50
# ---------------------------

# ---------------------------
# MSP2_VTX_CONFIG
# Betaflight: src/main/msp/msp2_vtx.c:100
# ---------------------------

# ---------------------------
# MSP2_BETAFLIGHT_RATES
# Betaflight: src/main/msp/msp2_betaflight.c:350
# ---------------------------

# ---------------------------
# MSP2_BETAFLIGHT_RX_MAP
# Betaflight: src/main/msp/msp2_betaflight.c:400
# ---------------------------

# ---------------------------
# MSP2_BLACKBOX_CONFIG
# Betaflight: src/main/msp/msp2_blackbox.c:50
# ---------------------------

# ---------------------------
# MSP2_COMMON_ANALOG
# Betaflight: src/main/msp/msp2_common.c:50
# ---------------------------

# ---------------------------
# MSP2_COMMON_ATTITUDE
# Betaflight: src/main/msp/msp2_common.c:100
# ---------------------------

# ---------------------------
# MSP2_COMMON_PG_LIST
# Betaflight: src/main/msp/msp2_common.c:250
# ---------------------------

# ---------------------------
# MSP2_COMMON_RAW_IMU
# Betaflight: src/main/msp/msp2_common.c:300
# ---------------------------

# ---------------------------
# MSP2_COMMON_SERVO
# Betaflight: src/main/msp/msp2_common.c:450
# ---------------------------

# ---------------------------
# MSP2_COMMON_SETTING
# Betaflight: src/main/msp/msp2_common.c:500
# ---------------------------

# ---------------------------
# MSP2_COMMON_SETTING_INFO
# Betaflight: src/main/msp/msp2_common.c:550
# ---------------------------

# ---------------------------
# MSP2_COMMON_STATUS
# Betaflight: src/main/msp/msp2_common.c:600
# ---------------------------

# ---------------------------
# MSP2_COMMON_UID
# Betaflight: src/main/msp/msp2_common.c:650
# ---------------------------
