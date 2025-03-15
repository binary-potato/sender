import streamlit as st
import serial
import time
import json
import threading

# App title and description
st.title("LoRa Sender")
st.write("This app sends commands to a LoRa receiver device and displays responses.")

# Sidebar for configuration
with st.sidebar:
    st.header("Device Configuration")
    serial_port = st.text_input("Serial Port", value="/dev/ttyUSB0", 
                               help="Example: COM3 (Windows) or /dev/ttyUSB0 (Linux/Mac)")
    baud_rate = st.selectbox("Baud Rate", options=[9600, 57600, 115200], index=2)
    
    # LoRa specific settings
    st.subheader("LoRa Settings")
    address = st.number_input("Device Address", min_value=1, max_value=65535, value=1)
    network_id = st.number_input("Network ID", min_value=0, max_value=16, value=0)
    spreading_factor = st.selectbox("Spreading Factor", options=[7, 8, 9, 10, 11, 12], index=5)
    bandwidth = st.selectbox("Bandwidth", options=["125 kHz", "250 kHz", "500 kHz"], index=0)
    coding_rate = st.selectbox("Coding Rate", options=["4/5", "4/6", "4/7", "4/8"], index=0)
    
    # Convert bandwidth to parameter value
    bandwidth_map = {"125 kHz": 7, "250 kHz": 8, "500 kHz": 9}
    bandwidth_value = bandwidth_map[bandwidth]
    
    # Convert coding rate to parameter value
    coding_rate_map = {"4/5": 1, "4/6": 2, "4/7": 3, "4/8": 4}
    coding_rate_value = coding_rate_map[coding_rate]

# Function to initialize the LoRa module
def initialize_lora():
    try:
        ser = serial.Serial(serial_port, baudrate=baud_rate, timeout=1)
        time.sleep(1)
        
        # Reset module
        ser.write(b"AT+RESET\r\n")
        time.sleep(1)
        response = ser.readline().decode().strip()
        st.session_state.log.append(f"Reset: {response}")
        
        # Set address
        ser.write(f"AT+ADDRESS={address}\r\n".encode())
        time.sleep(0.5)
        response = ser.readline().decode().strip()
        st.session_state.log.append(f"Set Address: {response}")
        
        # Set network ID
        ser.write(f"AT+NETWORKID={network_id}\r\n".encode())
        time.sleep(0.5)
        response = ser.readline().decode().strip()
        st.session_state.log.append(f"Set Network ID: {response}")
        
        # Set parameters (SF, BW, CR, Preamble)
        ser.write(f"AT+PARAMETER={spreading_factor},{bandwidth_value},{coding_rate_value},7\r\n".encode())
        time.sleep(0.5)
        response = ser.readline().decode().strip()
        st.session_state.log.append(f"Set Parameters: {response}")
        
        # Get version info
        ser.write(b"AT+VER\r\n")
        time.sleep(0.5)
        response = ser.readline().decode().strip()
        st.session_state.log.append(f"Module Version: {response}")
        
        return ser
    except Exception as e:
        st.error(f"Failed to initialize: {str(e)}")
        return None

# Function to send a message
def send_message(ser, dest_addr, message):
    command = f"AT+SEND={dest_addr},{len(message)},{message}\r\n"
    ser.write(command.encode())
    time.sleep(0.5)
    response = ser.readline().decode().strip()
    return response

# Function to wait for and parse a response
def wait_for_response(ser, timeout=30):
    start_time = time.time()
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    while time.time() - start_time < timeout:
        # Update progress bar
        elapsed = time.time() - start_time
        progress = min(elapsed / timeout, 1.0)
        progress_bar.progress(progress)
        status_text.text(f"Waiting for response... ({int(elapsed)}s / {timeout}s)")
        
        if ser.in_waiting > 0:
            data = ser.readline().decode().strip()
            
            # Check if it's a received message
            if data.startswith("+RCV"):
                progress_bar.progress(1.0)
                status_text.text("Response received!")
                
                try:
                    # Format: +RCV=<addr>,<length>,<data>,<rssi>,<snr>
                    parts = data.split(",")
                    src_addr = parts[0].split("=")[1]
                    length = parts[1]
                    message = ",".join(parts[2:-2])  # Join parts that may contain commas
                    rssi = parts[-2]
                    snr = parts[-1]
                    
                    return {
                        "source": src_addr,
                        "message": message,
                        "rssi": rssi,
                        "snr": snr
                    }
                except Exception as e:
                    return {"error": f"Failed to parse response: {str(e)}"}
            else:
                # Other module output
                st.session_state.log.append(f"Module: {data}")
                
        time.sleep(0.1)
    
    progress_bar.progress(1.0)
    status_text.text("Timeout: No response received.")
    return None

# Initialize session state
if 'initialized' not in st.session_state:
    st.session_state.initialized = False
    st.session_state.log = []
    st.session_state.receiver_addr = None
    st.session_state.last_response = None

# Main app layout
tabs = st.tabs(["Connection", "Send Command", "Response", "Logs"])

with tabs[0]:
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Module Status")
        status = "Disconnected"
        if st.session_state.initialized:
            status = "Connected"
        st.write(f"Status: {status}")
        
        if not st.session_state.initialized:
            if st.button("Connect to LoRa Module"):
                ser = initialize_lora()
                if ser:
                    st.session_state.ser = ser
                    st.session_state.initialized = True
                    st.experimental_rerun()
        else:
            if st.button("Disconnect"):
                st.session_state.ser.close()
                st.session_state.initialized = False
                st.session_state.receiver_addr = None
                st.experimental_rerun()
    
    with col2:
        st.subheader("Receiver Connection")
        
        receiver_code = st.text_input("Enter Receiver's Connection Code")
        
        if st.button("Connect to Receiver") and receiver_code:
            try:
                # Convert hex code to address
                receiver_addr = int(receiver_code, 16)
                st.session_state.receiver_addr = receiver_addr
                st.success(f"Connected to receiver with address: {receiver_addr}")
            except ValueError:
                st.error("Invalid connection code. Please enter a valid hexadecimal code.")

with tabs[1]:
    st.subheader("Send Command")
    
    if not st.session_state.initialized:
        st.warning("Please connect to the LoRa module first.")
    elif not st.session_state.receiver_addr:
        st.warning("Please connect to a receiver first.")
    else:
        # Command selection
        command_type = st.selectbox(
            "Select Command Type",
            ["Standard Commands", "Custom Command"]
        )
        
        if command_type == "Standard Commands":
            standard_command = st.selectbox(
                "Select Command",
                ["Read Temperature", "Read Humidity", "Read BME280 Sensor", "Control GPIO"]
            )
            
            # Set command details based on selection
            if standard_command == "Read Temperature":
                command_json = json.dumps({"command": "read", "sensor": "temperature"})
            elif standard_command == "Read Humidity":
                command_json = json.dumps({"command": "read", "sensor": "humidity"})
            elif standard_command == "Read BME280 Sensor":
                command_json = json.dumps({"command": "read", "sensor": "BME280"})
            elif standard_command == "Control GPIO":
                gpio_pin = st.number_input("GPIO Pin Number", min_value=0, max_value=40, value=13)
                gpio_state = st.selectbox("Pin State", ["HIGH", "LOW"])
                command_json = json.dumps({"command": "gpio", "pin": gpio_pin, "state": gpio_state})
        else:
            # Custom command JSON editor
            st.write("Enter custom JSON command:")
            command_json = st.text_area(
                "Custom JSON",
                value="""{"command": "custom", "param": "example", "value": "test"}""",
                height=150
            )
            
            # Validate JSON
            try:
                json.loads(command_json)
                st.success("Valid JSON format")
            except json.JSONDecodeError as e:
                st.error(f"Invalid JSON: {str(e)}")
        
        # Send button
        if st.button("Send Command"):
            st.session_state.log.append(f"Sending to {st.session_state.receiver_addr}: {command_json}")
            
            # Send the command
            result = send_message(st.session_state.ser, st.session_state.receiver_addr, command_json)
            st.session_state.log.append(f"Send result: {result}")
            
            # Wait for response
            with st.spinner("Waiting for response..."):
                response = wait_for_response(st.session_state.ser)
                
                if response:
                    st.session_state.log.append(f"Response received: {response}")
                    st.session_state.last_response = response
                    st.success("Response received! See the Response tab for details.")
                else:
                    st.error("No response received within the timeout period.")

with tabs[2]:
    st.subheader("Response")
    
    if st.session_state.last_response:
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("Response Details:")
            st.write(f"Source Address: {st.session_state.last_response.get('source', 'N/A')}")
            st.write(f"Signal Strength (RSSI): {st.session_state.last_response.get('rssi', 'N/A')} dBm")
            st.write(f"Signal-to-Noise Ratio: {st.session_state.last_response.get('snr', 'N/A')} dB")
        
        with col2:
            try:
                # Try to parse the message as JSON
                if 'message' in st.session_state.last_response:
                    message_json = json.loads(st.session_state.last_response['message'])
                    st.json(message_json)
            except json.JSONDecodeError:
                # If not JSON, show as plain text
                if 'message' in st.session_state.last_response:
                    st.code(st.session_state.last_response['message'])
                else:
                    st.write("No message content available")
    else:
        st.info("No response has been received yet. Send a command first.")

with tabs[3]:
    st.subheader("Communication Logs")
    
    # Display logs in reverse order (newest first)
    for log_entry in reversed(st.session_state.log):
        st.text(log_entry)
    
    if st.button("Clear Logs"):
        st.session_state.log = []
        st.experimental_rerun()
