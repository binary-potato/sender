import streamlit as st
import serial
import time
import json
import random
import threading

# App title and description
st.title("LoRa Receiver")
st.write("This app listens for messages from another LoRa device and processes requests according to custom rules.")

# Sidebar for configuration
with st.sidebar:
    st.header("Device Configuration")
    serial_port = st.text_input("Serial Port", value="/dev/ttyUSB0", 
                               help="Example: COM3 (Windows) or /dev/ttyUSB0 (Linux/Mac)")
    baud_rate = st.selectbox("Baud Rate", options=[9600, 57600, 115200], index=2)
    
    # LoRa specific settings
    st.subheader("LoRa Settings")
    address = st.number_input("Device Address", min_value=1, max_value=65535, value=random.randint(100, 65535))
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

# Function to handle received data
def handle_request(request_json):
    try:
        request = json.loads(request_json)
        
        # Execute custom handler if available
        if 'custom_handler' in st.session_state and st.session_state.custom_handler.strip():
            try:
                # Create a local scope with the request variable
                local_vars = {"request": request, "random": random}
                exec(st.session_state.custom_handler, globals(), local_vars)
                
                # Get the result from the local scope
                if 'result' in local_vars:
                    return json.dumps(local_vars['result'])
                else:
                    return json.dumps({"status": "error", "message": "Custom handler didn't set 'result'"})
            except Exception as e:
                return json.dumps({"status": "error", "message": f"Custom handler error: {str(e)}"})
        
        # Default handlers for common requests
        if request.get("command") == "read":
            sensor = request.get("sensor", "")
            if sensor == "temperature":
                return json.dumps({
                    "status": "success", 
                    "temperature": round(random.uniform(20.0, 30.0), 1),
                    "unit": "C"
                })
            elif sensor == "humidity":
                return json.dumps({
                    "status": "success", 
                    "humidity": round(random.uniform(30.0, 80.0), 1),
                    "unit": "%"
                })
            elif sensor in ["BME280", "DHT22"]:
                return json.dumps({
                    "status": "success", 
                    "temperature": round(random.uniform(20.0, 30.0), 1),
                    "humidity": round(random.uniform(30.0, 80.0), 1),
                    "pressure": round(random.uniform(990.0, 1010.0), 1) if sensor == "BME280" else None
                })
        elif request.get("command") == "gpio":
            pin = request.get("pin")
            state = request.get("state")
            return json.dumps({
                "status": "success",
                "message": f"Set GPIO pin {pin} to {state}"
            })
            
        # Default response for unknown commands
        return json.dumps({
            "status": "error",
            "message": "Unknown command or invalid request"
        })
        
    except json.JSONDecodeError:
        return json.dumps({"status": "error", "message": "Invalid JSON format"})
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})

# Function to send a response
def send_response(ser, address, message):
    command = f"AT+SEND={address},{len(message)},{message}\r\n"
    ser.write(command.encode())
    time.sleep(0.5)
    response = ser.readline().decode().strip()
    return response

# Function to read messages from the serial port
def message_listener(ser):
    while not st.session_state.stop_thread:
        if ser.in_waiting > 0:
            data = ser.readline().decode().strip()
            
            # Check if it's a received message
            if data.startswith("+RCV"):
                # Parse the received data
                try:
                    # Format: +RCV=<addr>,<length>,<data>,<rssi>,<snr>
                    parts = data.split(",")
                    src_addr = parts[0].split("=")[1]
                    length = parts[1]
                    message = ",".join(parts[2:-2])  # Join parts that may contain commas
                    rssi = parts[-2]
                    snr = parts[-1]
                    
                    # Add to logs
                    st.session_state.log.append(f"Received from {src_addr}: {message}")
                    
                    # Process request
                    response = handle_request(message)
                    st.session_state.log.append(f"Sending response: {response}")
                    
                    # Send response
                    result = send_response(ser, src_addr, response)
                    st.session_state.log.append(f"Send result: {result}")
                    
                except Exception as e:
                    st.session_state.log.append(f"Error processing message: {str(e)}")
            else:
                # Other module output
                st.session_state.log.append(f"Module: {data}")
                
        time.sleep(0.1)

# Initialize session state
if 'initialized' not in st.session_state:
    st.session_state.initialized = False
    st.session_state.log = []
    st.session_state.stop_thread = False
    st.session_state.custom_handler = """# This is your custom handler code
# The 'request' variable contains the parsed JSON request
# You need to set 'result' to the response you want to send

command = request.get("command", "")

if command == "custom":
    param = request.get("param", "")
    value = request.get("value", "")
    
    # Example custom processing
    result = {
        "status": "success",
        "command": command,
        "processed": f"Processed {param} with value {value}",
        "timestamp": time.time()
    }
elif command == "calculate":
    # Example calculation handler
    x = request.get("x", 0)
    y = request.get("y", 0)
    operation = request.get("operation", "add")
    
    if operation == "add":
        result = {"status": "success", "result": x + y}
    elif operation == "multiply":
        result = {"status": "success", "result": x * y}
    else:
        result = {"status": "error", "message": f"Unknown operation: {operation}"}
# The default handlers will process other standard commands
"""

# Main app layout
tabs = st.tabs(["Connection", "Custom Handler", "Logs"])

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
                    
                    # Start listener thread
                    st.session_state.stop_thread = False
                    thread = threading.Thread(target=message_listener, args=(ser,))
                    thread.daemon = True
                    thread.start()
                    st.session_state.thread = thread
                    
                    st.experimental_rerun()
        else:
            if st.button("Disconnect"):
                st.session_state.stop_thread = True
                time.sleep(0.5)  # Give thread time to stop
                st.session_state.ser.close()
                st.session_state.initialized = False
                st.experimental_rerun()
    
    with col2:
        st.subheader("Connection Code")
        if st.session_state.initialized:
            # Generate a hex code from the address
            connection_code = hex(address)[2:].upper()
            st.code(connection_code, language="text")
            st.info("Share this code with the sender application")
        else:
            st.write("Connect to generate a code")

with tabs[1]:
    st.subheader("Custom Request Handler")
    st.write("Define how to process incoming requests with custom Python code")
    
    custom_code = st.text_area("Handler Code", 
                              value=st.session_state.custom_handler,
                              height=400)
    
    if st.button("Save Handler"):
        st.session_state.custom_handler = custom_code
        st.success("Custom handler saved!")

with tabs[2]:
    st.subheader("Communication Logs")
    
    # Display logs in reverse order (newest first)
    for log_entry in reversed(st.session_state.log):
        st.text(log_entry)
    
    if st.button("Clear Logs"):
        st.session_state.log = []
        st.experimental_rerun()
