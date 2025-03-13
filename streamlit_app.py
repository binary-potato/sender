import streamlit as st
import pyrebase
import random
import string
import time
import qrcode
from io import BytesIO
import base64
import uuid
import threading
import queue
import json
import os

# Conditionally import Meshtastic
try:
    import meshtastic
    import meshtastic.serial_interface
    MESHTASTIC_AVAILABLE = True
except ImportError:
    MESHTASTIC_AVAILABLE = False
    st.warning("Meshtastic library not installed. To use Meshtastic functionality, install it with: pip install meshtastic")

# Conditionally import RLYR 998 library
try:
    import rlyr998
    RLYR998_AVAILABLE = True
except ImportError:
    RLYR998_AVAILABLE = False
    st.warning("RLYR 998 library not installed. To use RLYR 998 functionality, install it with: pip install rlyr998")

# Mock radio implementation for development/testing
class MockRadio:
    def __init__(self):
        self.message_queue = queue.Queue()
        self.connected = True
        
    def send_message(self, recipient, message):
        # In a real implementation, this would send data via the radio hardware
        print(f"MOCK RADIO: Sending to {recipient}: {message}")
        # Simulate successful transmission
        return True
        
    def check_messages(self):
        # In a real implementation, this would check for incoming radio transmissions
        # For testing, we'll just return any messages in our mock queue
        if not self.message_queue.empty():
            return self.message_queue.get()
        return None
    
    def add_test_message(self, sender, message):
        # This is just for testing - lets us simulate receiving a message
        self.message_queue.put({"sender": sender, "message": message})
    
    def close(self):
        # Nothing to do for mock radio
        pass

# Meshtastic implementation
class MeshtasticRadio:
    def __init__(self, port=None, timeout=5):
        self.interface = None
        self.connected = False
        self.message_queue = queue.Queue()
        self.node_info = {}
        
        # Try to connect to Meshtastic device
        try:
            self.interface = meshtastic.serial_interface.SerialInterface(port, debugOut=False)
            self.connected = True
            
            # Set up message receiving
            self.interface.onReceive = self.on_message_received
            
            # Get our node info
            self.node_info = self.interface.myInfo
            print(f"Connected to Meshtastic node: {self.node_info.get('user', {}).get('longName', 'Unknown')}")
            
        except Exception as e:
            print(f"Error connecting to Meshtastic: {e}")
    
    def on_message_received(self, packet, interface):
        """Callback for when a message is received from the mesh network"""
        try:
            # Extract the message data
            sender = packet.get('fromId', 'unknown')
            message = packet.get('decoded', {}).get('text', '')
            
            # Add to our queue
            self.message_queue.put({"sender": sender, "message": message})
            
            print(f"Received message from {sender}: {message}")
        except Exception as e:
            print(f"Error processing received message: {e}")
    
    def send_message(self, recipient, message):
        if not self.connected or self.interface is None:
            return False
            
        try:
            # In Meshtastic, we typically broadcast to the entire mesh
            # You can implement direct messaging if you know the node IDs
            self.interface.sendText(message)
            return True
        except Exception as e:
            print(f"Error sending Meshtastic message: {e}")
            return False
    
    def check_messages(self):
        # Just check our queue that's populated by the callback
        if not self.message_queue.empty():
            return self.message_queue.get()
        return None
    
    def close(self):
        if self.interface:
            self.interface.close()

# RLYR 998 implementation
class RLYR998Radio:
    def __init__(self, port=None, baudrate=9600):
        self.interface = None
        self.connected = False
        self.message_queue = queue.Queue()
        self.device_info = {}
        
        # Try to connect to RLYR 998 device
        if RLYR998_AVAILABLE:
            try:
                self.interface = rlyr998.SerialInterface(port, baudrate=baudrate)
                self.connected = True
                
                # Set up message receiving
                self.interface.register_callback(self.on_message_received)
                
                # Get device information
                self.device_info = {
                    "device_id": self.interface.get_device_id(),
                    "firmware_version": self.interface.get_firmware_version(),
                    "network_id": self.interface.get_network_id()
                }
                print(f"Connected to RLYR 998 device: {self.device_info['device_id']}")
                
                # Initialize network settings
                self.interface.set_power_level(3)  # Medium power level
                self.interface.set_frequency_hopping(True)  # Enable frequency hopping for better reliability
                
            except Exception as e:
                print(f"Error connecting to RLYR 998: {e}")
        else:
            print("RLYR 998 library not available")
    
    def on_message_received(self, message_data):
        """Callback for when a message is received from the RLYR network"""
        try:
            # Extract the message data
            sender = message_data.get('sender_id', 'unknown')
            message = message_data.get('payload', '')
            
            # Add to our queue
            self.message_queue.put({"sender": sender, "message": message})
            
            print(f"Received RLYR 998 message from {sender}: {message}")
        except Exception as e:
            print(f"Error processing RLYR 998 message: {e}")
    
    def send_message(self, recipient, message):
        if not self.connected or self.interface is None:
            return False
            
        try:
            # For RLYR 998, we can send to specific recipients or broadcast
            if recipient == "broadcast":
                self.interface.broadcast_message(message)
            else:
                self.interface.send_directed_message(recipient, message)
            return True
        except Exception as e:
            print(f"Error sending RLYR 998 message: {e}")
            return False
    
    def check_messages(self):
        # Check our queue that's populated by the callback
        if not self.message_queue.empty():
            return self.message_queue.get()
        return None
    
    def get_network_status(self):
        """Get RLYR 998 network status information"""
        if not self.connected or self.interface is None:
            return {}
            
        try:
            return {
                "signal_strength": self.interface.get_signal_strength(),
                "battery_level": self.interface.get_battery_level(),
                "connected_nodes": self.interface.get_connected_nodes(),
                "packets_sent": self.interface.get_packets_sent(),
                "packets_received": self.interface.get_packets_received(),
                "error_rate": self.interface.get_error_rate()
            }
        except Exception as e:
            print(f"Error getting RLYR 998 network status: {e}")
            return {}
    
    def close(self):
        if self.interface:
            self.interface.close()

# Firebase implementation
class FirebaseComm:
    def __init__(self, config):
        self.firebase = None
        self.db = None
        self.connected = False
        
        try:
            self.firebase = pyrebase.initialize_app(config)
            self.db = self.firebase.database()
            self.connected = True
        except Exception as e:
            print(f"Firebase initialization error: {e}")
    
    def send_message(self, recipient, message):
        if not self.connected or self.db is None:
            return False
            
        try:
            # Parse the message as JSON to extract request_id
            message_data = json.loads(message)
            request_id = message_data.get("request_id", str(uuid.uuid4()))
            
            # Create path in Firebase
            conn_path = f"connections/{recipient}/requests/{request_id}"
            self.db.child(conn_path).set(message_data)
            return True
        except Exception as e:
            print(f"Error sending Firebase message: {e}")
            return False
    
    def check_messages(self, recipient_code):
        if not self.connected or self.db is None:
            return None
            
        try:
            # Get current data
            conn_path = f"connections/{recipient_code}"
            data = self.db.child(conn_path).get().val()
            
            if data and 'requests' in data:
                for request_id, request_data in data['requests'].items():
                    if 'status' in request_data and request_data['status'] == 'pending':
                        # Format like radio message for consistency
                        sender = request_data.get('sender', 'unknown')
                        return {
                            "sender": sender, 
                            "message": json.dumps(request_data)
                        }
        except Exception as e:
            print(f"Error checking Firebase messages: {e}")
            
        return None
    
    def update_request_status(self, recipient, request_id, update_data):
        if not self.connected or self.db is None:
            return False
            
        try:
            conn_path = f"connections/{recipient}/requests/{request_id}"
            self.db.child(conn_path).update(update_data)
            return True
        except Exception as e:
            print(f"Error updating request status: {e}")
            return False
    
    def close(self):
        # Nothing to do for Firebase
        pass

# Firebase configuration - no authentication
def get_firebase_config():
    return {
        "apiKey": os.environ.get("FIREBASE_API_KEY", "AIzaSyBAspGDK14JlqF9RgumIc40DL-SMdshz8c"),
        "authDomain": os.environ.get("FIREBASE_AUTH_DOMAIN", "science-project-c6e47.firebaseapp.com"),
        "databaseURL": os.environ.get("FIREBASE_DATABASE_URL", "https://science-project-c6e47-default-rtdb.firebaseio.com"),
        "storageBucket": os.environ.get("FIREBASE_STORAGE_BUCKET", "science-project-c6e47.firebasestorage.app"),
    }
#apiKey: "AIzaSyBAspGDK14JlqF9RgumIc40DL-SMdshz8c",
  #authDomain: "science-project-c6e47.firebaseapp.com",
  #databaseURL: "https://science-project-c6e47-default-rtdb.firebaseio.com",
  #projectId: "science-project-c6e47",
  #storageBucket: "science-project-c6e47.firebasestorage.app",
  #messagingSenderId: "544287963506",
# Initialize communication method
@st.cache_resource
def initialize_communication(method="mock"):
    if method == "firebase":
        return FirebaseComm(get_firebase_config())
    elif method == "meshtastic":
        if MESHTASTIC_AVAILABLE:
            return MeshtasticRadio()
        else:
            st.error("Meshtastic library not available")
            return MockRadio()
    elif method == "rlyr998":
        if RLYR998_AVAILABLE:
            return RLYR998Radio()
        else:
            st.error("RLYR 998 library not available")
            return MockRadio()
    else:  # Use mock as default/fallback
        return MockRadio()

# Function to generate a random connection code
def generate_connection_code(length=6):
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

# Function to create QR code for a connection code
def generate_qr_code(code):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(code)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert PIL image to base64 string
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    return img_str

# Background thread for checking messages
def background_message_checker(comm, message_queue, code=None, is_firebase=False):
    while True:
        try:
            if is_firebase:
                message = comm.check_messages(code) if code else None
            else:
                message = comm.check_messages()
                
            if message:
                message_queue.put(message)
            time.sleep(0.1)  # Check every 100ms
        except Exception as e:
            print(f"Error in message checker: {e}")
            time.sleep(1)  # Back off on error

# Main app
def main():
    st.title("Cross-Device Communication App")
    
    # Communication method selection
    comm_method = st.sidebar.radio(
        "Communication Method",
        ["Internet (Firebase)", "Local Radio (Meshtastic)", "RLYR 998", "Mock (Testing)"]
    )
    
    # Initialize appropriate communication method
    method_map = {
        "Internet (Firebase)": "firebase",
        "Local Radio (Meshtastic)": "meshtastic",
        "RLYR 998": "rlyr998",
        "Mock (Testing)": "mock"
    }
    
    # Display current method info
    st.sidebar.info(f"Using: {comm_method}")
    
    # Initialize communication
    comm = initialize_communication(method_map[comm_method])
    is_firebase = method_map[comm_method] == "firebase"
    
    # Show connection status
    if comm.connected:
        st.sidebar.success(f"{comm_method} connected and ready")
    else:
        st.sidebar.error(f"{comm_method} not connected")
        if comm_method == "Local Radio (Meshtastic)":
            st.sidebar.info("Make sure your Meshtastic device is connected via USB")
        elif comm_method == "RLYR 998":
            st.sidebar.info("Make sure your RLYR 998 device is connected via USB")
        elif comm_method == "Internet (Firebase)":
            st.sidebar.info("Check your Firebase configuration and internet connection")
    
    # Display RLYR 998 specific information if applicable
    if comm_method == "RLYR 998" and comm.connected:
        with st.sidebar.expander("RLYR 998 Network Status"):
            if hasattr(comm, 'get_network_status'):
                network_status = comm.get_network_status()
                if network_status:
                    st.write(f"Signal Strength: {network_status.get('signal_strength', 'N/A')}%")
                    st.write(f"Battery Level: {network_status.get('battery_level', 'N/A')}%")
                    st.write(f"Connected Nodes: {network_status.get('connected_nodes', 'N/A')}")
                    st.write(f"Packets Sent: {network_status.get('packets_sent', 'N/A')}")
                    st.write(f"Packets Received: {network_status.get('packets_received', 'N/A')}")
                    st.write(f"Error Rate: {network_status.get('error_rate', 'N/A')}%")
    
    # Initialize session state for received messages
    if 'message_queue' not in st.session_state:
        st.session_state.message_queue = queue.Queue()
    
    if 'last_processed' not in st.session_state:
        st.session_state.last_processed = {}
    
    # Reset thread when communication method changes
    current_method_key = f"current_method_{method_map[comm_method]}"
    if current_method_key not in st.session_state:
        # Clear old thread keys
        for key in list(st.session_state.keys()):
            if key.startswith("current_method_") and key != current_method_key:
                del st.session_state[key]
        
        # Stop any existing message thread
        if 'message_thread' in st.session_state and st.session_state.message_thread.is_alive():
            # Can't directly stop thread but will be garbage collected
            pass
        
        # Start new background thread for message checking
        st.session_state[current_method_key] = True
        
        # Start the appropriate thread based on communication method
        receiver_code = st.session_state.get('receiver_code', generate_connection_code())
        thread = threading.Thread(
            target=background_message_checker,
            args=(comm, st.session_state.message_queue, receiver_code, is_firebase),
            daemon=True
        )
        thread.start()
        st.session_state.message_thread = thread
    
    # Create tabs for sender and receiver modes
    tab1, tab2, tab3, tab4 = st.tabs(["Receiver Mode", "Sender Mode", "RLYR 998 Settings", "Test Tools"])
    
    # Receiver Mode
    with tab1:
        st.header("Receiver Mode")
        st.info("Generate a connection code and share it with the sender to receive requests.")
        
        # Session state for connection code
        if 'receiver_code' not in st.session_state:
            st.session_state.receiver_code = generate_connection_code()
            
        # Display the connection code
        st.subheader("Your Connection Code:")
        code_display = st.code(st.session_state.receiver_code, language=None)
        
        # Generate and display QR code
        qr_code = generate_qr_code(st.session_state.receiver_code)
        st.image(f"data:image/png;base64,{qr_code}", caption="Scan this QR code with the sender device")
        
        # Button to generate a new code
        if st.button("Generate New Code"):
            st.session_state.receiver_code = generate_connection_code()
            st.rerun()
        
        # Custom handler settings
        st.subheader("Configure Request Handler")
        handler_type = st.selectbox("Handler Type", ["Echo", "Math Operation", "Text Processing", "Custom"])
        
        custom_handler = ""
        if handler_type == "Math Operation":
            st.info("This handler will perform math operations on numeric input.")
        elif handler_type == "Text Processing":
            st.info("This handler will process text input (uppercase, lowercase, etc).")
        elif handler_type == "Custom":
            custom_handler = st.text_area("Enter custom Python code to process the request:", 
                                          value="def process_request(data):\n    # data contains the request data\n    result = f\"Processed: {data}\"\n    return result")
        
        # Listening state
        if 'listening' not in st.session_state:
            st.session_state.listening = False
        
        # Start/Stop listening
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Start Listening" if not st.session_state.listening else "Stop Listening"):
                st.session_state.listening = not st.session_state.listening
                st.rerun()
        
        with col2:
            status = st.empty()
            if st.session_state.listening:
                status.success(f"Listening for requests via {comm_method}")
            else:
                status.warning("Not listening")
        
        # Request container
        request_container = st.container()
        
        # Check for new requests if listening
        if st.session_state.listening:
            with request_container:
                # Process any messages in the queue
                message_list = []
                while not st.session_state.message_queue.empty():
                    message = st.session_state.message_queue.get()
                    message_list.append(message)
                
                for message in message_list:
                    sender = message.get("sender", "unknown")
                    message_content = message.get("message", "{}")
                    
                    try:
                        # Try to parse the message as JSON
                        data = json.loads(message_content)
                        
                        # Check if this message is for us
                        if data.get("recipient") == st.session_state.receiver_code:
                            request_id = data.get("request_id", str(uuid.uuid4()))
                            
                            # Skip already processed requests
                            if request_id in st.session_state.last_processed:
                                continue
                            
                            # Process the request based on handler type
                            request_data = data.get("data", "")
                            result = ""
                            
                            if handler_type == "Echo":
                                result = f"Echo: {request_data}"
                            elif handler_type == "Math Operation":
                                try:
                                    # Use safer eval with limited builtins
                                    safe_globals = {
                                        "__builtins__": {
                                            k: v for k, v in __builtins__.items() 
                                            if k in ['abs', 'all', 'any', 'divmod', 'max', 'min', 
                                                    'pow', 'round', 'sum']
                                        }
                                    }
                                    safe_globals.update({
                                        'int': int, 'float': float, 'complex': complex,
                                        'bool': bool, 'str': str
                                    })
                                    result = f"Result: {eval(request_data, safe_globals)}"
                                except Exception as math_error:
                                    result = f"Invalid math expression: {str(math_error)}"
                            elif handler_type == "Text Processing":
                                text = request_data
                                result = f"Uppercase: {text.upper()}, Lowercase: {text.lower()}, Length: {len(text)}"
                            elif handler_type == "Custom":
                                try:
                                    # Execute custom code
                                    local_vars = {'data': request_data, 'result': ''}
                                    exec(custom_handler, {'__builtins__': {}}, local_vars)
                                    result = local_vars.get('result', 'No result provided')
                                except Exception as e:
                                    result = f"Error in custom handler: {str(e)}"
                            
                            # Display request and result
                            st.write(f"📬 Request received from {sender}: {request_data}")
                            st.write(f"✅ Response: {result}")
                            
                            # Send response back
                            response_data = {
                                "recipient": sender,
                                "request_id": request_id,
                                "result": result,
                                "status": "completed",
                                "timestamp": int(time.time() * 1000)
                            }
                            
                            if is_firebase:
                                # For Firebase, update the request in the database
                                comm.update_request_status(
                                    st.session_state.receiver_code, 
                                    request_id,
                                    {
                                        'status': 'completed',
                                        'result': result,
                                        'completed_at': int(time.time() * 1000)
                                    }
                                )
                            else:
                                # For radio methods, send a response message
                                comm.send_message(sender, json.dumps(response_data))
                            
                            # Mark as processed
                            st.session_state.last_processed[request_id] = True
                    except json.JSONDecodeError:
                        # Not JSON or not for us - ignore
                        pass
                    except Exception as e:
                        st.error(f"Error processing message: {str(e)}")
    
    # Sender Mode
    with tab2:
        st.header("Sender Mode")
        st.info("Enter the connection code from the receiver device to send requests.")
        
        # Input for connection code
        connection_code = st.text_input("Connection Code", placeholder="Enter the code from the receiver")
        
        # Only show the rest if a connection code is entered
        if connection_code:
            # Input for the request
            request_data = st.text_area("Request Data", placeholder="Enter your request data here...")
            
            # Set sender ID if not already set
            if 'sender_id' not in st.session_state:
                st.session_state.sender_id = generate_connection_code()
                
            # Display sender ID
            st.info(f"Your Sender ID: {st.session_state.sender_id}")
            
            # RLYR 998 specific options
            if comm_method == "RLYR 998":
                st.subheader("RLYR 998 Options")
                priority = st.select_slider(
                    "Message Priority", 
                    options=["Low", "Medium", "High", "Critical"],
                    value="Medium"
                )
                
                ack_mode = st.checkbox("Require Acknowledgment", value=True)
                retry_count = st.slider("Retry Count", min_value=0, max_value=10, value=3)
                hop_limit = st.slider("Maximum Hops", min_value=1, max_value=10, value=3)
            
            # Button to send the request
            if st.button("Send Request"):
                try:
                    # Generate a unique ID for this request
                    request_id = str(uuid.uuid4())
                    
                    # Create the request data
                    request_object = {
                        "recipient": connection_code,
                        "sender": st.session_state.sender_id,
                        "request_id": request_id,
                        "data": request_data,
                        "status": "pending",
                        "timestamp": int(time.time() * 1000)
                    }
                    
                    # Add RLYR 998 specific fields if applicable
                    if comm_method == "RLYR 998":
                        request_object.update({
                            "priority": priority.lower(),
                            "ack_required": ack_mode,
                            "retry_count": retry_count,
                            "hop_limit": hop_limit
                        })
                    
                    # Convert to JSON
                    request_json = json.dumps(request_object)
                    
                    # Send the request
                    if comm.send_message(connection_code, request_json):
                        st.success(f"Request sent via {comm_method}! Waiting for response...")
                        
                        # Wait for response
                        response_placeholder = st.empty()
                        
                        # Poll for response
                        response_received = False
                        start_time = time.time()
                        
                        while time.time() - start_time < 30:  # Wait for max 30 seconds
                            # For Firebase, check the database directly
                            if is_firebase:
                                try:
                                    # Check the request status in Firebase
                                    conn_path = f"connections/{connection_code}/requests/{request_id}"
                                    current_data = comm.db.child(conn_path).get().val()
                                    
                                    if current_data and current_data.get('status') == 'completed':
                                        response_placeholder.success(f"Response received: {current_data.get('result')}")
                                        response_received = True
                                        break
                                except Exception as e:
                                    print(f"Error checking Firebase response: {e}")
                            else:
                                # For radio methods, check the message queue
                                while not st.session_state.message_queue.empty():
                                    message = st.session_state.message_queue.get()
                                    
                                    try:
                                        # Try to parse the message as JSON
                                        message_content = message.get("message", "{}")
                                        data = json.loads(message_content)
                                        
                                        # Check if this is a response to our request
                                        if (data.get("recipient") == st.session_state.sender_id and 
                                            data.get("request_id") == request_id and
                                            data.get("status") == "completed"):
                                            
                                            response_placeholder.success(f"Response received: {data.get('result')}")
                                            response_received = True
                                            break
                                    except json.JSONDecodeError:
                                        # Not JSON or not for us - ignore
                                        pass
                            
                            if response_received:
                                break
                                
                            # Update waiting message with a countdown
                            elapsed = time.time() - start_time
                            remaining = 30 - int(elapsed)
                            response_placeholder.info(f"Waiting for response... ({remaining} seconds remaining)")
                            time.sleep(1)
                            
                        if not response_received:
                            response_placeholder.warning("No response received within timeout period.")
                    else:
                        st.error(f"Failed to send request via {comm_method}")
                
                except Exception as e:
                    st.error(f"Error sending request: {str(e)}")
    
    # RLYR 998 Settings Tab
    with tab3:
        st.header("RLYR 998 Settings")
        
        if comm_method != "RLYR 998":
            st.warning("Please select RLYR 998 as the communication method to configure these settings.")
        else:
            st.info("Configure advanced settings for your RLYR 998 device.")
            
            # Device connection settings
            st.subheader("Device Connection")
            
            # Port selection
            available_ports = ["AUTO"]
            try:
                import serial.tools.list_ports
                ports = list(serial.tools.list_ports.comports())
                available_ports += [p.device for p in ports]
            except:
                available_ports += ["/dev/ttyUSB0", "/dev/ttyACM0", "COM3"]
            
            col1, col2 = st.columns(2)
            with col1:
                selected_port = st.selectbox("Serial Port", available_ports)
            with col2:
                baudrate = st.selectbox("Baud Rate", [9600, 19200, 38400, 57600, 115200], index=4)
            
            if st.button("Connect"):
                # Store settings in session state
                st.session_state.rlyr998_port = selected_port if selected_port != "AUTO" else None
                st.session_state.rlyr998_baudrate = baudrate
                
                # Force reinitialization
                for key in list(st.session_state.keys()):
                    if key.startswith("current_method_"):
                        del st.session_state[key]
                
                st.success("Settings applied. Attempting to connect...")
                st.rerun()
            
            # Network settings
            st.subheader("Network Settings")
            
            col1, col2 = st.columns(2)
            with col1:
                network_id = st.text_input("Network ID", value="998-NET", max_chars=8)
                channel = st.slider("Channel", min_value=1, max_value=32, value=12)
            with col2:
                power_level = st.select_slider
