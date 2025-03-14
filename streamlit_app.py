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
        ["Internet (Firebase)", "Local Radio (Meshtastic)", "Mock (Testing)"]
    )
    
    # Initialize appropriate communication method
    method_map = {
        "Internet (Firebase)": "firebase",
        "Local Radio (Meshtastic)": "meshtastic",
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
        elif comm_method == "Internet (Firebase)":
            st.sidebar.info("Check your Firebase configuration and internet connection")
    
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
    tab1, tab2, tab3 = st.tabs(["Receiver Mode", "Sender Mode", "Test Tools"])
    
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

    # Test Tools Tab (for development/testing without hardware)
    with tab3:
        st.header("Test Tools")
        st.warning("This tab is primarily for testing without actual hardware")
        
        st.subheader("Communication Settings")
        
        # Firebase configuration settings
        if comm_method == "Internet (Firebase)":
            st.subheader("Firebase Configuration")
            with st.expander("Update Firebase Configuration"):
                api_key = st.text_input("API Key", value=get_firebase_config()["apiKey"])
                auth_domain = st.text_input("Auth Domain", value=get_firebase_config()["authDomain"])
                database_url = st.text_input("Database URL", value=get_firebase_config()["databaseURL"])
                storage_bucket = st.text_input("Storage Bucket", value=get_firebase_config()["storageBucket"])
                
                if st.button("Update Firebase Config"):
                    # Set environment variables
                    os.environ["AIzaSyBAspGDK14JlqF9RgumIc40DL-SMdshz8c"] = api_key
                    os.environ["science-project-c6e47.firebaseapp.com"] = auth_domain
                    os.environ["https://science-project-c6e47-default-rtdb.firebaseio.com"] = database_url
                    os.environ["science-project-c6e47.firebasestorage.app"] = storage_bucket
                    st.success("Firebase configuration updated")
                    st.rerun()
   
        elif comm_method == "Local Radio (Meshtastic)":
            st.subheader("Meshtastic Settings")
            with st.expander("Meshtastic Device Information"):
                if isinstance(comm, MeshtasticRadio) and comm.connected:
                    st.json(comm.node_info)
                else:
                    st.error("Not connected to a Meshtastic device")
                    
                # Port selection
                available_ports = ["AUTO"]
                try:
                    import serial.tools.list_ports
                    ports = list(serial.tools.list_ports.comports())
                    available_ports += [p.device for p in ports]
                except:
                    available_ports += ["/dev/ttyUSB0", "/dev/ttyACM0", "COM3"]
                
                selected_port = st.selectbox("Serial Port", available_ports)
                
                if st.button("Reconnect Device"):
                    if selected_port == "AUTO":
                        selected_port = None
                    st.session_state.meshtastic_port = selected_port
                    # Force reinitialization
                    for key in list(st.session_state.keys()):
                        if key.startswith("current_method_"):
                            del st.session_state[key]
                    st.rerun()
        
        # Simulate messages (works with all communication methods)
        st.subheader("Simulate Receiving Message")
        sim_sender = st.text_input("Simulated Sender ID", value="SIM123")
        sim_recipient = st.text_input("Recipient Code", value=st.session_state.get('receiver_code', ''))
        sim_request_id = st.text_input("Request ID", value=str(uuid.uuid4()))
        sim_data = st.text_area("Request Data", value="Test message")
        
        if st.button("Simulate Incoming Message"):
            # Create a simulated message
            sim_message = {
                "recipient": sim_recipient,
                "sender": sim_sender,
                "request_id": sim_request_id,
                "data": sim_data,
                "status": "pending",
                "timestamp": int(time.time() * 1000)
            }
            
            # Add to message queue
            st.session_state.message_queue.put({"sender": sim_sender, "message": json.dumps(sim_message)})
            st.success("Simulated message added to queue")

# Handle app close
def clean_up():
    # Close any communication resources
    if 'comm' in st.session_state:
        st.session_state.comm.close()

# Register cleanup handler
import atexit
atexit.register(clean_up)

if __name__ == "__main__":
    main()
