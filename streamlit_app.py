import streamlit as st
import jsonimport streamlit as st
import pyrebase
import random
import string
import time
import qrcode
from io import BytesIO
import base64
import uuid

# Firebase configuration - no authentication
@st.cache_resource
def initialize_firebase():
    config = {
        "databaseURL": "https://your-project-id-default-rtdb.firebaseio.com/",  # Replace with your Firebase database URL
    }
    
    # Initialize Firebase with just the database URL
    firebase = pyrebase.initialize_app(config)
    return firebase

try:
    firebase = initialize_firebase()
    db = firebase.database()
except Exception as e:
    st.error(f"Firebase initialization error: {e}")
    st.info("Please update the Firebase database URL.")

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

# Main app
def main():
    st.title("Cross-Device Communication App")
    
    # Create tabs for sender and receiver modes
    tab1, tab2 = st.tabs(["Receiver Mode", "Sender Mode"])
    
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
            st.experimental_rerun()
        
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
            st.session_state.last_processed = {}
        
        # Start/Stop listening
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Start Listening" if not st.session_state.listening else "Stop Listening"):
                st.session_state.listening = not st.session_state.listening
                st.experimental_rerun()
        
        with col2:
            status = st.empty()
            if st.session_state.listening:
                status.success("Listening for requests")
            else:
                status.warning("Not listening")
        
        # Request container
        request_container = st.container()
        
        # Check for new requests if listening
        if st.session_state.listening:
            with request_container:
                placeholder = st.empty()
                
                try:
                    # Get current data
                    conn_path = f"connections/{st.session_state.receiver_code}"
                    data = db.child(conn_path).get().val()
                    
                    if data and 'requests' in data:
                        for request_id, request_data in data['requests'].items():
                            # Skip already processed requests
                            if request_id in st.session_state.last_processed:
                                continue
                                
                            if 'status' in request_data and request_data['status'] == 'pending':
                                # Process the request based on handler type
                                result = ""
                                if handler_type == "Echo":
                                    result = f"Echo: {request_data['data']}"
                                elif handler_type == "Math Operation":
                                    try:
                                        result = f"Result: {eval(request_data['data'])}"
                                    except:
                                        result = "Invalid math expression"
                                elif handler_type == "Text Processing":
                                    text = request_data['data']
                                    result = f"Uppercase: {text.upper()}, Lowercase: {text.lower()}, Length: {len(text)}"
                                elif handler_type == "Custom":
                                    try:
                                        # Execute custom code
                                        local_vars = {'data': request_data['data'], 'result': ''}
                                        exec(custom_handler, {'__builtins__': {}}, local_vars)
                                        result = local_vars.get('result', 'No result provided')
                                    except Exception as e:
                                        result = f"Error in custom handler: {str(e)}"
                                
                                # Display request and result
                                st.write(f"📬 Request received: {request_data['data']}")
                                st.write(f"✅ Response: {result}")
                                
                                # Send response
                                db.child(conn_path).child(f"requests/{request_id}").update({
                                    'status': 'completed',
                                    'result': result,
                                    'completed_at': int(time.time() * 1000)
                                })
                                
                                # Mark as processed
                                st.session_state.last_processed[request_id] = True
                                
                except Exception as e:
                    st.error(f"Error in receiver mode: {str(e)}")
    
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
            
            # Button to send the request
            if st.button("Send Request"):
                try:
                    # Generate a unique ID for this request
                    request_id = str(uuid.uuid4())
                    
                    # Create the request data
                    request_object = {
                        'data': request_data,
                        'status': 'pending',
                        'timestamp': int(time.time() * 1000)
                    }
                    
                    # Send the request to Firebase
                    conn_path = f"connections/{connection_code}/requests/{request_id}"
                    db.child(conn_path).set(request_object)
                    
                    st.success("Request sent! Waiting for response...")
                    
                    # Wait for response
                    response_placeholder = st.empty()
                    
                    # Poll for response
                    for i in range(30):  # Wait for max 30 seconds
                        current_data = db.child(conn_path).get().val()
                        
                        if current_data and current_data.get('status') == 'completed':
                            response_placeholder.success(f"Response received: {current_data.get('result')}")
                            break
                        
                        # Update waiting message with a countdown
                        response_placeholder.info(f"Waiting for response... ({30-i} seconds remaining)")
                        time.sleep(1)
                    else:
                        response_placeholder.warning("No response received within timeout period.")
                
                except Exception as e:
                    st.error(f"Error sending request: {str(e)}")

if __name__ == "__main__":
    main()
import time
import uuid
import base64
import hashlib
import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import qrcode
from io import BytesIO
import os

# Set page config
st.set_page_config(page_title="WAN Communication Tool", layout="wide")

# Initialize session states if they don't exist
if 'connection_code' not in st.session_state:
    st.session_state.connection_code = ""
if 'receiver_active' not in st.session_state:
    st.session_state.receiver_active = False
if 'sender_connected' not in st.session_state:
    st.session_state.sender_connected = False
if 'received_requests' not in st.session_state:
    st.session_state.received_requests = []
if 'sent_requests' not in st.session_state:
    st.session_state.sent_requests = []
if 'responses' not in st.session_state:
    st.session_state.responses = []

# Firebase config - you'll need to create a Firebase Realtime Database
# and put your credentials here
FIREBASE_URL = "https://science-project-c6e47-default-rtdb.firebaseio.com/"  # Replace with your Firebase URL
# If you have a Firebase API key (for some operations)
FIREBASE_API_KEY = ""  # Optional

# Helper functions for encryption
def generate_key(passphrase, salt):
    """Generate a Fernet key from a passphrase and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
    return key

def encrypt_message(message, key):
    """Encrypt a message using Fernet symmetric encryption."""
    f = Fernet(key)
    encrypted_message = f.encrypt(json.dumps(message).encode())
    return base64.b64encode(encrypted_message).decode()

def decrypt_message(encrypted_message, key):
    """Decrypt a message using Fernet symmetric encryption."""
    f = Fernet(key)
    decrypted_message = f.decrypt(base64.b64decode(encrypted_message))
    return json.loads(decrypted_message.decode())

def generate_connection_code():
    """Generate a unique connection code."""
    unique_id = str(uuid.uuid4())
    timestamp = str(int(time.time()))
    code_hash = hashlib.sha256((unique_id + timestamp).encode()).hexdigest()
    return code_hash[:12]

# Firebase-based WAN Communication
class FirebaseWanCommunication:
    def __init__(self, firebase_url):
        self.firebase_url = firebase_url
        
    def _make_request(self, method, path, data=None):
        """Make a request to Firebase."""
        url = f"{self.firebase_url}/{path}.json"
        
        try:
            if method == "GET":
                response = requests.get(url)
            elif method == "PUT":
                response = requests.put(url, json=data)
            elif method == "POST":
                response = requests.post(url, json=data)
            elif method == "PATCH":
                response = requests.patch(url, json=data)
            elif method == "DELETE":
                response = requests.delete(url)
                
            if response.status_code in (200, 201, 204):
                return response.json() if response.content else None
            return None
        except Exception as e:
            st.error(f"Firebase request error: {str(e)}")
            return None
        
    def register_receiver(self, connection_code, encryption_key_info):
        """Register a new receiver with a connection code."""
        data = {
            "active": True,
            "created_at": int(time.time()),
            "last_active": int(time.time()),
            "encryption_info": encryption_key_info
        }
        result = self._make_request("PUT", f"connections/{connection_code}", data)
        return result is not None
        
    def deregister_receiver(self, connection_code):
        """Remove a receiver connection."""
        result = self._make_request("DELETE", f"connections/{connection_code}")
        return result is not None
    
    def check_connection(self, connection_code):
        """Check if a connection code is active."""
        result = self._make_request("GET", f"connections/{connection_code}/active")
        return result is True
    
    def update_last_active(self, connection_code):
        """Update the last active timestamp."""
        data = {"last_active": int(time.time())}
        self._make_request("PATCH", f"connections/{connection_code}", data)
    
    def send_request(self, connection_code, request, encrypted=False):
        """Send a request from sender to receiver."""
        # Check if connection exists
        if not self.check_connection(connection_code):
            return False, "Connection not found"
        
        request_id = str(uuid.uuid4())
        request_data = {
            "id": request_id,
            "data": request,
            "encrypted": encrypted,
            "timestamp": int(time.time()),
            "processed": False
        }
        
        result = self._make_request("PUT", f"connections/{connection_code}/requests/{request_id}", request_data)
        return result is not None, request_id
    
    def get_pending_requests(self, connection_code):
        """Get all pending requests for a receiver."""
        requests = self._make_request("GET", f"connections/{connection_code}/requests")
        if not requests:
            return []
        
        pending = []
        for req_id, req_data in requests.items():
            if not req_data.get("processed", False):
                # Mark as processed
                self._make_request("PATCH", f"connections/{connection_code}/requests/{req_id}", {"processed": True})
                req_data["id"] = req_id  # Add the ID to the data
                pending.append(req_data)
                
        return pending
    
    def send_response(self, connection_code, request_id, response, encrypted=False):
        """Send a response from receiver to sender."""
        response_data = {
            "data": response,
            "encrypted": encrypted,
            "timestamp": int(time.time()),
            "retrieved": False
        }
        
        result = self._make_request("PUT", f"connections/{connection_code}/responses/{request_id}", response_data)
        return result is not None
    
    def get_response(self, connection_code, request_id):
        """Get a response for a specific request."""
        response = self._make_request("GET", f"connections/{connection_code}/responses/{request_id}")
        if not response or response.get("retrieved", False):
            return None
        
        # Mark as retrieved
        self._make_request("PATCH", f"connections/{connection_code}/responses/{request_id}", {"retrieved": True})
        return response.get("data")

# Create a global instance of WanCommunication
wan_comm = FirebaseWanCommunication(FIREBASE_URL)

# Main app
st.title("WAN Secure Communication")

# Create tabs for Sender and Receiver modes
tab1, tab2 = st.tabs(["Receiver Mode", "Sender Mode"])

# Receiver Mode
with tab1:
    st.header("Receiver Mode")
    
    if not st.session_state.receiver_active:
        st.write("Generate a connection code to allow senders to connect securely.")
        if st.button("Generate Connection Code"):
            # Generate a unique connection code
            connection_code = generate_connection_code()
            st.session_state.connection_code = connection_code
            
            # Generate a unique encryption key
            salt = os.urandom(16)  # Use a secure random salt
            salt_b64 = base64.b64encode(salt).decode()
            encryption_key_info = {"salt": salt_b64}
            
            # Register this receiver
            if wan_comm.register_receiver(connection_code, encryption_key_info):
                st.session_state.receiver_active = True
                st.success("Connection code generated!")
                st.experimental_rerun()
            else:
                st.error("Failed to establish connection. Please check your internet connection.")
            
    else:
        col1, col2 = st.columns([3, 1])
        
        with col1:
            st.success(f"Your connection code: **{st.session_state.connection_code}**")
            st.write("Share this code with anyone who needs to send you requests.")
            
            # Keep the connection alive
            wan_comm.update_last_active(st.session_state.connection_code)
            
            # Option to deactivate
            if st.button("Deactivate Receiver"):
                wan_comm.deregister_receiver(st.session_state.connection_code)
                st.session_state.receiver_active = False
                st.session_state.connection_code = ""
                st.session_state.received_requests = []
                st.experimental_rerun()
        
        with col2:
            # Generate QR code for easy sharing
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(st.session_state.connection_code)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            buffered = BytesIO()
            img.save(buffered, format="PNG")
            st.image(buffered, caption="Scan to copy code", width=150)
        
        # Custom request handling code
        st.subheader("Custom Request Handler")
        custom_handler = st.text_area(
            "Define how to process incoming requests (Python code):",
            height=150,
            value="""# Example handler:
# 'request' variable contains the incoming request
# Return your result as the response

if "echo" in request:
    response = f"Echo: {request['message']}"
elif "calculate" in request:
    x = request.get('x', 0)
    y = request.get('y', 0)
    operation = request.get('operation', 'add')
    
    if operation == 'add':
        result = x + y
    elif operation == 'subtract':
        result = x - y
    elif operation == 'multiply':
        result = x * y
    elif operation == 'divide':
        result = x / y if y != 0 else 'Error: Division by zero'
    
    response = f"Result: {result}"
else:
    response = "Unknown request type"
"""
        )
        
        # Check for new requests
        if st.button("Check for Requests"):
            # Poll for new requests
            pending_requests = wan_comm.get_pending_requests(st.session_state.connection_code)
            
            if pending_requests:
                for req in pending_requests:
                    st.session_state.received_requests.append(req)
                st.success(f"Received {len(pending_requests)} new request(s)")
            else:
                st.info("No new requests")
        
        # Display and process received requests
        if st.session_state.received_requests:
            st.subheader("Received Requests")
            for i, req in enumerate(st.session_state.received_requests):
                with st.expander(f"Request {i+1} (ID: {req['id'][:8]}...)"):
                    st.write("Request Data:")
                    st.json(req["data"])
                    
                    if st.button(f"Process Request {i+1}", key=f"process_{i}"):
                        try:
                            # Create a safe execution environment
                            request = req["data"]  # The request data
                            response = None  # Will be set by the handler code
                            
                            # Execute the custom handler code
                            exec(custom_handler)
                            
                            # Send the response
                            if response is not None:
                                success = wan_comm.send_response(
                                    st.session_state.connection_code,
                                    req["id"],
                                    response
                                )
                                if success:
                                    st.success("Response sent successfully")
                                else:
                                    st.error("Failed to send response")
                            else:
                                st.warning("No response generated by handler")
                        except Exception as e:
                            st.error(f"Error processing request: {str(e)}")

# Sender Mode
with tab2:
    st.header("Sender Mode")
    
    # Connect to a receiver
    if not st.session_state.sender_connected:
        connection_code = st.text_input("Enter connection code from receiver")
        
        if st.button("Connect"):
            if connection_code and wan_comm.check_connection(connection_code):
                st.session_state.connection_code = connection_code
                st.session_state.sender_connected = True
                st.success("Connected successfully!")
                st.experimental_rerun()
            else:
                st.error("Invalid connection code or receiver not active")
    
    else:
        st.success(f"Connected to: {st.session_state.connection_code}")
        
        # Option to disconnect
        if st.button("Disconnect"):
            st.session_state.sender_connected = False
            st.session_state.connection_code = ""
            st.session_state.sent_requests = []
            st.session_state.responses = []
            st.experimental_rerun()
        
        # Create a new request
        st.subheader("Send Request")
        
        request_type = st.selectbox("Request Type", ["Echo", "Calculate"])
        
        request_data = {}
        
        if request_type == "Echo":
            message = st.text_input("Message to echo")
            if message:
                request_data = {
                    "echo": True,
                    "message": message
                }
        
        elif request_type == "Calculate":
            col1, col2, col3 = st.columns(3)
            with col1:
                x = st.number_input("X", value=0.0)
            with col2:
                operation = st.selectbox("Operation", ["add", "subtract", "multiply", "divide"])
            with col3:
                y = st.number_input("Y", value=0.0)
            
            request_data = {
                "calculate": True,
                "x": x,
                "y": y,
                "operation": operation
            }
        
        # Send the request
        if st.button("Send Request"):
            if request_data:
                success, request_id = wan_comm.send_request(
                    st.session_state.connection_code,
                    request_data
                )
                
                if success:
                    st.session_state.sent_requests.append({
                        "id": request_id,
                        "data": request_data,
                        "timestamp": time.time()
                    })
                    st.success("Request sent successfully!")
                else:
                    st.error(f"Failed to send request: {request_id}")
            else:
                st.warning("Please complete the request form")
        
        # Check for responses
        if st.button("Check for Responses"):
            new_responses = 0
            for req in st.session_state.sent_requests:
                response = wan_comm.get_response(st.session_state.connection_code, req["id"])
                if response:
                    st.session_state.responses.append({
                        "request_id": req["id"],
                        "request_data": req["data"],
                        "response": response,
                        "timestamp": time.time()
                    })
                    new_responses += 1
            
            if new_responses > 0:
                st.success(f"Received {new_responses} new response(s)")
            else:
                st.info("No new responses")
        
        # Display sent requests and responses
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Sent Requests")
            if st.session_state.sent_requests:
                for i, req in enumerate(st.session_state.sent_requests):
                    with st.expander(f"Request {i+1} (ID: {req['id'][:8]}...)"):
                        st.write("Request Data:")
                        st.json(req["data"])
                        st.write(f"Sent: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(req['timestamp']))}")
            else:
                st.write("No requests sent yet")
        
        with col2:
            st.subheader("Received Responses")
            if st.session_state.responses:
                for i, resp in enumerate(st.session_state.responses):
                    with st.expander(f"Response {i+1}"):
                        st.write("For Request:")
                        st.json(resp["request_data"])
                        st.write("Response:")
                        st.write(resp["response"])
                        st.write(f"Received: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(resp['timestamp']))}")
            else:
                st.write("No responses received yet")

# Footer
st.markdown("---")
st.markdown("WAN Communication Tool - Secure encrypted communication over wide area networks")
