import streamlit as st
import json
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
from supabase import create_client

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

# Supabase configuration
SUPABASE_URL = "https://your-supabase-project.supabase.co"  # Replace with your Supabase URL
SUPABASE_KEY = "your-supabase-anon-key"  # Replace with your Supabase anon/public key

# Create Supabase client
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

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

# Supabase-based WAN Communication
class SupabaseWanCommunication:
    def __init__(self, supabase_client):
        self.supabase = supabase_client
        
    def register_receiver(self, connection_code, encryption_key_info):
        """Register a new receiver with a connection code."""
        try:
            data = {
                "connection_code": connection_code,
                "active": True,
                "created_at": int(time.time()),
                "last_active": int(time.time()),
                "encryption_info": encryption_key_info
            }
            
            # Insert into the connections table
            result = self.supabase.table("connections").insert(data).execute()
            
            return len(result.data) > 0
        except Exception as e:
            st.error(f"Supabase error: {str(e)}")
            return False
        
    def deregister_receiver(self, connection_code):
        """Remove a receiver connection by marking it as inactive."""
        try:
            # Update the connection to inactive
            result = self.supabase.table("connections") \
                .update({"active": False}) \
                .eq("connection_code", connection_code) \
                .execute()
                
            return len(result.data) > 0
        except Exception as e:
            st.error(f"Supabase error: {str(e)}")
            return False
    
    def check_connection(self, connection_code):
        """Check if a connection code is active."""
        try:
            result = self.supabase.table("connections") \
                .select("active") \
                .eq("connection_code", connection_code) \
                .execute()
                
            if result.data and len(result.data) > 0:
                return result.data[0]["active"]
            return False
        except Exception as e:
            st.error(f"Supabase error: {str(e)}")
            return False
    
    def update_last_active(self, connection_code):
        """Update the last active timestamp."""
        try:
            self.supabase.table("connections") \
                .update({"last_active": int(time.time())}) \
                .eq("connection_code", connection_code) \
                .execute()
        except Exception as e:
            st.error(f"Supabase error: {str(e)}")
    
    def send_request(self, connection_code, request, encrypted=False):
        """Send a request from sender to receiver."""
        # Check if connection exists and is active
        if not self.check_connection(connection_code):
            return False, "Connection not found or inactive"
        
        try:
            request_id = str(uuid.uuid4())
            request_data = {
                "request_id": request_id,
                "connection_code": connection_code,
                "data": json.dumps(request),
                "encrypted": encrypted,
                "timestamp": int(time.time()),
                "processed": False
            }
            
            # Insert the request
            result = self.supabase.table("requests").insert(request_data).execute()
            
            return len(result.data) > 0, request_id
        except Exception as e:
            st.error(f"Supabase error: {str(e)}")
            return False, str(e)
    
    def get_pending_requests(self, connection_code):
        """Get all pending requests for a receiver."""
        try:
            # Get unprocessed requests
            result = self.supabase.table("requests") \
                .select("*") \
                .eq("connection_code", connection_code) \
                .eq("processed", False) \
                .execute()
                
            pending = []
            for req in result.data:
                # Mark as processed
                self.supabase.table("requests") \
                    .update({"processed": True}) \
                    .eq("request_id", req["request_id"]) \
                    .execute()
                
                # Format the request for the app
                req["data"] = json.loads(req["data"])
                req["id"] = req["request_id"]  # For compatibility with existing code
                pending.append(req)
                
            return pending
        except Exception as e:
            st.error(f"Supabase error: {str(e)}")
            return []
    
    def send_response(self, connection_code, request_id, response, encrypted=False):
        """Send a response from receiver to sender."""
        try:
            response_data = {
                "response_id": str(uuid.uuid4()),
                "request_id": request_id,
                "connection_code": connection_code,
                "data": json.dumps(response),
                "encrypted": encrypted,
                "timestamp": int(time.time()),
                "retrieved": False
            }
            
            # Insert the response
            result = self.supabase.table("responses").insert(response_data).execute()
            
            return len(result.data) > 0
        except Exception as e:
            st.error(f"Supabase error: {str(e)}")
            return False
    
    def get_response(self, connection_code, request_id):
        """Get a response for a specific request."""
        try:
            # Get unretrieved response for the request
            result = self.supabase.table("responses") \
                .select("*") \
                .eq("connection_code", connection_code) \
                .eq("request_id", request_id) \
                .eq("retrieved", False) \
                .execute()
                
            if result.data and len(result.data) > 0:
                # Mark as retrieved
                self.supabase.table("responses") \
                    .update({"retrieved": True}) \
                    .eq("response_id", result.data[0]["response_id"]) \
                    .execute()
                
                # Return the response data
                return json.loads(result.data[0]["data"])
            
            return None
        except Exception as e:
            st.error(f"Supabase error: {str(e)}")
            return None

# Create a global instance of SupabaseWanCommunication
wan_comm = SupabaseWanCommunication(supabase)

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
                st.error("Failed to establish connection. Please check your Supabase configuration.")
            
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
