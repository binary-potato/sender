# Shared Utilities (save as utils.py)
import base64
import hashlib
import json
import os
import secrets
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import streamlit as st
import requests

def generate_connection_code():
    """Generate a unique connection code for the receiver"""
    # Generate a random token
    token = secrets.token_hex(8)
    # Add timestamp to ensure uniqueness
    timestamp = int(time.time())
    # Combine and hash
    combined = f"{token}-{timestamp}"
    code = hashlib.sha256(combined.encode()).hexdigest()[:12].upper()
    # Format with dashes for readability
    return f"{code[:4]}-{code[4:8]}-{code[8:12]}"

def generate_encryption_key(connection_code, salt=None):
    """Generate an encryption key from the connection code"""
    if salt is None:
        salt = os.urandom(16)
    
    # Derive key from connection code
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(connection_code.encode()))
    return key, salt

def encrypt_message(message, key):
    """Encrypt a message using the provided key"""
    f = Fernet(key)
    return f.encrypt(json.dumps(message).encode())

def decrypt_message(encrypted_message, key):
    """Decrypt a message using the provided key"""
    f = Fernet(key)
    decrypted = f.decrypt(encrypted_message)
    return json.loads(decrypted.decode())

def save_to_session(key, value):
    """Save value to session state"""
    st.session_state[key] = value

def get_from_session(key, default=None):
    """Get value from session state"""
    return st.session_state.get(key, default)

# Mock WAN server (in a real app, you'd use a proper database or message queue)
class MockWANServer:
    @staticmethod
    def register_receiver(connection_code, salt, endpoint):
        """Register a receiver with its connection code"""
        # In a real app, this would be a server-side operation
        st.session_state['wan_registry'] = st.session_state.get('wan_registry', {})
        st.session_state['wan_registry'][connection_code] = {
            'salt': salt,
            'endpoint': endpoint,
            'messages': []
        }
        return True
    
    @staticmethod
    def send_message(connection_code, encrypted_message):
        """Send an encrypted message to a receiver"""
        # In a real app, this would push to a queue or database
        registry = st.session_state.get('wan_registry', {})
        if connection_code not in registry:
            return False
        
        registry[connection_code]['messages'].append({
            'message': encrypted_message,
            'timestamp': time.time(),
            'status': 'pending'
        })
        return True
    
    @staticmethod
    def get_messages(connection_code):
        """Get pending messages for a receiver"""
        registry = st.session_state.get('wan_registry', {})
        if connection_code not in registry:
            return []
        
        messages = registry[connection_code]['messages']
        # Filter pending messages
        pending = [m for m in messages if m['status'] == 'pending']
        # Mark as processing
        for m in pending:
            m['status'] = 'processing'
        return pending
    
    @staticmethod
    def update_message_status(connection_code, message_timestamp, status, response=None):
        """Update message status and add response if any"""
        registry = st.session_state.get('wan_registry', {})
        if connection_code not in registry:
            return False
        
        for message in registry[connection_code]['messages']:
            if message['timestamp'] == message_timestamp:
                message['status'] = status
                if response:
                    message['response'] = response
                return True
        return False
    
    @staticmethod
    def get_response(connection_code, message_timestamp):
        """Get response for a specific message"""
        registry = st.session_state.get('wan_registry', {})
        if connection_code not in registry:
            return None
        
        for message in registry[connection_code]['messages']:
            if message['timestamp'] == message_timestamp and 'response' in message:
                return message['response']
        return None

# Receiver App (save as receiver_app.py)
import streamlit as st
import time
from utils import generate_connection_code, generate_encryption_key, decrypt_message, encrypt_message
from utils import save_to_session, get_from_session, MockWANServer

def receiver_app():
    st.title("Encrypted WAN Receiver")
    
    # Initialize session state for the receiver
    if 'receiver_initialized' not in st.session_state:
        st.session_state['receiver_initialized'] = False
        st.session_state['connection_code'] = generate_connection_code()
        st.session_state['salt'] = os.urandom(16)
        encryption_key, _ = generate_encryption_key(
            st.session_state['connection_code'], 
            st.session_state['salt']
        )
        st.session_state['encryption_key'] = encryption_key
        
        # Register with the WAN server
        MockWANServer.register_receiver(
            st.session_state['connection_code'],
            st.session_state['salt'],
            "http://receiver-endpoint"  # In a real app, this would be a proper endpoint
        )
        st.session_state['receiver_initialized'] = True
    
    # Display connection code
    st.header("Your Connection Code")
    st.code(st.session_state['connection_code'], language=None)
    st.info("Share this code with the sender to establish a secure connection.")
    
    # Custom instruction editor
    st.header("Custom Instruction Configuration")
    if 'custom_instructions' not in st.session_state:
        st.session_state['custom_instructions'] = """
def process_request(request_data):
    # This function will be called when a request is received
    # You can customize this to handle different types of requests
    
    if 'action' in request_data:
        if request_data['action'] == 'echo':
            return {'status': 'success', 'echo': request_data.get('message', '')}
        elif request_data['action'] == 'calculate':
            try:
                expression = request_data.get('expression', '')
                result = eval(expression)  # Note: eval can be dangerous in production
                return {'status': 'success', 'result': result}
            except Exception as e:
                return {'status': 'error', 'message': str(e)}
    
    return {'status': 'error', 'message': 'Unknown action or invalid request'}
"""
    
    custom_code = st.text_area("Custom Request Handler", 
                               st.session_state['custom_instructions'], 
                               height=300)
    
    if st.button("Save Instructions"):
        try:
            # Validate the code by executing it
            exec(custom_code)
            st.session_state['custom_instructions'] = custom_code
            st.success("Custom instructions saved successfully!")
        except Exception as e:
            st.error(f"Error in code: {str(e)}")
    
    # Request handling and status section
    st.header("Request Monitor")
    status_placeholder = st.empty()
    
    # Function to handle incoming requests
    def check_and_process_requests():
        messages = MockWANServer.get_messages(st.session_state['connection_code'])
        
        if not messages:
            status_placeholder.info("Waiting for requests...")
            return
        
        for message in messages:
            try:
                # Decrypt the message
                encrypted_data = message['message']
                decrypted_data = decrypt_message(encrypted_data, st.session_state['encryption_key'])
                
                status_placeholder.info(f"Processing request: {decrypted_data.get('id', 'unknown')}")
                
                # Execute the custom handler
                local_vars = {}
                exec(st.session_state['custom_instructions'], globals(), local_vars)
                process_function = local_vars.get('process_request')
                
                if not process_function:
                    result = {'status': 'error', 'message': 'No process_request function defined'}
                else:
                    result = process_function(decrypted_data)
                
                # Encrypt the response
                encrypted_response = encrypt_message(result, st.session_state['encryption_key'])
                
                # Update message status
                MockWANServer.update_message_status(
                    st.session_state['connection_code'],
                    message['timestamp'],
                    'completed',
                    encrypted_response
                )
                
                status_placeholder.success(f"Request {decrypted_data.get('id', 'unknown')} processed: {result}")
                
            except Exception as e:
                status_placeholder.error(f"Error processing request: {str(e)}")
                MockWANServer.update_message_status(
                    st.session_state['connection_code'],
                    message['timestamp'],
                    'error'
                )
    
    # Check for requests every few seconds
    if st.button("Check for Requests"):
        check_and_process_requests()

# Sender App (save as sender_app.py)
import streamlit as st
import time
import uuid
from utils import generate_encryption_key, encrypt_message, decrypt_message
from utils import save_to_session, get_from_session, MockWANServer

def sender_app():
    st.title("Encrypted WAN Sender")
    
    # Connection setup
    st.header("Connect to Receiver")
    connection_code = st.text_input("Enter Connection Code (e.g., ABCD-1234-XYZ9)")
    
    if st.button("Connect") and connection_code:
        # In a real app, you would verify the connection code with the server
        if get_from_session('wan_registry', {}).get(connection_code):
            # Get the salt from the registry
            salt = get_from_session('wan_registry', {})[connection_code]['salt']
            # Generate encryption key
            encryption_key, _ = generate_encryption_key(connection_code, salt)
            # Save to session
            save_to_session('connected_to', connection_code)
            save_to_session('encryption_key', encryption_key)
            st.success(f"Connected to {connection_code}")
        else:
            st.error("Invalid connection code or receiver not available")
    
    # Only show request section if connected
    if get_from_session('connected_to'):
        st.header("Send Request")
        
        # Request type selector
        request_type = st.selectbox(
            "Request Type",
            ["Echo Message", "Calculate Expression", "Custom Request"]
        )
        
        request_data = {}
        
        if request_type == "Echo Message":
            message = st.text_input("Message to Echo")
            if message:
                request_data = {
                    'action': 'echo',
                    'message': message
                }
        
        elif request_type == "Calculate Expression":
            expression = st.text_input("Enter Expression (e.g., 2 + 2 * 10)")
            if expression:
                request_data = {
                    'action': 'calculate',
                    'expression': expression
                }
        
        elif request_type == "Custom Request":
            custom_json = st.text_area("Enter Custom JSON Request", "{\"action\": \"custom\"}")
            try:
                request_data = json.loads(custom_json)
            except json.JSONDecodeError:
                st.error("Invalid JSON format")
        
        if st.button("Send Request") and request_data:
            # Add request ID and timestamp
            request_data['id'] = str(uuid.uuid4())
            request_data['timestamp'] = time.time()
            
            # Encrypt the request
            encrypted_data = encrypt_message(
                request_data, 
                get_from_session('encryption_key')
            )
            
            # Send via WAN server
            if MockWANServer.send_message(
                get_from_session('connected_to'), 
                encrypted_data
            ):
                save_to_session('last_request_id', request_data['id'])
                save_to_session('last_request_time', request_data['timestamp'])
                st.success(f"Request sent! ID: {request_data['id']}")
            else:
                st.error("Failed to send request")
        
        # Response section
        st.header("Response")
        
        if get_from_session('last_request_id') and st.button("Check for Response"):
            connection_code = get_from_session('connected_to')
            request_time = get_from_session('last_request_time')
            
            # Find the message
            response = None
            registry = get_from_session('wan_registry', {})
            if connection_code in registry:
                for msg in registry[connection_code]['messages']:
                    if msg['timestamp'] == request_time and 'response' in msg:
                        response = msg['response']
                        break
            
            if response:
                try:
                    # Decrypt the response
                    decrypted_response = decrypt_message(
                        response, 
                        get_from_session('encryption_key')
                    )
                    st.json(decrypted_response)
                except Exception as e:
                    st.error(f"Error decrypting response: {str(e)}")
            else:
                st.info("No response yet or request still processing")

# Main App (save as app.py)
import streamlit as st
from receiver_app import receiver_app
from sender_app import sender_app

def main():
    st.set_page_config(page_title="Encrypted WAN Communication", layout="wide")
    
    # Initialize session state
    if 'wan_registry' not in st.session_state:
        st.session_state['wan_registry'] = {}
    
    # App selection
    app_mode = st.sidebar.radio("Select App Mode", ["Sender", "Receiver"])
    
    if app_mode == "Sender":
        sender_app()
    else:
        receiver_app()

if __name__ == "__main__":
    main()
