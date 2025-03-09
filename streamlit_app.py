# app.py - Enhanced WAN Communication App with Bi-directional Communication
import streamlit as st
import base64
import hashlib
import json
import os
import secrets
import time
import uuid
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import requests
from datetime import datetime

# ---- UTILITY FUNCTIONS ----

def generate_connection_code():
    """Generate a unique connection code for the receiver"""
    token = secrets.token_hex(8)
    timestamp = int(time.time())
    combined = f"{token}-{timestamp}"
    code = hashlib.sha256(combined.encode()).hexdigest()[:12].upper()
    return f"{code[:4]}-{code[4:8]}-{code[8:12]}"

def generate_encryption_key(connection_code, salt=None):
    """Generate an encryption key from the connection code"""
    if salt is None:
        salt = os.urandom(16)
    
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

# ---- ENHANCED WAN SERVER WITH BI-DIRECTIONAL MESSAGING ----

class EnhancedWANServer:
    @staticmethod
    def register_endpoint(connection_code, salt, endpoint_type):
        """Register an endpoint (sender or receiver) with its connection code"""
        st.session_state['wan_registry'] = st.session_state.get('wan_registry', {})
        
        if connection_code not in st.session_state['wan_registry']:
            st.session_state['wan_registry'][connection_code] = {
                'salt': salt,
                'endpoints': {},
                'messages': {
                    'receiver_messages': [],  # Messages from sender to receiver
                    'sender_messages': []     # Messages from receiver to sender
                }
            }
        
        st.session_state['wan_registry'][connection_code]['endpoints'][endpoint_type] = True
        return True
    
    @staticmethod
    def send_message(connection_code, encrypted_message, direction="to_receiver"):
        """Send an encrypted message in either direction"""
        registry = st.session_state.get('wan_registry', {})
        if connection_code not in registry:
            return False
        
        message_queue = "receiver_messages" if direction == "to_receiver" else "sender_messages"
        
        registry[connection_code]['messages'][message_queue].append({
            'message': encrypted_message,
            'timestamp': time.time(),
            'id': str(uuid.uuid4()),
            'status': 'pending'
        })
        return True
    
    @staticmethod
    def get_messages(connection_code, direction="to_receiver"):
        """Get pending messages for an endpoint"""
        registry = st.session_state.get('wan_registry', {})
        if connection_code not in registry:
            return []
        
        message_queue = "receiver_messages" if direction == "to_receiver" else "sender_messages"
        messages = registry[connection_code]['messages'][message_queue]
        
        # Filter pending messages
        pending = [m for m in messages if m['status'] == 'pending']
        # Mark as processing
        for m in pending:
            m['status'] = 'processing'
        return pending
    
    @staticmethod
    def update_message_status(connection_code, message_id, status, response=None, direction="to_receiver"):
        """Update message status and add response if any"""
        registry = st.session_state.get('wan_registry', {})
        if connection_code not in registry:
            return False
        
        message_queue = "receiver_messages" if direction == "to_receiver" else "sender_messages"
        
        for message in registry[connection_code]['messages'][message_queue]:
            if message['id'] == message_id:
                message['status'] = status
                if response:
                    message['response'] = response
                return True
        return False
    
    @staticmethod
    def get_message_by_id(connection_code, message_id, direction="to_receiver"):
        """Get a specific message by its ID"""
        registry = st.session_state.get('wan_registry', {})
        if connection_code not in registry:
            return None
        
        message_queue = "receiver_messages" if direction == "to_receiver" else "sender_messages"
        
        for message in registry[connection_code]['messages'][message_queue]:
            if message['id'] == message_id:
                return message
        return None
    
    @staticmethod
    def get_message_history(connection_code, limit=10, include_all_statuses=False, direction="to_receiver"):
        """Get recent message history"""
        registry = st.session_state.get('wan_registry', {})
        if connection_code not in registry:
            return []
        
        message_queue = "receiver_messages" if direction == "to_receiver" else "sender_messages"
        messages = registry[connection_code]['messages'][message_queue]
        
        if not include_all_statuses:
            messages = [m for m in messages if m['status'] in ('completed', 'error')]
        
        # Sort by timestamp (newest first) and limit
        sorted_messages = sorted(messages, key=lambda m: m['timestamp'], reverse=True)
        return sorted_messages[:limit]

# ---- RECEIVER APP FUNCTIONS ----

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
        st.session_state['receiver_message_history'] = []
        
        # Register with the WAN server
        EnhancedWANServer.register_endpoint(
            st.session_state['connection_code'],
            st.session_state['salt'],
            "receiver"
        )
        st.session_state['receiver_initialized'] = True
    
    # Create tabs for different receiver functions
    tab1, tab2, tab3, tab4 = st.tabs(["Connection", "Request Handler", "Monitor", "Send Requests"])
    
    # Tab 1: Connection settings
    with tab1:
        st.header("Your Connection Code")
        st.code(st.session_state['connection_code'], language=None)
        st.info("Share this code with the sender to establish a secure connection.")
        
        # Display connection status
        registry = get_from_session('wan_registry', {})
        conn_code = st.session_state['connection_code']
        
        if conn_code in registry and registry[conn_code]['endpoints'].get('sender'):
            st.success("✅ Sender is connected")
        else:
            st.warning("⚠️ Waiting for sender to connect")
    
    # Tab 2: Custom instructions
    with tab2:
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
        elif request_data['action'] == 'file_request':
            # Simulating file access (in real world, this would access actual files)
            files = {
                'report.csv': 'Date,Value\n2023-01-01,100\n2023-01-02,150',
                'config.json': '{"server": "production", "timeout": 30}'
            }
            requested_file = request_data.get('filename')
            if requested_file in files:
                return {'status': 'success', 'filename': requested_file, 'content': files[requested_file]}
            else:
                return {'status': 'error', 'message': f'File {requested_file} not found'}
    
    return {'status': 'error', 'message': 'Unknown action or invalid request'}
"""
        
        custom_code = st.text_area("Custom Request Handler", 
                                  st.session_state['custom_instructions'], 
                                  height=300)
        
        col1, col2 = st.columns([1, 1])
        with col1:
            if st.button("Save Instructions"):
                try:
                    # Validate the code by executing it
                    exec(custom_code)
                    st.session_state['custom_instructions'] = custom_code
                    st.success("Custom instructions saved successfully!")
                except Exception as e:
                    st.error(f"Error in code: {str(e)}")
        
        with col2:
            if st.button("Load Example"):
                st.session_state['custom_instructions'] = """
def process_request(request_data):
    # Example handler with extended functionality
    import datetime
    
    if 'action' in request_data:
        # Basic echo service
        if request_data['action'] == 'echo':
            return {
                'status': 'success', 
                'echo': request_data.get('message', ''),
                'timestamp': datetime.datetime.now().isoformat()
            }
        
        # Calculator service
        elif request_data['action'] == 'calculate':
            try:
                expression = request_data.get('expression', '')
                result = eval(expression)  # Note: eval can be dangerous in production
                return {'status': 'success', 'result': result}
            except Exception as e:
                return {'status': 'error', 'message': str(e)}
        
        # Weather service (simulated)
        elif request_data['action'] == 'weather':
            city = request_data.get('city', 'Unknown')
            weather_data = {
                'New York': {'temp': 72, 'condition': 'Sunny'},
                'London': {'temp': 65, 'condition': 'Cloudy'},
                'Tokyo': {'temp': 80, 'condition': 'Rainy'},
                'Unknown': {'temp': 70, 'condition': 'Unknown'}
            }
            return {
                'status': 'success',
                'city': city,
                'weather': weather_data.get(city, weather_data['Unknown'])
            }
            
        # File request (simulated)
        elif request_data['action'] == 'file_request':
            files = {
                'report.csv': 'Date,Value\\n2023-01-01,100\\n2023-01-02,150',
                'config.json': '{"server": "production", "timeout": 30}'
            }
            requested_file = request_data.get('filename')
            if requested_file in files:
                return {'status': 'success', 'filename': requested_file, 'content': files[requested_file]}
            else:
                return {'status': 'error', 'message': f'File {requested_file} not found'}
    
    return {'status': 'error', 'message': 'Unknown action or invalid request'}
"""
                st.success("Example code loaded!")
    
    # Tab 3: Request monitoring
    with tab3:
        st.header("Request Monitor")
        status_placeholder = st.empty()
        
        col1, col2 = st.columns([1, 1])
        with col1:
            if st.button("Check for Requests", key="check_requests"):
                process_incoming_requests(status_placeholder)
        
        with col2:
            if st.button("View Message History", key="view_history"):
                message_history = EnhancedWANServer.get_message_history(
                    st.session_state['connection_code'],
                    limit=10,
                    include_all_statuses=True,
                    direction="to_receiver"
                )
                
                if not message_history:
                    status_placeholder.info("No message history available.")
                else:
                    history_output = ""
                    for idx, msg in enumerate(message_history):
                        try:
                            # Try to decrypt the message for display
                            decrypted_data = decrypt_message(
                                msg['message'], 
                                st.session_state['encryption_key']
                            )
                            
                            # Format response if available
                            response_text = "No response yet"
                            if 'response' in msg:
                                try:
                                    decrypted_response = decrypt_message(
                                        msg['response'], 
                                        st.session_state['encryption_key']
                                    )
                                    response_text = json.dumps(decrypted_response, indent=2)
                                except:
                                    response_text = "Error decrypting response"
                            
                            # Format timestamp
                            timestamp = datetime.fromtimestamp(msg['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
                            
                            history_output += f"### Message {idx+1} - {timestamp}\n"
                            history_output += f"**Status:** {msg['status']}\n"
                            history_output += f"**ID:** {msg['id']}\n"
                            history_output += f"**Request:** `{json.dumps(decrypted_data)}`\n"
                            history_output += f"**Response:** ```json\n{response_text}\n```\n\n---\n\n"
                            
                        except Exception as e:
                            history_output += f"### Message {idx+1} - Error\n"
                            history_output += f"Error decrypting: {str(e)}\n\n---\n\n"
                    
                    status_placeholder.markdown(history_output)
        
        # Automatic refresh
        if 'auto_refresh' not in st.session_state:
            st.session_state['auto_refresh'] = False
            
        auto_refresh = st.checkbox("Enable auto-refresh (checks every 10 seconds)", 
                                  value=st.session_state['auto_refresh'])
        
        if auto_refresh != st.session_state['auto_refresh']:
            st.session_state['auto_refresh'] = auto_refresh
            st.experimental_rerun()
            
        if auto_refresh:
            if 'last_refresh' not in st.session_state:
                st.session_state['last_refresh'] = time.time()
                process_incoming_requests(status_placeholder)
            elif time.time() - st.session_state['last_refresh'] > 10:
                st.session_state['last_refresh'] = time.time()
                process_incoming_requests(status_placeholder)
                
            st.info(f"Auto-refreshing... Last check: {datetime.fromtimestamp(st.session_state['last_refresh']).strftime('%H:%M:%S')}")
    
    # Tab 4: Send requests back to sender
    with tab4:
        st.header("Send Requests to Sender")
        
        registry = get_from_session('wan_registry', {})
        conn_code = st.session_state['connection_code']
        
        if conn_code in registry and registry[conn_code]['endpoints'].get('sender'):
            # Request type selector
            request_type = st.selectbox(
                "Request Type",
                ["Status Update", "Data Request", "Custom Request"]
            )
            
            request_data = {}
            
            if request_type == "Status Update":
                status_message = st.text_area("Status Message", "System is functioning normally.")
                status_level = st.selectbox("Status Level", ["info", "warning", "error", "success"])
                
                request_data = {
                    'action': 'status_update',
                    'message': status_message,
                    'level': status_level,
                    'timestamp': datetime.now().isoformat()
                }
            
            elif request_type == "Data Request":
                data_type = st.selectbox("Data Type", ["Configuration", "Credentials", "Logs"])
                reason = st.text_input("Reason for Request", "Regular maintenance")
                
                request_data = {
                    'action': 'data_request',
                    'type': data_type,
                    'reason': reason,
                    'timestamp': datetime.now().isoformat()
                }
            
            elif request_type == "Custom Request":
                custom_json = st.text_area("Enter Custom JSON Request", 
                                          """{
  "action": "custom_action",
  "parameters": {
    "param1": "value1",
    "param2": "value2"
  },
  "priority": "high"
}""")
                try:
                    request_data = json.loads(custom_json)
                except json.JSONDecodeError:
                    st.error("Invalid JSON format")
            
            if st.button("Send to Sender") and request_data:
                # Add request ID and timestamp if not present
                if 'id' not in request_data:
                    request_data['id'] = str(uuid.uuid4())
                if 'timestamp' not in request_data:
                    request_data['timestamp'] = time.time()
                
                # Encrypt the request
                encrypted_data = encrypt_message(
                    request_data, 
                    st.session_state['encryption_key']
                )
                
                # Send via WAN server (to sender)
                if EnhancedWANServer.send_message(
                    st.session_state['connection_code'], 
                    encrypted_data,
                    direction="to_sender"
                ):
                    st.success(f"Request sent to sender! ID: {request_data['id']}")
                    
                    # Store the last sent message ID
                    save_to_session('last_sent_to_sender_id', request_data['id'])
                else:
                    st.error("Failed to send request")
            
            # Check for responses
            if get_from_session('last_sent_to_sender_id') and st.button("Check for Response"):
                message_id = get_from_session('last_sent_to_sender_id')
                message = EnhancedWANServer.get_message_by_id(
                    st.session_state['connection_code'],
                    message_id,
                    direction="to_sender"
                )
                
                if message and 'response' in message:
                    try:
                        # Decrypt the response
                        decrypted_response = decrypt_message(
                            message['response'], 
                            st.session_state['encryption_key']
                        )
                        st.json(decrypted_response)
                    except Exception as e:
                        st.error(f"Error decrypting response: {str(e)}")
                else:
                    st.info("No response yet or request still processing")
        else:
            st.warning("⚠️ Sender is not connected yet. Cannot send requests.")

def process_incoming_requests(status_placeholder):
    """Process incoming requests for the receiver"""
    messages = EnhancedWANServer.get_messages(st.session_state['connection_code'], direction="to_receiver")
    
    if not messages:
        status_placeholder.info("No new requests.")
        return
    
    for message in messages:
        try:
            # Decrypt the message
            encrypted_data = message['message']
            decrypted_data = decrypt_message(encrypted_data, st.session_state['encryption_key'])
            
            status_placeholder.info(f"Processing request: {message['id']}")
            
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
            EnhancedWANServer.update_message_status(
                st.session_state['connection_code'],
                message['id'],
                'completed',
                encrypted_response,
                direction="to_receiver"
            )
            
            status_placeholder.success(f"Request processed: {json.dumps(result)}")
            
        except Exception as e:
            status_placeholder.error(f"Error processing request: {str(e)}")
            EnhancedWANServer.update_message_status(
                st.session_state['connection_code'],
                message['id'],
                'error',
                direction="to_receiver"
            )

# ---- SENDER APP FUNCTIONS ----

def sender_app():
    st.title("Encrypted WAN Sender")
    
    # Initialize sender's session state if needed
    if 'sender_initialized' not in st.session_state:
        st.session_state['sender_initialized'] = False
        st.session_state['sender_message_history'] = []
    
    # Create tabs for sender functions
    tab1, tab2, tab3 = st.tabs(["Connect", "Send Requests", "Receiver Messages"])
    
    # Tab 1: Connection setup
    with tab1:
        st.header("Connect to Receiver")
        
        # Check if already connected
        if get_from_session('connected_to'):
            st.success(f"Connected to: {get_from_session('connected_to')}")
            if st.button("Disconnect"):
                # Clear connection data
                for key in ['connected_to', 'encryption_key', 'last_request_id', 'last_request_time']:
                    if key in st.session_state:
                        del st.session_state[key]
                st.experimental_rerun()
        else:
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
                    
                    # Register as sender
                    EnhancedWANServer.register_endpoint(
                        connection_code,
                        salt,
                        "sender"
                    )
                    
                    st.success(f"Connected to {connection_code}")
                    st.experimental_rerun()
                else:
                    st.error("Invalid connection code or receiver not available")
    
    # Only show request tabs if connected
    if get_from_session('connected_to'):
        # Tab 2: Send requests
        with tab2:
            st.header("Send Request")
            
            # Request type selector
            request_type = st.selectbox(
                "Request Type",
                ["Echo Message", "Calculate Expression", "File Request", "Weather Check", "Custom Request"]
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
            
            elif request_type == "File Request":
                filename = st.text_input("Enter Filename (e.g., report.csv, config.json)")
                if filename:
                    request_data = {
                        'action': 'file_request',
                        'filename': filename
                    }
            
            elif request_type == "Weather Check":
                city = st.text_input("Enter City Name")
                if city:
                    request_data = {
                        'action': 'weather',
                        'city': city
                    }
            
            elif request_type == "Custom Request":
                custom_json = st.text_area("Enter Custom JSON Request", "{\"action\": \"custom\"}")
                try:
                    request_data = json.loads(custom_json)
                except json.JSONDecodeError:
                    st.error("Invalid JSON format")
            
            col1, col2 = st.columns([1, 1])
            
            with col1:
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
                    if EnhancedWANServer.send_message(
                        get_from_session('connected_to'), 
                        encrypted_data,
                        direction="to_receiver"
                    ):
                        save_to_session('last_request_id', request_data['id'])
                        save_to_session('last_request_time', time.time())
                        st.success(f"Request sent! ID: {request_data['id'][:8]}...")
                    else:
                        st.error("Failed to send request")
            
            # Response section
            st.header("Response")
            
            response_placeholder = st.empty()
            
            if get_from_session('last_request_id'):
                with col2:
                    if st.button("Check for Response"):
                        check_for_response(response_placeholder)
            
            # Message history
            if st.button("View Message History"):
                message_history = EnhancedWANServer.get_message_history(
                    get_from_session('connected_to'),
                    limit=10,
                    include_all_statuses=True,
                    direction="to_receiver"
                )
                
                if not message_history:
                    response_placeholder.info("No message history available.")
                else:
                    history_output = ""
                    for idx, msg in enumerate(message_history):
                        try:
                            # Try to decrypt the message for display
                            decrypted_data = decrypt_message(
                                msg['message'], 
                                get_from_session('encryption_key')
                            )
                            
                            # Format response if available
                            response_text = "No response yet"
                            if 'response' in msg:
                                try:
                                    decrypted_response = decrypt_message(
                                        msg['response'], 
                                        get_from_session('encryption_key')
                                    )
                                    response_text = json.dumps(decrypted_response, indent=2)
                                except:
                                    response_text = "Error decrypting response"
                            
                            # Format timestamp
                            timestamp = datetime.fromtimestamp(msg['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
                            
                            history_output += f"### Message {idx+1} - {timestamp}\n"
                            history_output += f"**Status:** {msg['status']}\n"
                            history_output += f"**ID:** {msg['id']}\n"
                            history_output += f"**Request:** `{json.dumps(decrypted_data)}`\n"
                            history_output += f"**Response:** ```json\n{response_text}\n```\n\n---\n\n"
                            
                        except Exception as e:
                            history_output += f"### Message {idx+1} - Error\n"
                            history_output += f"Error decrypting: {str(e)}\n\n---\n\n"
                    
                    response_placeholder.markdown(history_output)
        
        # Tab 3: Receiver Messages
        with tab3:
            st.header("Messages from Receiver")
            
            receiver_msg_placeholder = st.empty()
            
            col1, col2 = st.columns([1, 1])
            with col1:
                if st.button("Check for Messages"):
                    # Check for messages from receiver to sender
                    process_receiver_messages(receiver_msg_placeholder)
            
            with col2:
                if st.button("View Message History", key="view_receiver_history"):
                    # View history of messages from receiver
                    message_history = EnhancedWANServer.get_message_history(
                        get_from_session('connected_to'),
                        limit=10,
                        include_all_statuses=True,
                        direction="to_sender"
                    )
                    
                    if not message_history:
                        receiver_msg_placeholder.info("No message history from receiver.")
                    else:
                        history_output = ""
                        for idx, msg in enumerate(message_history):
                            try:
                                # Try to decrypt the message for display
                                decrypted_data = decrypt_message(
                                    msg['message'], 
                                    get_from_session('encryption_key')
                                )
                                
                                # Format response if available
                                response_text = "No response yet"
                                if 'response' in msg:
                                    try:
                                        decrypted_response = decrypt_message(
                                            msg['response'], 
                                            get_from_session('encryption_key')
                                        )
                                        response_text = json.dumps(decrypted_response, indent=2)
                                    except:
                                        response_text = "Error decrypting response"
                                
                                # Format timestamp
                                timestamp = datetime.fromtimestamp(msg['timestamp']).strftime('%Y-%m-%d %H:%timestamp = datetime.fromtimestamp(msg['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
                                
                                history_output += f"### Message {idx+1} - {timestamp}\n"
                                history_output += f"**Status:** {msg['status']}\n"
                                history_output += f"**ID:** {msg['id']}\n"
                                history_output += f"**Request:** `{json.dumps(decrypted_data)}`\n"
                                history_output += f"**Response:** ```json\n{response_text}\n```\n\n---\n\n"
                                
                            except Exception as e:
                                history_output += f"### Message {idx+1} - Error\n"
                                history_output += f"Error decrypting: {str(e)}\n\n---\n\n"
                        
                        receiver_msg_placeholder.markdown(history_output)
            
            # Automatic refresh for receiver messages
            if 'auto_refresh_receiver' not in st.session_state:
                st.session_state['auto_refresh_receiver'] = False
                
            auto_refresh = st.checkbox("Enable auto-refresh (checks every 10 seconds)", 
                                      value=st.session_state['auto_refresh_receiver'],
                                      key="auto_refresh_receiver_msgs")
            
            if auto_refresh != st.session_state['auto_refresh_receiver']:
                st.session_state['auto_refresh_receiver'] = auto_refresh
                st.experimental_rerun()
                
            if auto_refresh:
                if 'last_refresh_receiver' not in st.session_state:
                    st.session_state['last_refresh_receiver'] = time.time()
                    process_receiver_messages(receiver_msg_placeholder)
                elif time.time() - st.session_state['last_refresh_receiver'] > 10:
                    st.session_state['last_refresh_receiver'] = time.time()
                    process_receiver_messages(receiver_msg_placeholder)
                    
                st.info(f"Auto-refreshing... Last check: {datetime.fromtimestamp(st.session_state['last_refresh_receiver']).strftime('%H:%M:%S')}")

def check_for_response(response_placeholder):
    """Check for a response to a specific request"""
    connection_code = get_from_session('connected_to')
    request_id = get_from_session('last_request_id')
    
    # Get the message
    message = EnhancedWANServer.get_message_by_id(
        connection_code, 
        request_id,
        direction="to_receiver"
    )
    
    if message and 'response' in message:
        try:
            # Decrypt the response
            decrypted_response = decrypt_message(
                message['response'], 
                get_from_session('encryption_key')
            )
            response_placeholder.json(decrypted_response)
        except Exception as e:
            response_placeholder.error(f"Error decrypting response: {str(e)}")
    else:
        response_placeholder.info("No response yet or request still processing")

def process_receiver_messages(message_placeholder):
    """Process messages sent from receiver to sender"""
    connection_code = get_from_session('connected_to')
    
    # Get pending messages
    messages = EnhancedWANServer.get_messages(
        connection_code, 
        direction="to_sender"
    )
    
    if not messages:
        message_placeholder.info("No new messages from receiver.")
        return
    
    message_output = ""
    for message in messages:
        try:
            # Decrypt the message
            encrypted_data = message['message']
            decrypted_data = decrypt_message(
                encrypted_data, 
                get_from_session('encryption_key')
            )
            
            # Display the message
            message_output += f"### New Message from Receiver\n"
            message_output += f"**ID:** {message['id']}\n"
            message_output += f"**Timestamp:** {datetime.fromtimestamp(message['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}\n"
            message_output += f"**Content:**\n```json\n{json.dumps(decrypted_data, indent=2)}\n```\n\n"
            
            # Prepare response based on message type
            response = {
                'status': 'received',
                'message': 'Message received and processed',
                'timestamp': time.time()
            }
            
            # Handle different types of actions
            if decrypted_data.get('action') == 'status_update':
                response['details'] = f"Status update acknowledged: {decrypted_data.get('level', 'info')}"
            elif decrypted_data.get('action') == 'data_request':
                data_type = decrypted_data.get('type')
                if data_type == 'Configuration':
                    response['data'] = {
                        'server': 'production',
                        'timeout': 30,
                        'retries': 3
                    }
                elif data_type == 'Credentials':
                    response['data'] = {
                        'username': 'admin',
                        'api_key': '********',
                        'expires': '2023-12-31'
                    }
                elif data_type == 'Logs':
                    response['data'] = [
                        {'time': '2023-06-10T10:00:01', 'level': 'INFO', 'message': 'Application started'},
                        {'time': '2023-06-10T10:01:15', 'level': 'WARNING', 'message': 'High memory usage'},
                        {'time': '2023-06-10T10:02:30', 'level': 'ERROR', 'message': 'Connection timeout'}
                    ]
            
            # Encrypt the response
            encrypted_response = encrypt_message(
                response, 
                get_from_session('encryption_key')
            )
            
            # Update message status
            EnhancedWANServer.update_message_status(
                connection_code,
                message['id'],
                'completed',
                encrypted_response,
                direction="to_sender"
            )
            
            message_output += f"**Response:** Message acknowledged and processed.\n\n---\n\n"
            
        except Exception as e:
            message_output += f"### Error Processing Message\n"
            message_output += f"**Error:** {str(e)}\n\n---\n\n"
            
            # Update message status as error
            EnhancedWANServer.update_message_status(
                connection_code,
                message['id'],
                'error',
                direction="to_sender"
            )
    
    message_placeholder.markdown(message_output)

# ---- MAIN APP ----

def main():
    st.set_page_config(
        page_title="Enhanced WAN Communication", 
        layout="wide",
        initial_sidebar_state="collapsed"
    )
    
    # App title and description
    st.title("📡 Encrypted WAN Communication")
    st.markdown("""
    This application demonstrates secure communication between endpoints over a wide area network (WAN).
    All messages are encrypted end-to-end using the Fernet symmetric encryption algorithm.
    """)
    
    # Initialize session state
    if 'wan_registry' not in st.session_state:
        st.session_state['wan_registry'] = {}
    
    # Navigation tabs for app modes
    selected_tab = st.radio("Select App Mode", ["Sender", "Receiver"], horizontal=True)
    
    st.markdown("---")
    
    if selected_tab == "Sender":
        sender_app()
    else:
        receiver_app()
    
    # Footer
    st.markdown("---")
    st.markdown("#### App Information")
    st.markdown("""
    - **Security:** All messages are encrypted using Fernet symmetric encryption
    - **Connection:** One-time code exchange establishes secure channel
    - **Persistence:** Data is stored in session state for demonstration purposes
    - **Protocol:** JSON-based messaging with request/response pattern
    """)

if __name__ == "__main__":
    main()
