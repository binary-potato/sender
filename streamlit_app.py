# Enhanced Encrypted WAN Communication App
import streamlit as st
import base64
import hashlib
import json
import os
import secrets
import time
import uuid
import datetime
import io
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import requests

# ---- UTILITY FUNCTIONS ----

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

def generate_chart(data_type='line', seed=None):
    """Generate a sample chart based on the data type"""
    if seed is not None:
        np.random.seed(seed)
    
    plt.figure(figsize=(10, 6))
    
    if data_type == 'line':
        x = np.linspace(0, 10, 100)
        y = np.sin(x) + np.random.normal(0, 0.1, 100)
        plt.plot(x, y)
        plt.title('Sample Line Chart')
        plt.xlabel('X axis')
        plt.ylabel('Y axis')
        
    elif data_type == 'bar':
        categories = ['A', 'B', 'C', 'D', 'E']
        values = np.random.randint(1, 10, size=5)
        plt.bar(categories, values)
        plt.title('Sample Bar Chart')
        plt.xlabel('Categories')
        plt.ylabel('Values')
        
    elif data_type == 'scatter':
        x = np.random.randn(50)
        y = np.random.randn(50)
        colors = np.random.rand(50)
        sizes = 1000 * np.random.rand(50)
        plt.scatter(x, y, c=colors, s=sizes, alpha=0.5)
        plt.title('Sample Scatter Plot')
        plt.xlabel('X axis')
        plt.ylabel('Y axis')
    
    elif data_type == 'pie':
        labels = ['A', 'B', 'C', 'D']
        sizes = np.random.randint(1, 10, size=4)
        plt.pie(sizes, labels=labels, autopct='%1.1f%%')
        plt.title('Sample Pie Chart')
    
    # Save plot to a bytes buffer
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    
    # Convert to base64 for embedding
    plt_base64 = base64.b64encode(buf.read()).decode('utf-8')
    plt.close()
    
    return plt_base64

def process_data_analysis(data_str, analysis_type):
    """Process CSV or JSON data and return analysis results"""
    try:
        # Try parsing as JSON first
        try:
            data = json.loads(data_str)
            df = pd.DataFrame(data)
        except json.JSONDecodeError:
            # If not JSON, try CSV
            df = pd.read_csv(io.StringIO(data_str))
        
        # Perform the requested analysis
        if analysis_type == 'summary':
            result = {
                'shape': df.shape,
                'columns': df.columns.tolist(),
                'dtypes': df.dtypes.astype(str).to_dict(),
                'summary': df.describe().to_dict(),
                'missing_values': df.isnull().sum().to_dict()
            }
        elif analysis_type == 'correlation':
            result = {
                'correlation': df.corr().to_dict()
            }
        else:
            result = {
                'error': 'Unknown analysis type'
            }
        
        return {'status': 'success', 'result': result}
    
    except Exception as e:
        return {'status': 'error', 'message': str(e)}

# ---- MOCK WAN SERVER ----

class MockWANServer:
    @staticmethod
    def register_receiver(connection_code, salt, endpoint):
        """Register a receiver with its connection code"""
        # In a real app, this would be a server-side operation
        st.session_state['wan_registry'] = st.session_state.get('wan_registry', {})
        st.session_state['wan_registry'][connection_code] = {
            'salt': salt,
            'endpoint': endpoint,
            'messages': [],
            'created_at': datetime.datetime.now().isoformat(),
            'heartbeat': datetime.datetime.now().isoformat(),
            'message_count': 0,
            'metadata': {}
        }
        return True
    
    @staticmethod
    def send_message(connection_code, encrypted_message):
        """Send an encrypted message to a receiver"""
        # In a real app, this would push to a queue or database
        registry = st.session_state.get('wan_registry', {})
        if connection_code not in registry:
            return False
        
        msg_id = str(uuid.uuid4())
        registry[connection_code]['messages'].append({
            'id': msg_id,
            'message': encrypted_message,
            'timestamp': time.time(),
            'status': 'pending',
            'retry_count': 0
        })
        
        # Update message count
        registry[connection_code]['message_count'] += 1
        # Update heartbeat
        registry[connection_code]['heartbeat'] = datetime.datetime.now().isoformat()
        
        return msg_id
    
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
        
        # Update heartbeat
        registry[connection_code]['heartbeat'] = datetime.datetime.now().isoformat()
        
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
                message['processed_at'] = datetime.datetime.now().isoformat()
                if response:
                    message['response'] = response
                return True
        return False
    
    @staticmethod
    def get_response(connection_code, message_id):
        """Get response for a specific message"""
        registry = st.session_state.get('wan_registry', {})
        if connection_code not in registry:
            return None
        
        for message in registry[connection_code]['messages']:
            if message['id'] == message_id and 'response' in message:
                return message['response']
        return None
    
    @staticmethod
    def set_metadata(connection_code, key, value):
        """Set metadata for a connection"""
        registry = st.session_state.get('wan_registry', {})
        if connection_code not in registry:
            return False
        
        registry[connection_code]['metadata'][key] = value
        return True
    
    @staticmethod
    def get_metadata(connection_code, key=None):
        """Get metadata for a connection"""
        registry = st.session_state.get('wan_registry', {})
        if connection_code not in registry:
            return None
        
        if key is None:
            return registry[connection_code]['metadata']
        return registry[connection_code]['metadata'].get(key)
    
    @staticmethod
    def get_connection_stats(connection_code):
        """Get statistics for a connection"""
        registry = st.session_state.get('wan_registry', {})
        if connection_code not in registry:
            return None
        
        conn = registry[connection_code]
        
        # Calculate message statistics
        total_messages = conn['message_count']
        successful_messages = len([m for m in conn['messages'] if m['status'] == 'completed'])
        failed_messages = len([m for m in conn['messages'] if m['status'] == 'error'])
        pending_messages = len([m for m in conn['messages'] if m['status'] in ('pending', 'processing')])
        
        # Calculate uptime
        created_dt = datetime.datetime.fromisoformat(conn['created_at'])
        uptime_seconds = (datetime.datetime.now() - created_dt).total_seconds()
        
        # Check if receiver is active (heartbeat within last 5 minutes)
        last_heartbeat = datetime.datetime.fromisoformat(conn['heartbeat'])
        is_active = (datetime.datetime.now() - last_heartbeat).total_seconds() < 300
        
        return {
            'connection_code': connection_code,
            'created_at': conn['created_at'],
            'uptime_seconds': uptime_seconds,
            'is_active': is_active,
            'last_heartbeat': conn['heartbeat'],
            'total_messages': total_messages,
            'successful_messages': successful_messages,
            'failed_messages': failed_messages,
            'pending_messages': pending_messages,
            'success_rate': successful_messages / total_messages if total_messages > 0 else 0,
            'metadata': conn['metadata']
        }

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
        
        # Set up message log
        st.session_state['message_log'] = []
        
        # Register with the WAN server
        MockWANServer.register_receiver(
            st.session_state['connection_code'],
            st.session_state['salt'],
            "http://receiver-endpoint"  # In a real app, this would be a proper endpoint
        )
        
        # Set initial metadata
        MockWANServer.set_metadata(
            st.session_state['connection_code'],
            'receiver_name',
            f"Receiver-{uuid.uuid4().hex[:6]}"
        )
        MockWANServer.set_metadata(
            st.session_state['connection_code'],
            'max_message_size',
            1048576  # 1MB
        )
        
        st.session_state['receiver_initialized'] = True
    
    # App tabs
    tabs = st.tabs(["Connection", "Instructions", "Monitor", "Settings", "Stats"])
    
    with tabs[0]:  # Connection Tab
        st.header("Your Connection Code")
        st.code(st.session_state['connection_code'], language=None)
        st.info("Share this code with the sender to establish a secure connection.")
        
        # QR code for mobile connections
        st.subheader("Scan QR Code")
        qr_data = f"wan-connect://{st.session_state['connection_code']}"
        
        # Generate a mock QR code (in reality, you'd use a QR code generator)
        qr_mock = generate_chart(data_type='scatter', seed=hash(qr_data) % 10000)
        st.image(f"data:image/png;base64,{qr_mock}", width=200, caption="Scan with mobile app")
        
        # Connection security details
        with st.expander("Connection Security Details"):
            st.write("**Security Protocol:** Fernet symmetric encryption")
            st.write("**Key Derivation:** PBKDF2HMAC with SHA-256")
            st.write("**Connection Established:** ", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    with tabs[1]:  # Instructions Tab
        st.header("Custom Instruction Configuration")
        
        # Default code template selector
        template_options = {
            "Basic Echo & Calculate": """
def process_request(request_data):
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
""",
            "Data Analysis": """
def process_request(request_data):
    if 'action' in request_data:
        if request_data['action'] == 'analyze_data':
            try:
                data_str = request_data.get('data', '')
                analysis_type = request_data.get('analysis_type', 'summary')
                return process_data_analysis(data_str, analysis_type)
            except Exception as e:
                return {'status': 'error', 'message': str(e)}
        elif request_data['action'] == 'generate_chart':
            try:
                chart_type = request_data.get('chart_type', 'line')
                chart_data = generate_chart(chart_type)
                return {'status': 'success', 'chart': chart_data}
            except Exception as e:
                return {'status': 'error', 'message': str(e)}
    
    return {'status': 'error', 'message': 'Unknown action or invalid request'}
""",
            "File Operations": """
def process_request(request_data):
    if 'action' in request_data:
        if request_data['action'] == 'list_files':
            try:
                # Simulated file listing
                files = [
                    {"name": "document1.txt", "size": 1024, "modified": "2025-03-08T10:15:00"},
                    {"name": "image.jpg", "size": 5120, "modified": "2025-03-07T15:30:00"},
                    {"name": "data.csv", "size": 2048, "modified": "2025-03-09T08:45:00"}
                ]
                return {'status': 'success', 'files': files}
            except Exception as e:
                return {'status': 'error', 'message': str(e)}
        elif request_data['action'] == 'file_info':
            try:
                filename = request_data.get('filename', '')
                # Simulated file info
                if filename == "document1.txt":
                    info = {"name": "document1.txt", "size": 1024, "type": "text", "lines": 42}
                    return {'status': 'success', 'file_info': info}
                else:
                    return {'status': 'error', 'message': 'File not found'}
            except Exception as e:
                return {'status': 'error', 'message': str(e)}
    
    return {'status': 'error', 'message': 'Unknown action or invalid request'}
"""
        }
        
        selected_template = st.selectbox("Select Template", list(template_options.keys()))
        
        if 'custom_instructions' not in st.session_state:
            st.session_state['custom_instructions'] = template_options["Basic Echo & Calculate"]
        
        if st.button("Apply Template"):
            st.session_state['custom_instructions'] = template_options[selected_template]
            st.success(f"Applied template: {selected_template}")
        
        custom_code = st.text_area("Custom Request Handler", 
                                   st.session_state['custom_instructions'], 
                                   height=300)
        
        col1, col2 = st.columns(2)
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
            if st.button("Test Instructions"):
                try:
                    # Test with a simple echo request
                    test_request = {"action": "echo", "message": "Test message"}
                    
                    local_vars = {}
                    exec(custom_code, globals(), local_vars)
                    process_function = local_vars.get('process_request')
                    
                    if not process_function:
                        st.error("No process_request function defined")
                    else:
                        result = process_function(test_request)
                        st.success("Test passed!")
                        st.json(result)
                except Exception as e:
                    st.error(f"Error testing instructions: {str(e)}")
    
    with tabs[2]:  # Monitor Tab
        st.header("Request Monitor")
        
        # Message log display
        if 'message_log' not in st.session_state:
            st.session_state['message_log'] = []
        
        # Control buttons
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("Check for Requests"):
                check_and_process_requests()
        
        with col2:
            if st.button("Start Auto-Processing", key="start_auto"):
                st.session_state['auto_processing'] = True
                st.success("Auto-processing started")
        
        with col3:
            if st.button("Stop Auto-Processing", key="stop_auto"):
                st.session_state['auto_processing'] = False
                st.info("Auto-processing stopped")
        
        # Status indicator
        auto_status = "Running" if st.session_state.get('auto_processing', False) else "Stopped"
        st.info(f"Auto-processing: {auto_status}")
        
        # Display message log
        if st.session_state['message_log']:
            st.subheader("Message Log")
            for log_entry in reversed(st.session_state['message_log']):
                timestamp = datetime.datetime.fromtimestamp(log_entry['timestamp']).strftime("%H:%M:%S")
                if log_entry['type'] == 'info':
                    st.info(f"[{timestamp}] {log_entry['message']}")
                elif log_entry['type'] == 'success':
                    st.success(f"[{timestamp}] {log_entry['message']}")
                elif log_entry['type'] == 'error':
                    st.error(f"[{timestamp}] {log_entry['message']}")
        else:
            st.write("No messages yet. Check for requests or enable auto-processing.")
        
        # Add log entry function
        def add_log_entry(type, message):
            st.session_state['message_log'].append({
                'type': type,
                'message': message,
                'timestamp': time.time()
            })
            # Keep only the last 50 messages
            if len(st.session_state['message_log']) > 50:
                st.session_state['message_log'] = st.session_state['message_log'][-50:]
    
    with tabs[3]:  # Settings Tab
        st.header("Receiver Settings")
        
        # Get current metadata
        metadata = MockWANServer.get_metadata(st.session_state['connection_code'])
        if not metadata:
            metadata = {}
        
        # Receiver name
        receiver_name = st.text_input("Receiver Name", metadata.get('receiver_name', ''))
        if st.button("Update Name"):
            MockWANServer.set_metadata(
                st.session_state['connection_code'],
                'receiver_name',
                receiver_name
            )
            st.success(f"Receiver name updated to: {receiver_name}")
        
        # Max message size
        max_size_options = {
            "512 KB": 512 * 1024,
            "1 MB": 1024 * 1024,
            "5 MB": 5 * 1024 * 1024,
            "10 MB": 10 * 1024 * 1024
        }
        current_max_size = metadata.get('max_message_size', 1024 * 1024)
        current_max_size_key = next((k for k, v in max_size_options.items() if v == current_max_size), "1 MB")
        
        selected_max_size = st.selectbox("Maximum Message Size", 
                                         list(max_size_options.keys()),
                                         index=list(max_size_options.keys()).index(current_max_size_key))
        
        if st.button("Update Max Size"):
            MockWANServer.set_metadata(
                st.session_state['connection_code'],
                'max_message_size',
                max_size_options[selected_max_size]
            )
            st.success(f"Maximum message size updated to: {selected_max_size}")
        
        # Auto-processing interval
        if 'auto_processing_interval' not in st.session_state:
            st.session_state['auto_processing_interval'] = 5
            
        auto_interval = st.slider("Auto-processing Check Interval (seconds)", 
                                 min_value=1, max_value=30, 
                                 value=st.session_state['auto_processing_interval'])
        
        if st.button("Update Interval"):
            st.session_state['auto_processing_interval'] = auto_interval
            st.success(f"Auto-processing interval updated to: {auto_interval} seconds")
        
        # Security settings
        st.subheader("Security Settings")
        
        # IP allowlist
        if 'ip_allowlist' not in st.session_state:
            st.session_state['ip_allowlist'] = ""
            
        ip_allowlist = st.text_area("IP Address Allowlist (one per line)", 
                                   st.session_state['ip_allowlist'],
                                   placeholder="192.168.1.1\n10.0.0.1")
        
        if st.button("Update IP Allowlist"):
            st.session_state['ip_allowlist'] = ip_allowlist
            MockWANServer.set_metadata(
                st.session_state['connection_code'],
                'ip_allowlist',
                [ip.strip() for ip in ip_allowlist.split('\n') if ip.strip()]
            )
            st.success("IP allowlist updated")
        
        # Reset connection
        st.subheader("Reset Connection")
        if st.button("Generate New Connection Code", type="primary"):
            if st.session_state.get('confirm_reset', False):
                # Reset the connection
                st.session_state['receiver_initialized'] = False
                st.session_state['confirm_reset'] = False
                st.experimental_rerun()
            else:
                st.session_state['confirm_reset'] = True
                st.warning("Click again to confirm. This will invalidate the current connection.")
    
    with tabs[4]:  # Stats Tab
        st.header("Connection Statistics")
        
        stats = MockWANServer.get_connection_stats(st.session_state['connection_code'])
        
        if stats:
            # Connection info
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Connection Status", "Active" if stats['is_active'] else "Inactive")
                st.metric("Total Messages", stats['total_messages'])
                st.metric("Successful Messages", stats['successful_messages'])
            
            with col2:
                # Calculate uptime in a readable format
                uptime_seconds = stats['uptime_seconds']
                hours, remainder = divmod(uptime_seconds, 3600)
                minutes, seconds = divmod(remainder, 60)
                uptime_str = f"{int(hours)}h {int(minutes)}m {int(seconds)}s"
                
                st.metric("Uptime", uptime_str)
                st.metric("Failed Messages", stats['failed_messages'])
                st.metric("Success Rate", f"{stats['success_rate']*100:.2f}%")
            
            # Generate a mock chart for message statistics
            st.subheader("Message Statistics")
            chart_type = st.selectbox("Chart Type", ["bar", "pie"])
            chart_data = generate_chart(data_type=chart_type, seed=int(time.time()) % 1000)
            st.image(f"data:image/png;base64,{chart_data}")
            
            # Recent activities
            st.subheader("Recent Activity")
            
            # Get messages
            registry = st.session_state.get('wan_registry', {})
            if st.session_state['connection_code'] in registry:
                messages = registry[st.session_state['connection_code']]['messages']
                
                # Create a DataFrame
                if messages:
                    data = []
                    for msg in messages[-10:]:  # Get last 10 messages
                        data.append({
                            'id': msg['id'][:8] + '...',
                            'timestamp': datetime.datetime.fromtimestamp(msg['timestamp']).strftime("%Y-%m-%d %H:%M:%S"),
                            'status': msg['status'].capitalize()
                        })
                    
                    activity_df = pd.DataFrame(data)
                    st.dataframe(activity_df)
                else:
                    st.info("No messages yet")
            
            # System health
            st.subheader("System Health")
            col1, col2, col3 = st.columns(3)
            with col1:
                # Mock CPU usage (random value between 5-20%)
                cpu = np.random.randint(5, 20)
                st.metric("CPU Usage", f"{cpu}%")
            
            with col2:
                # Mock memory usage (random value between 50-200MB)
                memory = np.random.randint(50, 200)
                st.metric("Memory Usage", f"{memory} MB")
            
            with col3:
                # Mock network traffic (random value between 1-100KB/s)
                network = np.random.randint(1, 100)
                st.metric("Network Traffic", f"{network} KB/s")
        else:
            st.error("Could not retrieve connection statistics")
    
    # Function to check and process requests
    def check_and_process_requests():
        messages = MockWANServer.get_messages(st.session_state['connection_code'])
        
        if not messages:
            add_log_entry('info', "Waiting for requests...")
            return
        
        for message in messages:
            try:
                # Decrypt the message
                encrypted_data = message['message']
                decrypted_data = decrypt_message(encrypted_data, st.session_state['encryption_key'])
                
                add_log_entry('info', f"Processing request: {decrypted_data.get('id', 'unknown')}")
                
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
                
                add_log_entry('success', f"Request {decrypted_data.get('id', 'unknown')} processed successfully")
                
            except Exception as e:
                add_log_entry('error', f"Error processing request: {str(e)}")
                MockWANServer.update_message_status(
                    st.session_state['connection_code'],
                    message['timestamp'],
                    'error'
                )
    
    # Auto-processing
    if st.session_state.get('auto_processing', False):
        check_and_process_requests()

# ---- SENDER APP FUNCTIONS ----

def sender_app():
    st.title("Encrypted WAN Sender")
    
    # App tabs
    tabs = st.tabs(["Connect", "Send Request", "Responses", "Saved Requests", "Settings"])
    
    with tabs[0]:  # Connect Tab
        st.header("Connect to Receiver")
        
        # Connection method selector
        connection_method = st.radio(
            "Connection Method",
            ["Enter Code", "Scan QR Code"],
            horizontal=True
        )
        
        if connection_method == "Enter Code":
            # Connection setup 
            connection_code = st.text_input(
                "Enter Connection Code (e.g., ABCD-1234-XYZ9)",
                placeholder="XXXX-XXXX-XXXX"
            )
            
            if st.button("Connect", key="connect_button") and connection_code:
                # In a real app, you would verify the connection code with the server
                if get_from_session('wan_registry', {}).get(connection_code):
                    # Get the salt from the registry
                    salt = get_from_session('wan_registry', {})[connection_code]['salt']
                    # Generate encryption key
                    encryption_key
