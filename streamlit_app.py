import streamlit as st
import socket
import threading
import json
import time
import hashlib
import base64
import uuid
import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Initialize session state variables if they don't exist
if 'connection_id' not in st.session_state:
    st.session_state.connection_id = ""
if 'encryption_key' not in st.session_state:
    st.session_state.encryption_key = None
if 'receiver_address' not in st.session_state:
    st.session_state.receiver_address = ""
if 'responses' not in st.session_state:
    st.session_state.responses = []

def generate_key(passcode):
    """Generate a Fernet key from a passcode."""
    salt = b'static_salt_for_key_derivation'  # In production, use a secure random salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passcode.encode()))
    return key

def encrypt_message(message, key):
    """Encrypt a message using Fernet symmetric encryption."""
    f = Fernet(key)
    return f.encrypt(json.dumps(message).encode()).decode()

def decrypt_message(encrypted_message, key):
    """Decrypt a message using Fernet symmetric encryption."""
    f = Fernet(key)
    decrypted = f.decrypt(encrypted_message.encode())
    return json.loads(decrypted.decode())

def send_request(request_type, data, receiver_address, connection_id, encryption_key):
    """Send an encrypted request to the receiver and get the response."""
    try:
        payload = {
            "connection_id": connection_id,
            "request_type": request_type,
            "data": data,
            "timestamp": time.time()
        }
        
        encrypted_payload = encrypt_message(payload, encryption_key)
        
        response = requests.post(
            f"{receiver_address}/api/request",
            json={"encrypted_payload": encrypted_payload}
        )
        
        if response.status_code == 200:
            encrypted_response = response.json().get("encrypted_response")
            decrypted_response = decrypt_message(encrypted_response, encryption_key)
            return True, decrypted_response
        else:
            return False, f"Error: {response.status_code} - {response.text}"
    except Exception as e:
        return False, f"Error: {str(e)}"

def main():
    st.title("Secure WAN Communication App")
    
    tabs = st.tabs(["Connection Setup", "Send Requests", "Response History"])
    
    with tabs[0]:
        st.header("Connection Setup")
        
        st.subheader("Create New Connection")
        if st.button("Generate New Connection ID"):
            new_connection_id = str(uuid.uuid4())
            new_passcode = hashlib.sha256(str(time.time()).encode()).hexdigest()[:12]
            st.session_state.connection_id = new_connection_id
            st.session_state.encryption_key = generate_key(new_passcode)
            
            st.success("New connection created!")
            st.code(f"Connection ID: {new_connection_id}")
            st.code(f"Passcode: {new_passcode}")
            st.info("Share these details with the receiver app")
        
        st.divider()
        
        st.subheader("Enter Receiver Connection Details")
        connection_id = st.text_input("Connection ID", value=st.session_state.connection_id)
        passcode = st.text_input("Passcode", type="password")
        receiver_address = st.text_input("Receiver Address (e.g., http://receiver-ip:8501)", 
                                         value=st.session_state.receiver_address)
        
        if st.button("Connect to Receiver"):
            if connection_id and passcode and receiver_address:
                st.session_state.connection_id = connection_id
                st.session_state.encryption_key = generate_key(passcode)
                st.session_state.receiver_address = receiver_address
                
                # Test connection
                success, response = send_request(
                    "connection_test", 
                    {"message": "Hello from sender"}, 
                    receiver_address,
                    connection_id,
                    st.session_state.encryption_key
                )
                
                if success:
                    st.success(f"Connection successful! Receiver says: {response.get('message', 'No message')}")
                else:
                    st.error(f"Connection failed: {response}")
            else:
                st.warning("Please fill in all connection details")
    
    with tabs[1]:
        st.header("Send Requests")
        
        if not st.session_state.connection_id or not st.session_state.encryption_key or not st.session_state.receiver_address:
            st.warning("Please set up connection details first")
        else:
            st.info(f"Connected to: {st.session_state.receiver_address}")
            st.info(f"Connection ID: {st.session_state.connection_id}")
            
            request_type = st.selectbox(
                "Request Type",
                ["text_message", "file_request", "data_processing", "custom_action"]
            )
            
            if request_type == "text_message":
                message = st.text_area("Message")
                data = {"message": message}
            elif request_type == "file_request":
                file_path = st.text_input("File Path")
                data = {"file_path": file_path}
            elif request_type == "data_processing":
                input_data = st.text_area("Data to Process (JSON)")
                processing_type = st.selectbox("Processing Type", ["summarize", "analyze", "transform"])
                try:
                    data = {
                        "input": json.loads(input_data) if input_data else {},
                        "processing_type": processing_type
                    }
                except json.JSONDecodeError:
                    st.error("Invalid JSON format")
                    data = None
            elif request_type == "custom_action":
                action_name = st.text_input("Action Name")
                parameters = st.text_area("Parameters (JSON)")
                try:
                    data = {
                        "action": action_name,
                        "parameters": json.loads(parameters) if parameters else {}
                    }
                except json.JSONDecodeError:
                    st.error("Invalid JSON format")
                    data = None
            
            if st.button("Send Request"):
                if data:
                    with st.spinner("Sending request..."):
                        success, response = send_request(
                            request_type,
                            data,
                            st.session_state.receiver_address,
                            st.session_state.connection_id,
                            st.session_state.encryption_key
                        )
                        
                        if success:
                            st.success("Request sent successfully")
                            st.json(response)
                            
                            # Save to history
                            history_entry = {
                                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                                "request_type": request_type,
                                "request_data": data,
                                "response": response
                            }
                            st.session_state.responses.insert(0, history_entry)
                        else:
                            st.error(f"Request failed: {response}")
    
    with tabs[2]:
        st.header("Response History")
        
        if not st.session_state.responses:
            st.info("No responses yet")
        else:
            for i, entry in enumerate(st.session_state.responses):
                with st.expander(f"{entry['timestamp']} - {entry['request_type']}"):
                    st.subheader("Request")
                    st.json(entry['request_data'])
                    st.subheader("Response")
                    st.json(entry['response'])

if __name__ == "__main__":
    main()
