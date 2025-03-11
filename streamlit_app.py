import streamlit as st
import socket
import requests
import json
import time
import uuid
from cryptography.fernet import Fernet
import base64

# Generate encryption key
if 'encryption_key' not in st.session_state:
    key = Fernet.generate_key()
    st.session_state.encryption_key = key
    st.session_state.cipher = Fernet(key)

# Get local IP
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

# Check if server is running
def check_server(url):
    try:
        response = requests.get(url, timeout=2)
        return True
    except:
        return False

st.title("WAN Communication App")

# Setup local message store for demo purposes
if 'messages' not in st.session_state:
    st.session_state.messages = {}
if 'device_id' not in st.session_state:
    st.session_state.device_id = str(uuid.uuid4())
if 'received' not in st.session_state:
    st.session_state.received = []

# Simple encryption/decryption
def encrypt(text):
    return st.session_state.cipher.encrypt(json.dumps(text).encode()).decode()

def decrypt(text):
    return json.loads(st.session_state.cipher.decrypt(text.encode()))

# Demo server endpoints (in-memory)
def demo_send_message(target_id, content):
    if target_id not in st.session_state.messages:
        st.session_state.messages[target_id] = []
    st.session_state.messages[target_id].append(content)
    return True

def demo_get_messages(device_id):
    messages = st.session_state.messages.get(device_id, [])
    st.session_state.messages[device_id] = []
    return messages

# Main interface
tabs = st.tabs(["Send Messages", "Receive Messages"])

with tabs[0]:
    st.header("Send Message")
    receiver_id = st.text_input("Receiver ID")
    message = st.text_area("Message")
    
    if st.button("Send Message"):
        if receiver_id and message:
            encrypted = encrypt({"content": message, "from": st.session_state.device_id, "time": time.time()})
            if demo_send_message(receiver_id, encrypted):
                st.success("Message sent!")
        else:
            st.error("Please enter receiver ID and message")

with tabs[1]:
    st.header("Receive Messages")
    st.write(f"Your device ID: **{st.session_state.device_id}**")
    
    if st.button("Check for Messages"):
        messages = demo_get_messages(st.session_state.device_id)
        for msg in messages:
            try:
                decrypted = decrypt(msg)
                st.session_state.received.append(decrypted)
            except:
                st.error("Failed to decrypt a message")
        
        if messages:
            st.success(f"Received {len(messages)} new messages")
        else:
            st.info("No new messages")
    
    # Display received messages
    if st.session_state.received:
        st.subheader("Received Messages")
        for msg in reversed(st.session_state.received):
            with st.expander(f"Message from {msg['from'][:8]}..."):
                st.write(f"**Content:** {msg['content']}")
                st.write(f"**Time:** {time.ctime(msg['time'])}")

with st.sidebar:
    st.header("App Information")
    st.info("""
    This is a simplified version that stores messages in memory for demo purposes.
    
    - Your device ID is shown on the Receive Messages tab
    - To send a message, you need the receiver's device ID
    - Messages are encrypted for security
    """)
    
    st.code(f"Your Device ID: {st.session_state.device_id}")
