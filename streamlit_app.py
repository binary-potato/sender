import streamlit as st
import socket
import json
import time
import uuid
import base64

# Set page title
st.title("Simple Communication App")

# Initialize session state variables
if 'device_id' not in st.session_state:
    st.session_state.device_id = str(uuid.uuid4())
if 'messages' not in st.session_state:
    st.session_state.messages = {}
if 'received' not in st.session_state:
    st.session_state.received = []
if 'sent' not in st.session_state:
    st.session_state.sent = []

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

# Simple encoding/decoding (not encryption, just to avoid plaintext)
def encode_message(message_dict):
    message_json = json.dumps(message_dict)
    return base64.b64encode(message_json.encode()).decode()

def decode_message(encoded_string):
    try:
        decoded = base64.b64decode(encoded_string.encode())
        return json.loads(decoded)
    except:
        return None

# Demo message functions
def send_message(recipient_id, content):
    if recipient_id not in st.session_state.messages:
        st.session_state.messages[recipient_id] = []
    
    message = {
        "content": content,
        "sender": st.session_state.device_id,
        "timestamp": time.time()
    }
    
    encoded = encode_message(message)
    st.session_state.messages[recipient_id].append(encoded)
    
    # Store in sent messages
    st.session_state.sent.append({
        "recipient": recipient_id,
        "content": content,
        "time": time.time()
    })
    
    return True

def check_messages():
    my_id = st.session_state.device_id
    incoming = st.session_state.messages.get(my_id, [])
    
    # Clear messages
    if my_id in st.session_state.messages:
        st.session_state.messages[my_id] = []
    
    new_messages = []
    for encoded_msg in incoming:
        msg = decode_message(encoded_msg)
        if msg:
            new_messages.append(msg)
            st.session_state.received.append(msg)
    
    return new_messages

# Main layout with tabs
tab1, tab2 = st.tabs(["Send", "Receive"])

with tab1:
    st.header("Send Message")
    recipient = st.text_input("Recipient ID")
    message = st.text_area("Message")
    
    if st.button("Send"):
        if recipient and message:
            if send_message(recipient, message):
                st.success("Message sent!")
        else:
            st.warning("Please enter both recipient ID and message")
    
    # Show sent messages
    if st.session_state.sent:
        st.subheader("Sent Messages")
        for msg in reversed(st.session_state.sent):
            st.write(f"To: {msg['recipient']}")
            st.write(f"Message: {msg['content']}")
            st.write(f"Time: {time.ctime(msg['time'])}")
            st.divider()

with tab2:
    st.header("Receive Messages")
    st.info(f"Your Device ID: **{st.session_state.device_id}**")
    
    if st.button("Check for Messages"):
        new_msgs = check_messages()
        if new_msgs:
            st.success(f"Received {len(new_msgs)} new message(s)!")
        else:
            st.info("No new messages")
    
    # Display received messages
    if st.session_state.received:
        st.subheader("Received Messages")
        for msg in reversed(st.session_state.received):
            st.write(f"From: {msg['sender']}")
            st.write(f"Message: {msg['content']}")
            st.write(f"Time: {time.ctime(msg['timestamp'])}")
            st.divider()

# Sidebar with info
with st.sidebar:
    st.header("App Info")
    st.write("This simplified version stores messages in memory only.")
    st.write("Share your Device ID with others to receive messages.")
    
    st.code(st.session_state.device_id)
    
    st.write(f"Your IP address: {get_local_ip()}")
    
    if st.button("Generate New ID"):
        st.session_state.device_id = str(uuid.uuid4())
        st.rerun()
