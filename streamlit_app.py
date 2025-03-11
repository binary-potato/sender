import streamlit as st
import json
import uuid
import base64
import qrcode
import time
import os
import glob
from io import BytesIO
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Set page config
st.set_page_config(
    page_title="WAN Communication App",
    page_icon="🔄",
    layout="wide"
)

# Create messages directory if it doesn't exist
MESSAGE_DIR = "wan_messages"
if not os.path.exists(MESSAGE_DIR):
    os.makedirs(MESSAGE_DIR)

# Initialize session state variables
if 'connection_code' not in st.session_state:
    st.session_state.connection_code = None
if 'my_connection_code' not in st.session_state:
    st.session_state.my_connection_code = None
if 'is_listening' not in st.session_state:
    st.session_state.is_listening = False
if 'received_messages' not in st.session_state:
    st.session_state.received_messages = []
if 'sent_messages' not in st.session_state:
    st.session_state.sent_messages = []
if 'encryption_key' not in st.session_state:
    # Generate a unique salt for the session
    salt = uuid.uuid4().hex.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(b"secure_wan_app_key"))
    st.session_state.encryption_key = key
if 'last_check' not in st.session_state:
    st.session_state.last_check = time.time()

# Setup Fernet encryption
def get_cipher():
    return Fernet(st.session_state.encryption_key)

# Function to generate a unique connection code
def generate_connection_code():
    device_id = str(uuid.uuid4())
    st.session_state.my_connection_code = device_id
    return device_id

# Function to encrypt a message
def encrypt_message(message):
    cipher = get_cipher()
    return cipher.encrypt(json.dumps(message).encode()).decode()

# Function to decrypt a message
def decrypt_message(encrypted_message):
    cipher = get_cipher()
    decrypted = cipher.decrypt(encrypted_message.encode())
    return json.loads(decrypted.decode())

# Function to create a QR code
def generate_qr_code(data):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered)
    return buffered.getvalue()

# File-based message storage system
def store_message(target_id, encrypted_message):
    try:
        filename = os.path.join(MESSAGE_DIR, f"{target_id}_{time.time()}.msg")
        with open(filename, 'w') as f:
            f.write(encrypted_message)
        return True
    except Exception as e:
        st.error(f"Error storing message: {e}")
        return False

def get_messages():
    device_id = st.session_state.my_connection_code
    if not device_id:
        return []
    
    messages = []
    # Get all message files for this device
    message_files = glob.glob(os.path.join(MESSAGE_DIR, f"{device_id}_*.msg"))
    
    for file_path in message_files:
        try:
            with open(file_path, 'r') as f:
                message_content = f.read()
                messages.append(message_content)
            # Delete the file after reading
            os.remove(file_path)
        except Exception as e:
            st.error(f"Error reading message file {file_path}: {e}")
    
    return messages

# Check for new messages
def check_for_messages():
    if st.session_state.my_connection_code and st.session_state.is_listening:
        encrypted_messages = get_messages()
        for encrypted_message in encrypted_messages:
            try:
                message = decrypt_message(encrypted_message)
                # Add message to received messages
                st.session_state.received_messages.append({
                    "timestamp": time.strftime("%H:%M:%S"),
                    "content": message
                })
            except Exception as e:
                st.error(f"Failed to decrypt message: {e}")

# Main app layout
st.title("WAN Communication App")

# Tabs
tab1, tab2 = st.tabs(["Sender Mode", "Receiver Mode"])

# Sender Mode Tab
with tab1:
    st.header("Send Data to Remote Device")
    
    # Input connection code from receiver
    connection_code = st.text_input("Enter Receiver's Connection Code", key="sender_code")
    
    # Message to send
    message_content = st.text_area("Message to Send", height=100)
    
    # Custom instructions for the receiver
    custom_instructions = st.text_area("Custom Instructions for Receiver", 
                                     value="process_data(data)", 
                                     height=100)
    
    # Send button
    if st.button("Send Message"):
        if connection_code and message_content:
            # Ensure we have a connection code for ourselves
            if not st.session_state.my_connection_code:
                st.session_state.my_connection_code = generate_connection_code()
                
            # Prepare message with content and instructions
            message = {
                "content": message_content,
                "instructions": custom_instructions,
                "sender_id": st.session_state.my_connection_code,
                "timestamp": time.time()
            }
            
            # Encrypt the message
            encrypted_message = encrypt_message(message)
            
            # Send to "server" (store in file system)
            if store_message(connection_code, encrypted_message):
                st.success(f"Message sent successfully to {connection_code}!")
                # Track sent messages
                st.session_state.sent_messages.append({
                    "timestamp": time.strftime("%H:%M:%S"),
                    "target": connection_code,
                    "content": message_content
                })
            else:
                st.error("Failed to send message.")
        else:
            st.warning("Please enter both a connection code and a message.")
    
    # Display sent messages
    if st.session_state.sent_messages:
        st.subheader("Sent Messages")
        for idx, msg in enumerate(reversed(st.session_state.sent_messages)):
            st.text(f"[{msg['timestamp']}] To {msg['target']}: {msg['content']}")

# Receiver Mode Tab
with tab2:
    st.header("Receive Data from Remote Device")
    
    # Generate connection code if not already generated
    if not st.session_state.my_connection_code:
        st.session_state.my_connection_code = generate_connection_code()
    
    # Display connection code
    st.subheader("Your Connection Code")
    st.code(st.session_state.my_connection_code)
    
    # Copy button for connection code
    if st.button("Copy Connection Code"):
        st.success("Connection code copied to clipboard!")
        st.write("You can paste this in the sender app.")
    
    # Generate QR code for the connection code
    qr_code = generate_qr_code(st.session_state.my_connection_code)
    st.image(qr_code, caption="Scan this QR code with the sender device")
    
    # Start/Stop listening button
    listen_col1, listen_col2 = st.columns(2)
    with listen_col1:
        if st.button("Start Listening" if not st.session_state.is_listening else "Stop Listening"):
            st.session_state.is_listening = not st.session_state.is_listening
            if st.session_state.is_listening:
                st.success("Started listening for messages...")
            else:
                st.info("Stopped listening for messages.")
    
    with listen_col2:
        if st.session_state.is_listening:
            st.success("✅ Active: Listening for messages...")
        else:
            st.warning("❌ Inactive: Not listening for messages")
    
    # Custom code for processing received data
    st.subheader("Custom Processing Code")
    custom_processor = st.text_area(
        "Define how to process incoming data",
        value="""def process_data(data):
    # Example processing: convert to uppercase
    return f"Processed: {data.upper()}"
""",
        height=150
    )
    
    # Display received messages
    if st.session_state.received_messages:
        st.subheader("Received Messages")
        for idx, msg in enumerate(reversed(st.session_state.received_messages)):
            with st.expander(f"Message [{msg['timestamp']}]", expanded=idx==0):
                st.write("Content:", msg['content']['content'])
                st.write("Instructions:", msg['content']['instructions'])
                st.write("From:", msg['content']['sender_id'])
                
                # Execute custom instructions if any
                if 'instructions' in msg['content'] and msg['content']['instructions']:
                    st.subheader("Processing Result")
                    try:
                        # Create a safe execution environment
                        local_env = {'data': msg['content']['content']}
                        # Add the user-defined process_data function
                        exec(custom_processor, globals(), local_env)
                        
                        # Execute the instructions from the message
                        result = eval(msg['content']['instructions'], globals(), local_env)
                        st.success(f"Result: {result}")
                        
                        # Send result back to sender
                        reply_key = f"respond_{idx}"
                        if st.button(f"Send Result Back to Sender", key=reply_key):
                            response_message = {
                                "content": str(result),
                                "original_message": msg['content']['content'],
                                "instructions": "",  # No instructions for the response
                                "sender_id": st.session_state.my_connection_code,
                                "timestamp": time.time()
                            }
                            encrypted_response = encrypt_message(response_message)
                            if store_message(msg['content']['sender_id'], encrypted_response):
                                st.success(f"Response sent successfully to {msg['content']['sender_id']}!")
                            else:
                                st.error("Failed to send response.")
                    except Exception as e:
                        st.error(f"Error executing instructions: {e}")
                        st.code(str(e))

# Main sidebar with app info and controls
with st.sidebar:
    st.header("App Controls")
    
    # Display your own connection code
    if st.session_state.my_connection_code:
        st.subheader("Your Device ID")
        st.code(st.session_state.my_connection_code)
    
    # Add a refresh button to manually check for messages
    if st.button("Check for Messages"):
        check_for_messages()
        st.success("Checked for new messages")
        
    # Add a new connection code button
    if st.button("Generate New Connection Code"):
        st.session_state.my_connection_code = generate_connection_code()
        st.success("Generated new connection code!")
        
    st.divider()
    
    st.header("App Information")
    st.info("""
    This app allows two devices to communicate using an encrypted protocol.
    
    **How to use:**
    1. On the receiver device, start in "Receiver Mode"
    2. Click "Start Listening" to begin receiving messages
    3. Share the connection code with the sender
    4. On the sender device, enter the connection code and send a message
    5. The receiver will process the message and can send a response back
    
    **Note:** Messages are stored in the file system for delivery between users.
    """)

# Check for messages on page load if listening is active
check_for_messages()

# Add automatic periodic refresh if listening
if st.session_state.is_listening:
    # Only rerun every 3 seconds to avoid too many refreshes
    current_time = time.time()
    if current_time - st.session_state.last_check > 3:
        st.session_state.last_check = current_time
        st.rerun()
