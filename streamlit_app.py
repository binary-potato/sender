import streamlit as st
import json
import uuid
import base64
import qrcode
import time
from io import BytesIO
import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Set page config
st.set_page_config(
    page_title="WAN Communication App",
    page_icon="🔄",
    layout="wide"
)

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
if 'message_store' not in st.session_state:
    st.session_state.message_store = {}

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

# Using session state as a simple database (in a real app, you'd use a real database)
def store_message(target_id, encrypted_message):
    if target_id not in st.session_state.message_store:
        st.session_state.message_store[target_id] = []
    st.session_state.message_store[target_id].append(encrypted_message)
    return True

def get_messages():
    device_id = st.session_state.my_connection_code
    if not device_id or device_id not in st.session_state.message_store:
        return []
    
    messages = st.session_state.message_store.get(device_id, [])
    if device_id in st.session_state.message_store:
        st.session_state.message_store[device_id] = []  # Clear messages after retrieving
    return messages

# Check for new messages (this will be called regularly with st.rerun)
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
                print(e)

# Main app layout
st.title("WAN Communication App")
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
            
            # Send to "server" (store in session state)
            if store_message(connection_code, encrypted_message):
                st.success("Message sent successfully!")
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
        for idx, msg in enumerate(st.session_state.sent_messages):
            st.text(f"[{msg['timestamp']}] To {msg['target']}: {msg['content']}")

# Receiver Mode Tab
with tab2:
    st.header("Receive Data from Remote Device")
    
    # Generate connection code if not already generated
    if not st.session_state.my_connection_code:
        st.session_state.my_connection_code = generate_connection_code()
    
    # Display connection code
    st.subheader("Your Connection Code")
    connection_code_container = st.container()
    with connection_code_container:
        st.code(st.session_state.my_connection_code)
    
    # Generate QR code for the connection code
    qr_code = generate_qr_code(st.session_state.my_connection_code)
    st.image(qr_code, caption="Scan this QR code with the sender device")
    
    # Start/Stop listening button
    listen_col1, listen_col2 = st.columns(2)
    with listen_col1:
        if st.button("Start Listening" if not st.session_state.is_listening else "Stop Listening"):
            st.session_state.is_listening = not st.session_state.is_listening
            if st.session_state.is_listening:
                st.info("Started listening for messages...")
            else:
                st.info("Stopped listening for messages.")
    
    with listen_col2:
        if st.session_state.is_listening:
            st.success("Listening for messages...")
        else:
            st.warning("Not listening for messages")
    
    # Custom code for processing received data
    st.subheader("Custom Processing Code")
    custom_processor = st.text_area(
        "Define how to process incoming data",
        value="""def process_data(data):
    # Example processing
    return f"Processed: {data.upper()}"
""",
        height=150
    )
    
    # Display received messages
    if st.session_state.received_messages:
        st.subheader("Received Messages")
        for idx, msg in enumerate(st.session_state.received_messages):
            with st.expander(f"Message [{msg['timestamp']}]"):
                st.write("Content:", msg['content']['content'])
                st.write("Instructions:", msg['content']['instructions'])
                
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
                        if st.button(f"Send Result Back to Sender", key=f"respond_{idx}"):
                            response_message = {
                                "content": str(result),
                                "original_message": msg['content']['content'],
                                "sender_id": st.session_state.my_connection_code,
                                "timestamp": time.time()
                            }
                            encrypted_response = encrypt_message(response_message)
                            if store_message(msg['content']['sender_id'], encrypted_response):
                                st.success("Response sent successfully!")
                            else:
                                st.error("Failed to send response.")
                    except Exception as e:
                        st.error(f"Error executing instructions: {e}")

# Main sidebar with app info
with st.sidebar:
    st.header("App Information")
    st.info("""
    This app allows two devices to communicate over a WAN network using an encrypted protocol.
    
    **How to use:**
    1. On the receiver device, start in "Receiver Mode"
    2. Share the connection code with the sender
    3. On the sender device, enter the connection code and send a message
    4. The receiver will process the message and can send a response back
    
    **Note:** This demo uses Streamlit's session state for message storage. In a real-world application, you would implement a proper backend server.
    """)
    
    # Display your own connection code
    if st.session_state.my_connection_code:
        st.subheader("Your Device ID")
        st.code(st.session_state.my_connection_code)
    
    # Add a refresh button to manually check for messages
    if st.button("Check for Messages"):
        check_for_messages()
        st.success("Checked for new messages")

# Check for messages on page load if listening is active
check_for_messages()

# Add automatic periodic refresh if listening
if st.session_state.is_listening:
    # Only rerun every 3 seconds to avoid too many refreshes
    current_time = time.time()
    if current_time - st.session_state.last_check > 3:
        st.session_state.last_check = current_time
        st.rerun()
