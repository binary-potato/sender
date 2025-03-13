import streamlit as st
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
        "apiKey": "AIzaSyBAspGDK14JlqF9RgumIc40DL-SMdshz8c",  # Replace with your Firebase API key
        "authDomain": "science-project-c6e47.firebaseapp.com",  # Replace with your Firebase auth domain
        "databaseURL": "https://science-project-c6e47-default-rtdb.firebaseio.com",  # Replace with your Firebase database URL
        "storageBucket": "science-project-c6e47.firebasestorage.app",  # Replace with your Firebase storage bucket
    }
    
    # Initialize Firebase
    firebase = pyrebase.initialize_app(config)
    return firebase

# Initialize db as None before the try block
db = None

try:
    firebase = initialize_firebase()
    db = firebase.database()
except Exception as e:
    st.error(f"Firebase initialization error: {e}")
    st.info("Please update the Firebase configuration.")

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
            st.rerun()  # Updated from experimental_rerun()
        
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
                st.rerun()  # Updated from experimental_rerun()
        
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
                
                # Check if db is initialized
                if db is None:
                    st.error("Firebase database is not initialized. Please check your configuration.")
                else:
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
                                        except Exception as math_error:
                                            result = f"Invalid math expression: {str(math_error)}"
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
                # Check if db is initialized
                if db is None:
                    st.error("Firebase database is not initialized. Please check your configuration.")
                else:
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
