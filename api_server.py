from fastapi import FastAPI
from pydantic import BaseModel
import socket
import uvicorn

# Initialize FastAPI app
api = FastAPI()

# Data models for API
class Message(BaseModel):
    target_id: str
    encrypted_content: str

# In-memory message store
message_store = {}

# API endpoint to receive messages
@api.post("/send_message")
async def receive_message(message: Message):
    if message.target_id not in message_store:
        message_store[message.target_id] = []
    message_store[message.target_id].append(message.encrypted_content)
    return {"status": "success"}

# API endpoint to retrieve messages
@api.get("/get_messages/{device_id}")
async def get_messages(device_id: str):
    messages = message_store.get(device_id, [])
    # Clear messages after retrieving
    if device_id in message_store:
        message_store[device_id] = []
    return {"messages": messages}

# Get local IP address
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't need to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

if __name__ == "__main__":
    host = get_local_ip()
    port = 8000
    print(f"Starting API server at http://{host}:{port}")
    uvicorn.run(api, host=host, port=port)
