import pyperclip
import base64
import urllib.parse
import binascii

# Functions for different encoding and decoding algorithms

def base64_encode(data):
    """Encode data using Base64."""
    encoded_bytes = base64.b64encode(data.encode('utf-8'))
    return encoded_bytes.decode('utf-8')

def base64_decode(data):
    """Decode Base64 encoded data."""
    decoded_bytes = base64.b64decode(data.encode('utf-8'))
    return decoded_bytes.decode('utf-8')

def url_encode(data):
    """URL-encode data."""
    return urllib.parse.quote(data, safe="")

def url_decode(data):
    """URL-decode data."""
    return urllib.parse.unquote(data)

def hex_encode(data):
    """Hex-encode data."""
    encoded_bytes = binascii.hexlify(data.encode('utf-8'))
    return encoded_bytes.decode('utf-8')

def hex_decode(data):
    """Hex-decode data."""
    decoded_bytes = binascii.unhexlify(data.encode('utf-8'))
    return decoded_bytes.decode('utf-8')

# Main tool logic

def clipboard_tool():
    print("Welcome to Clipboard Encoding/Decoding Tool")
    print("Commands: base64-encode, base64-decode, url-encode, url-decode, hex-encode, hex-decode")
    
    # Get the command from the user
    command = input("Enter the command (e.g., base64-encode): ").strip().lower()
    
    # Access the clipboard data
    clipboard_data = pyperclip.paste()
    print(f"Clipboard data: {clipboard_data}")
    
    # Perform the operation based on the command
    result = None
    try:
        if command == "base64-encode":
            result = base64_encode(clipboard_data)
        elif command == "base64-decode":
            result = base64_decode(clipboard_data)
        elif command == "url-encode":
            result = url_encode(clipboard_data)
        elif command == "url-decode":
            result = url_decode(clipboard_data)
        elif command == "hex-encode":
            result = hex_encode(clipboard_data)
        elif command == "hex-decode":
            result = hex_decode(clipboard_data)
        else:
            print("Invalid command!")
            return
        
        # Copy the result back to the clipboard and display it
        pyperclip.copy(result)
        print(f"Result: {result} (Copied to clipboard)")
    except Exception as e:
        print(f"Error: {str(e)}")

# Run the tool
if __name__ == "__main__":
    clipboard_tool()
