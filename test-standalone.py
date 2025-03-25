from mcp import Server, jsonrpc

# Example RPC methods with type hints
@jsonrpc
def add(a: int, b: int) -> int:
    return a + b

@jsonrpc
def greet(name: str, excited: bool = False) -> str:
    return f"Hello {name}{'!' if excited else '.'}"

@jsonrpc
def update_config(settings: dict) -> dict:
    # Echo back the settings
    return settings

if __name__ == "__main__":
    # Start the server
    server = Server()
    server.start()

    # Keep the server running until Ctrl+C
    try:
        while True:
            pass
    except KeyboardInterrupt:
        server.stop()

"""
Example curl commands to test the server:

# Test add method with positional parameters
curl -X POST http://localhost:13337/mcp -H "Content-Type: application/json" -d '{
    "jsonrpc": "2.0",
    "method": "add",
    "params": [5, 3],
    "id": 1
}'

# Test greet method with named parameters
curl -X POST http://localhost:13337/mcp -H "Content-Type: application/json" -d '{
    "jsonrpc": "2.0",
    "method": "greet",
    "params": {"name": "Alice", "excited": true},
    "id": 2
}'

# Test update_config method with a dictionary parameter
curl -X POST http://localhost:13337/mcp -H "Content-Type: application/json" -d '{
    "jsonrpc": "2.0",
    "method": "update_config",
    "params": {"settings": {"theme": "dark", "notifications": true}},
    "id": 3
}'
"""
