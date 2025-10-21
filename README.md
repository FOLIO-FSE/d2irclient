# D2IR Client for Python
D2IRClient implements a basic API client for the Direct to INN-Reach (D2IR) API for INN-Reach resource sharing services.

## Getting Started
### Installation
```bash
pip intall d2irclient
```
or
```bash
uv pip install d2irclient
```

### Environment Variables
We recommend setting your connection parameters via environment variable:
```bash
export D2IR_API_KEY='<api_key>'
export D2IR_API_SECRET='<api_secret>'
export D2IR_AUTH_URL='https://<d2ir_server_domain>/auth/v1/oauth2/token'
export D2IR_ROOT_URL='https://<d2ir_server_domain>/innreach/'
export D2IR_LOCAL_SERVER_CODE='<local_server_code>'
export D2IR_CENTRAL_SERVER_CODE='<central_server_code>'
```

### Connecting to the D2IR service
```python
from d2irclient.D2IRClient import D2IRClient
dc = D2IRClient(
    d2ir_auth_url=os.environ.get("D2IR_AUTH_URL"),
    d2ir_root_url=os.environ.get("D2IR_ROOT_URL"),
    d2ir_key=os.environ.get("D2IR_API_KEY"),
    d2ir_secret=os.environ.get("D2IR_ROOT_URL"),
    from_server_code=os.environ.get("D2IR_LOCAL_SERVER_CODE"),
    to_server_code=os.environ.get("D2IR_CENTRAL_SERVER_CODE")
)
```

### Calling APIs
```python
# Fetch the current list of contributed locations
location_config = dc.d2ir_get("v2/contribution/locations")

# Add a location
location_config["locationList"].append({"locationKey": "abcde", "description": "Alphabet Library"})

# Replace all locations with updated list
_ = dc.d2ir_post("v2/contribution/locations", json=location_config)
```

