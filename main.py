import smtplib
import dns.resolver
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

class EmailCheckRequest(BaseModel):
    email: str

@app.post("/verify")
def verify_email_handshake(payload: EmailCheckRequest):
    email = payload.email
    if '@' not in email:
        raise HTTPException(status_code=400, detail="Invalid email format")
        
    domain = email.split('@')[-1]
    
    # 1. Resolve MX Records
    try:
        records = dns.resolver.resolve(domain, 'MX')
        mx_records = sorted(records, key=lambda r: r.preference)
        # Using [0] to grab the highest priority record's exchange
        mx_host = str(mx_records[0].exchange).rstrip('.')
    except Exception as e:
        return {"status": "error", "message": f"MX resolution failed: {str(e)}"}

    # 2. Perform the exact handshake you requested
    try:
        server = smtplib.SMTP(mx_host, 25, timeout=10)
        server.ehlo('google.com') 
        server.mail('verify-agent@gmail.com')
        
        # Read the server response
        code, message = server.rcpt(email)
        server.quit() # Hang up before sending data
        
        server_reply = message.decode('utf-8', errors='ignore').strip()
        
        return {
            "status": "success",
            "code": code,
            "server_reply": server_reply,
            "is_valid": (code == 250)
        }
            
    except Exception as e:
        return {"status": "blocked", "message": f"Connection dropped by target: {str(e)}"}
