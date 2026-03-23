import os
import smtplib
import random
import jwt
from datetime import datetime, timedelta
from email.message import EmailMessage
from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# DATABASE CONFIGURATION
client = AsyncIOMotorClient(os.getenv("MONGO_URI"))
db = client["SudeepCloud"]
users_col = db["users"]
otp_col = db["pending_otps"]

# SECURITY CONFIGURATION
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.getenv("JWT_SECRET", "supersecretkey")
ALGORITHM = "HS256"

# DATA MODELS
class AuthRequest(BaseModel):
    email: str
    password: str

class OTPVerify(BaseModel):
    email: str
    otp: str

# EMAIL FUNCTION
def send_email_sync(email: str, otp: str):
    msg = EmailMessage()
    msg.set_content(f"Your SudeepCloud verification OTP is: {otp}\n\nDo not share this with anyone.")
    msg["Subject"] = "Verify your SudeepCloud Account"
    msg["From"] = os.getenv("SMTP_EMAIL")
    msg["To"] = email

    try:
        server = smtplib.SMTP(os.getenv("SMTP_SERVER"), 587)
        server.starttls()
        server.login(os.getenv("SMTP_EMAIL"), os.getenv("SMTP_PASSWORD"))
        server.send_message(msg)
        server.quit()
    except Exception as e:
        print(f"SMTP Error: {e}")

# SERVE HTML PAGE
@app.get("/", response_class=HTMLResponse)
async def serve_login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

# 1. SEND OTP API
@app.post("/send-otp")
async def send_otp(data: AuthRequest, background_tasks: BackgroundTasks):
    user = await users_col.find_one({"email": data.email})
    if user:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Generate 6 digit OTP
    otp = str(random.randint(100000, 999999))
    hashed_password = pwd_context.hash(data.password)

    # Save OTP to database (upsert)
    await otp_col.update_one(
        {"email": data.email},
        {"$set": {"otp": otp, "password": hashed_password, "created_at": datetime.utcnow()}},
        upsert=True
    )

    # Send email in background
    background_tasks.add_task(send_email_sync, data.email, otp)
    return {"message": "OTP sent successfully"}

# 2. VERIFY OTP & CREATE ACCOUNT
@app.post("/verify-otp")
async def verify_otp(data: OTPVerify):
    record = await otp_col.find_one({"email": data.email})
    
    if not record or record["otp"] != data.otp:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    # Create User
    new_user = {
        "email": data.email,
        "password": record["password"],
        "role": "user",
        "status": "active",
        "created_at": datetime.utcnow()
    }
    await users_col.insert_one(new_user)
    await otp_col.delete_one({"email": data.email}) # Clean up OTP

    return {"message": "Account created successfully"}

# 3. LOGIN & ISSUE JWT TOKEN
@app.post("/login")
async def login(data: AuthRequest):
    user = await users_col.find_one({"email": data.email})
    
    if not user or not pwd_context.verify(data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if user.get("status") == "suspended":
        raise HTTPException(status_code=403, detail="Account is suspended by Admin")

    # Create JWT Token
    expire = datetime.utcnow() + timedelta(days=7)
    token_data = {"sub": user["email"], "role": user["role"], "exp": expire}
    token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)

    return {"access_token": token, "token_type": "bearer"}
  
