from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import bcrypt
from motor.motor_asyncio import AsyncIOMotorClient
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

# CORS for your Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB connection
MONGODB_URI = os.getenv("MONGODB_URI")
DATABASE_NAME = os.getenv("DATABASE_NAME", "backend")

client = AsyncIOMotorClient(MONGODB_URI)
db = client[DATABASE_NAME]

class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    role: str = "end-user"

@app.post("/login")  # Matches your frontend fetch URL
async def login(login_data: LoginRequest):
    try:
        # Find user by email
        user = await db.users.find_one({"email": login_data.email})
        if not user:
            raise HTTPException(status_code=400, detail="Invalid credentials")
        
        # Verify password
        if not bcrypt.checkpw(login_data.password.encode(), user["password"].encode()):
            raise HTTPException(status_code=400, detail="Invalid credentials")
        
        # Check role
        if login_data.role != user.get("role", "end-user"):
            raise HTTPException(status_code=403, detail="Access denied")
        
        return {
            "success": True,
            "message": f"Login successful as {user['role']}",
            "user": {
                "id": str(user["_id"]),
                "username": user.get("username"),
                "email": user["email"],
                "role": user["role"]
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Login failed")

@app.post("/create-demo-users")
async def create_demo_users():
    hashed_password = bcrypt.hashpw("password123".encode(), bcrypt.gensalt()).decode()
    
    users = [
        {
            "email": "user@example.com",
            "username": "John Doe",
            "password": hashed_password,
            "role": "end-user"
        },
        {
            "email": "admin@example.com", 
            "username": "Admin User",
            "password": hashed_password,
            "role": "admin"
        }
    ]
    
    for user in users:
        existing = await db.users.find_one({"email": user["email"]})
        if not existing:
            await db.users.insert_one(user)
    
    return {
        "success": True,
        "message": "Demo users created",
        "credentials": [
            {"email": "user@example.com", "password": "password123", "role": "end-user"},
            {"email": "admin@example.com", "password": "password123", "role": "admin"}
        ]
    }

@app.get("/")
async def root():
    return {"message": "Login API is running"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
