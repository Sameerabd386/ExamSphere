from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from pymongo import MongoClient
from passlib.context import CryptContext
from typing import List, Optional
import os
import jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load environment variables from the .env file
load_dotenv()

# --- Configuration and Initialization ---
mongo_uri = os.getenv('MONGO_URI')
jwt_secret = os.getenv('JWT_SECRET')
jwt_algorithm = os.getenv('JWT_ALGORITHM', 'HS256')

if not mongo_uri or not jwt_secret:
    raise ValueError("MONGO_URI and JWT_SECRET environment variables must be set")

app = FastAPI()
client = MongoClient(mongo_uri)
db = client.get_database('examsphere_db')

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- Pydantic Models for Request and Response Data ---
class UserInDB(BaseModel):
    username: str
    password: str

class UserRegister(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class Question(BaseModel):
    question_text: str
    options: List[str]
    correct_answer: str

class Quiz(BaseModel):
    questions: List[Question]

class UserAnswer(BaseModel):
    question_text: str
    submitted_answer: str

class ExamSubmission(BaseModel):
    answers: List[UserAnswer]

# --- Security and Authentication Functions ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, jwt_secret, algorithm=jwt_algorithm)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, jwt_secret, algorithms=[jwt_algorithm])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
            )
        user = db.get_collection("users").find_one({"username": username})
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
            )
        return user
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )

# --- API Endpoints ---
@app.get("/", tags=["Home"])
def home():
    return {"message": "Welcome to ExamSphere! This is a FastAPI backend."}

@app.post("/register", response_model=Token, tags=["Authentication"])
async def register_user(user_data: UserRegister):
    users_collection = db.get_collection("users")
    existing_user = users_collection.find_one({"username": user_data.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    hashed_password = pwd_context.hash(user_data.password)
    user = {"username": user_data.username, "password": hashed_password}
    users_collection.insert_one(user)

    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/token", response_model=Token, tags=["Authentication"])
async def login_for_access_token(user_data: UserLogin):
    user = db.get_collection("users").find_one({"username": user_data.username})
    if not user or not verify_password(user_data.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/quiz", tags=["Exam"])
async def get_quiz(current_user: dict = Depends(get_current_user)):
    # This is a placeholder for generating quiz questions
    # In a real-world scenario, you would fetch questions from a database and randomize them.
    questions = [
        {"question_text": "What does API stand for?", "options": ["Application Programming Interface", "Advanced Programming Interface", "Automated Personal Interface", "Application Protocol Instruction"], "correct_answer": "Application Programming Interface"},
        {"question_text": "Which of these is a NoSQL database?", "options": ["MySQL", "PostgreSQL", "MongoDB", "SQLite"], "correct_answer": "MongoDB"},
    ]
    return {"quiz_questions": questions}

@app.post("/submit-exam", tags=["Exam"])
async def submit_exam(submission: ExamSubmission, current_user: dict = Depends(get_current_user)):
    # This is a placeholder for calculating the score
    # You would fetch the correct answers from the database to validate the submission
    correct_answers = {
        "What does API stand for?": "Application Programming Interface",
        "Which of these is a NoSQL database?": "MongoDB",
    }
    
    score = 0
    for answer in submission.answers:
        if correct_answers.get(answer.question_text) == answer.submitted_answer:
            score += 1
    
    return {"message": "Exam submitted successfully", "score": score}

@app.get("/users/me", tags=["Authentication"])
async def read_users_me(current_user: dict = Depends(get_current_user)):
    return {"username": current_user["username"]}
