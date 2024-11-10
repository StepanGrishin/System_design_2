from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext

SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

class User(BaseModel):
    id: int
    username: str
    email: str
    hashed_password: str
    first_name: str
    last_name: str
    age: Optional[int] = None

class Post(BaseModel):
    id: int  # уникальный идентификатор для поста
    user_id: int  # идентификатор пользователя
    content: str  # содержание поста
    created_at: datetime  # дата создания поста

class Message(BaseModel):
    id: int
    sender_id: int
    receiver_id: int
    content: str
    created_at: datetime

users_db = []
posts_db = []
messages_db = []

client_db = {
    "admin": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW"  # hashed "secret"
}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def get_current_client(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        return username
    except JWTError:
        raise credentials_exception

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now() + expires_delta
    else:
        expire = datetime.now() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    password_check = False
    if form_data.username in client_db:
        password = client_db[form_data.username]
        if pwd_context.verify(form_data.password, password):
            password_check = True

    if password_check:
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(data={"sub": form_data.username}, expires_delta=access_token_expires)
        return {"access_token": access_token, "token_type": "bearer"}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
# получение юзера по id
@app.post("/users", response_model=User)
def create_user(user: User, current_user: str = Depends(get_current_client)):
    for u in users_db:
        if u.id == user.id:
            raise HTTPException(status_code=400, detail="User already exists")
    users_db.append(user)
    return user
  
# Получение юзера по username
@app.get("/users/username/{username}", response_model=User)
def get_user_by_username(username: str, current_user: str = Depends(get_current_client)):
    for user in users_db:
        print(user, " " , username)
        if (user.username.lower() == username.lower()):   
            return user
    raise HTTPException(status_code=404, detail="User not found")
  
# Получение юзера по имени и фамилии
@app.get("/users/search", response_model=User)
def search_users(first_name: Optional[str] = None, last_name: Optional[str] = None, current_user: str = Depends(get_current_client)):
    for user in users_db:
        # Приводим к нижнему регистру для поиска без учета регистра
        if (first_name.lower() == user.first_name.lower()) and (last_name.lower() == user.last_name.lower()):
            return user
          
# Создание поста
@app.post("/posts", response_model=Post)
def create_post(post: Post, current_user: str = Depends(get_current_client)):
    posts_db.append(post)
    return post

# Загрузка стены пользователя
@app.get("/posts/{user_id}", response_model=List[Post])
def get_user_wall(user_id: int, current_user: str = Depends(get_current_client)):
    user_posts = [post for post in posts_db if post.user_id == user_id]  # Сравниваем по `user_id`
    return user_posts

# Отправка сообщения пользователю
@app.post("/messages", response_model=Message)
def send_message(message: Message, current_user: str = Depends(get_current_client)):
    messages_db.append(message)
    return message

# Получение списка сообщений для пользователя
@app.get("/messages/{user_id}", response_model=List[Message])
def get_messages(user_id: int, current_user: str = Depends(get_current_client)):
    user_messages = [msg for msg in messages_db if msg.receiver_id == user_id]
    return user_messages

# Запуск сервера
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
