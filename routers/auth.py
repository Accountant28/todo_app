from fastapi import Depends, HTTPException, status, APIRouter, Request, Response, Form
from typing import Optional
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from starlette.responses import RedirectResponse

from database import SessionLocal, engine
import models
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from datetime import datetime, timedelta
from jose import jwt, JWTError

from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

models.Base.metadata.create_all(bind=engine)
bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
templates = Jinja2Templates(directory='templates')

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
oauth2_bearer = OAuth2PasswordBearer(tokenUrl="token")


router = APIRouter(
    prefix='/auth',
    tags=['auth'],
    responses={401: {'user': 'Not authorized'}}
)


class LoginForm:
    def __init__(self, request: Request):
        self.request: Request = request
        self.username: Optional[str] = None
        self.password: Optional[str] = None

    async def create_auth_form(self):
        form = await self.request.form()
        self.username = form.get('email')
        self.password = form.get('password')


class EditPasswordForm:
    def __init__(self, request: Request):
        self.request: Request = request
        self.username: Optional[str] = None
        self.password: Optional[str] = None
        self.new_password: Optional[str] = None


def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()


def hash_password(password):
    return bcrypt_context.hash(password)


def verify_password(plain_password, hashed_password):
    return bcrypt_context.verify(plain_password, hashed_password)


def authenticate_user(db, username: str, password: str):
    user = db.query(models.Users).filter(models.Users.username == username).first()
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(username: str, user_id: int,
                        expires_delta: Optional[timedelta] = None):
    encode = {'sub': username, 'id': user_id}
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    encode.update({'exp': expire})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(request: Request):
    try:
        token = request.cookies.get('access_token')
        if token is None:
            return None
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        if username is None or user_id is None:
            logout(request)
        return {'username': username, 'id': user_id}
    except JWTError:
        raise HTTPException(status_code=404, detail='Not Found')


@router.post('/token')
async def login_for_access_token(response: Response, form_data: OAuth2PasswordRequestForm = Depends(),
                                 db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        return False
    token_expires = timedelta(minutes=60)
    token = create_access_token(user.username, user.id, expires_delta=token_expires)

    response.set_cookie(key='access_token', value=token, httponly=True)

    return True


@router.get('/', response_class=HTMLResponse)
async def authentication_page(request: Request):
    return templates.TemplateResponse('login.html', {'request': request})


@router.post('/', response_class=HTMLResponse)
async def login(request: Request, db: Session = Depends(get_db)):
    try:
        form = LoginForm(request)
        await form.create_auth_form()
        response = RedirectResponse(url='/todos', status_code=status.HTTP_302_FOUND)

        validate_user_cookie = await login_for_access_token(response=response, form_data=form, db=db)

        if not validate_user_cookie:
            msg = 'Incorrect username or password'
            return templates.TemplateResponse('login.html', {'request': request, 'msg': msg})
        return response

    except HTTPException:
        msg = 'Unknown Error'
        return templates.TemplateResponse('login.html', {'request': request, 'msg': msg})


@router.get('/logout')
async def logout(request: Request):
    msg = 'Logout Successful'
    response = templates.TemplateResponse('login.html', {'request': request, 'msg': msg})
    response.delete_cookie(key='access_token')
    return response


@router.get('/register', response_class=HTMLResponse)
async def register(request: Request):
    return templates.TemplateResponse('register.html', {'request': request})


@router.post('/register', response_class=HTMLResponse)
async def register_user(request: Request,
                        email: str = Form(...),
                        username: str = Form(...),
                        firstname: str = Form(...),
                        lastname: str = Form(...),
                        password: str = Form(...),
                        password2: str = Form(...),
                        db: Session = Depends(get_db)
                        ):

    validation1 = db.query(models.Users).filter(models.Users.username == username).first()

    validation2 = db.query(models.Users).filter(models.Users.email == email).first()

    if password != password2 or validation1 is not None or validation2 is not None:
        msg = 'Invalid registration request'
        return templates.TemplateResponse('register.html', {'request': request, 'msg': msg})

    user_model = models.Users()
    user_model.email = email
    user_model.username = username
    user_model.firstname = firstname
    user_model.lastname = lastname

    hashed_password = hash_password(password)
    user_model.hashed_password = hashed_password
    user_model.is_active = True

    db.add(user_model)
    db.commit()

    msg = 'User successfully created'

    return templates.TemplateResponse('login.html', {'request': request, 'msg': msg})


@router.get('/edit-password', response_class=HTMLResponse)
async def edit_user_view(request: Request):
    user = await get_current_user(request)
    if user is None:
        return RedirectResponse(url='/auth', status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse('edit-password.html', {'request': request, 'user': user})


@router.post('/edit-password', response_class=HTMLResponse)
async def edit_password(request: Request,
                        username: str = Form(...),
                        password: str = Form(...),
                        new_password: str = Form(...),
                        db: Session = Depends(get_db)):

    user = await get_current_user(request)
    if user is None:
        return RedirectResponse(url='/auth', status_code=status.HTTP_302_FOUND)

    user_model = db.query(models.Users).filter(models.Users.username == username).first()

    msg = 'Invalid Username or Password'

    if user_model is not None:
        if username == user_model.username and \
                        verify_password(password, user_model.hashed_password):

            user_model.hashed_password = hash_password(new_password)
            db.add(user_model)
            db.commit()
            msg = 'Password updated'

    return templates.TemplateResponse('edit-password.html', {'request': request, 'user': user, 'msg': msg})