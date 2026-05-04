from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.extension import _rate_limit_exceeded_handler
from slowapi.util import get_remote_address

from checker.analyzer import PasswordAnalyzer
from checker.utils import generate_password


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="Password Strength Checker")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class PasswordRequest(BaseModel):
    password: str


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


def analyze_password(password: str):
    return PasswordAnalyzer(password).evaluate()


@app.post("/analyze")
@limiter.limit("10/minute")
def analyze(req: PasswordRequest, request: Request):
    return analyze_password(req.password)


@app.post("/api/check")
@limiter.limit("10/minute")
def check_password(req: PasswordRequest, request: Request):
    return PasswordAnalyzer(req.password).evaluate()


@app.get("/api/generate")
@limiter.limit("20/minute")
def generate_suggestion(request: Request, length: int = 16):
    return {"password": generate_password(length)}
