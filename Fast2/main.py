from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from src.routes import users, auth

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(users.router, prefix='/api')


@app.get("/")
def read_root():
    return {"massage": "USER API"}

