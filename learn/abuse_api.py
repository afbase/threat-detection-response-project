from fastapi import FastAPI

app = FastAPI()

@app.get("/hello")
def hello():
    return {"message": "hello"}
from pydantic import BaseModel

class Book(BaseModel):
    title: str
    pages: int
    in_stock: bool

@app.post("/books")
def add_book(book: Book):
    return {"saved": book.title}