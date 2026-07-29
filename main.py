from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database import SessionLocal
from models import Packet

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def home():
    return {"message": "NetSentinel AI API is running"}

@app.get("/packets")
def get_packets():
    db = SessionLocal()

    packets = db.query(Packet).order_by(Packet.id.desc()).limit(100).all()

    result = []

    for packet in packets:
       result.append({
    "id": packet.id,
    "source_ip": packet.source_ip,
    "destination_ip": packet.destination_ip,
    "protocol": packet.protocol,
    "source_port": packet.source_port,
    "destination_port": packet.destination_port,
    "alert": packet.alert,
    "attack_type": packet.attack_type
        })

    db.close()

    return result
