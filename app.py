import joblib
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import uvicorn
import numpy as np
import pandas as pd
from fastapi.middleware.cors import CORSMiddleware
from feature_extraction import extract_url_features

app = FastAPI(title="Phishing URL Checker")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MODEL_PATH = "phishing_pipeline.pkl"

model = joblib.load(MODEL_PATH)

app.mount("/static", StaticFiles(directory="static"), name="static")

class PredictRequest(BaseModel):
    url: str

@app.get("/")
def index():
    return FileResponse("static/index.html")

@app.post("/predict")
async def predict(request: PredictRequest):
    url = request.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    
    features = extract_url_features(url)

    df = pd.DataFrame([features], columns=features.keys())

    try:
        proba = model.predict_proba(df)[:,1].item()
        pred = int(proba >= 0.5)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {"url": url, "phishing_probability": proba, "prediction": pred}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)