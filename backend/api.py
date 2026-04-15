from fastapi import FastAPI
from pydantic import BaseModel
from agents.orchestrator import run_pipeline

app = FastAPI()


class Request(BaseModel):
    org_description: str
    org_name: str = "Organization"


@app.post("/run")
def run_aria(req: Request):
    report = run_pipeline(
        org_description=req.org_description,
        org_name=req.org_name,
        verbose=False,
    )
    return report
