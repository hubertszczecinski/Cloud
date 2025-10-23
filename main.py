from fastapi import FastAPI, UploadFile, File, HTTPException
from azure.storage.blob import BlobServiceClient
from dotenv import load_dotenv
import os

load_dotenv()

AZURE_STORAGE_CONNECTION_STRING = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
CONTAINER_NAME = os.getenv("CONTAINER_NAME")
blob_service_client = BlobServiceClient.from_connection_string(AZURE_STORAGE_CONNECTION_STRING)

app = FastAPI()

@app.post("/upload/")
async def upload_file(file: UploadFile = File(...)):
    contents = await file.read()
    key = file.filename  

    blob_client = blob_service_client.get_blob_client(container=CONTAINER_NAME, blob=key)
    blob_client.upload_blob(contents, overwrite=True)

    return {"message": f"File {file.filename} uploaded successfully"}

@app.get("/download/{filename}")
async def download_file(filename: str):
    try:
        blob_client = blob_service_client.get_blob_client(container=CONTAINER_NAME, blob=filename)
        download_stream = blob_client.download_blob()
        content = download_stream.readall()
        return {"content": content.decode('utf-8')}
    except:
        raise HTTPException(status_code=404, detail="File not found")