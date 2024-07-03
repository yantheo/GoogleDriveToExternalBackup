import os
import io
import pickle
import json
import logging
import psutil
from urllib.parse import urlparse

from google.oauth2.credentials import Credentials
from googleapiclient.errors import HttpError
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload

# Configuration
SCOPES = ["https://www.googleapis.com/auth/drive.readonly"]
CLIENT_SECRET_FILE = "credentials.json"
TOKEN_PICKLE_FILE = "token.pickle"
batch_size = 100

# List of download paths (external drives)
download_paths = [
    r"C:\Users\utilisateur\Desktop\test_download"  # Example path for external drive 1  # Example path for external drive 2
]

# Track downloaded files by drive
download_track_files = [
    "download_track_drive1.txt",  # Track file for drive 1
    "download_track_drive2.txt",  # Track file for drive 2
]

# Configure logging
logging.basicConfig(level=logging.INFO)


def authenticate_google_drive():
    creds = None
    if os.path.exists(TOKEN_PICKLE_FILE):
        with open(TOKEN_PICKLE_FILE, "rb") as token:
            try:
                creds = pickle.load(token)
            except EOFError:
                creds = None

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRET_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(TOKEN_PICKLE_FILE, "wb") as token:
            pickle.dump(creds, token)

    return creds


def list_files(service, batch_size):
    results = (
        service.files()
        .list(pageSize=batch_size, fields="nextPageToken, files(id, name, mimeType)")
        .execute()
    )
    return results.get("files", [])


def clean_file_name(file_name):
    invalid_chars = r'<>:"/\|?*'
    cleaned_name = "".join(c if c not in invalid_chars else "-" for c in file_name)
    return cleaned_name


def extract_domain_name(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.split(".")[0]  # Get the first part of the domain
    return domain.lower()


def download_file(service, file_id, file_name, mime_type, current_path, track_file):
    cleaned_file_name = clean_file_name(file_name)
    file_path = os.path.join(current_path, cleaned_file_name)

    if os.path.exists(track_file):
        with open(track_file, "r") as f:
            downloaded_files = f.read().splitlines()
    else:
        downloaded_files = []

    if file_id in downloaded_files:
        logging.info(f"File {file_name} already downloaded.")
        return

    if (
        mime_type
        == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    ):
        export_file(service, file_id, file_name, mime_type, current_path)
    elif mime_type == "application/vnd.google-apps.spreadsheet":
        export_file(service, file_id, file_name, mime_type, current_path)
    elif mime_type == "application/pdf" or mime_type == "image/jpeg":
        request = service.files().get_media(fileId=file_id)
        try:
            with open(file_path, "wb") as fh:
                downloader = MediaIoBaseDownload(fh, request)
                done = False
                while done is False:
                    status, done = downloader.next_chunk()
                    logging.info(
                        f"Download {file_name} {int(status.progress() * 100)}%."
                    )
            notify_file_downloaded(file_name)
            with open(track_file, "a") as f:
                f.write(file_id + "\n")
        except HttpError as e:
            if e.resp.status == 403 and "fileNotDownloadable" in e.content:
                logging.warning(
                    f"Cannot download '{file_name}'. It is not a binary file."
                )
                export_file(service, file_id, file_name, mime_type, current_path)
            else:
                raise e
    else:
        logging.warning(
            f"Unsupported MIME type '{mime_type}'. Skipped downloading '{file_name}'."
        )
    with open(track_file, "a") as f:
        f.write(file_id + "\n")


def export_file(service, file_id, file_name, mime_type, current_path):
    try:
        if (
            mime_type
            == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        ):
            request = service.files().export_media(
                fileId=file_id, mimeType="application/pdf"
            )
            file_path = os.path.join(current_path, f"{clean_file_name(file_name)}.pdf")
        elif mime_type == "application/vnd.google-apps.spreadsheet":
            request = service.files().export_media(
                fileId=file_id,
                mimeType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
            file_path = os.path.join(current_path, f"{clean_file_name(file_name)}.xlsx")
        else:
            request = service.files().get_media(fileId=file_id)
            file_path = os.path.join(current_path, clean_file_name(file_name))

        if file_path.startswith("http://") or file_path.startswith("https://"):
            domain_name = extract_domain_name(file_path)
            file_path = os.path.join(current_path, domain_name)

        logging.info(f"Exporting {file_name} to {file_path}")
        with open(file_path, "wb") as fh:
            downloader = MediaIoBaseDownload(fh, request)
            done = False
            while done is False:
                status, done = downloader.next_chunk()
                logging.info(f"Export {file_name} {int(status.progress() * 100)}%.")
        notify_file_downloaded(file_name)
    except HttpError as e:
        logging.error(f"Error exporting file '{file_name}': {e}")
    except OSError as e:
        logging.error(f"OS Error: {e}. Invalid file path: {file_path}")


def notify_file_downloaded(file_name):
    logging.info(f"File '{file_name}' has been successfully downloaded.")


def get_free_space_gb(folder):
    disk_usage = psutil.disk_usage(folder)
    return disk_usage.free / (1024**3)


def main():
    creds = authenticate_google_drive()
    service = build("drive", "v3", credentials=creds)

    for current_path, track_file in zip(download_paths, download_track_files):
        if not os.path.exists(track_file):
            with open(track_file, "w"):  # Create track file if it doesn't exist
                pass

        free_space = get_free_space_gb(current_path)
        if free_space < 1:  # 1 GB threshold
            logging.warning(f"Not enough space on {current_path}. Skipping.")
            continue

        files = list_files(service, batch_size)
        if not files:
            logging.info(f"No more files to download on {current_path}.")
            continue

        for file in files:
            download_file(
                service,
                file["id"],
                file["name"],
                file["mimeType"],
                current_path,
                track_file,
            )

            free_space = get_free_space_gb(current_path)
            if free_space < 1:
                logging.warning(
                    f"Not enough space on {current_path}. Stopping downloads."
                )
                break


if __name__ == "__main__":
    main()
