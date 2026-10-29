import os
import logging
from pathlib import Path
from dotenv import load_dotenv
from app import create_app

logging.basicConfig(level=logging.INFO)

# Load the backend's .env regardless of the shell's current directory.
# Existing environment variables keep precedence over values in the file.
load_dotenv(Path(__file__).resolve().with_name(".env"))

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=port, debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true")
