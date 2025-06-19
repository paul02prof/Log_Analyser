# Log_Analyser

Log_Analyser est une application basee sur FastAPI pour la collecte,le stockage et l'analyse des logs d'hotes linux.
## Features

- Modern UI
- Host management (add, view, delete hosts)
- User management (add, view, modify and delete users )
- Application for collecting logs on hosts
- Filter for best analyse

## Tech Stack

- Python 3.x
- FastAPI 0.x
- SQLite (default database)

## Installation

### Prerequisites

- Python 3.8 or higher

### Setup Instructions

1. **Clone the repository**

   ```bash
   git clone https://github.com/yourusername/log_project.git
   cd log_project.git
   ```

2. **Create and activate a virtual environment**

   ```bash
   python -m venv .venv
   # On Windows
   .venv\Scripts\activate
   # On macOS/Linux
   source .venv/bin/activate
   ```

3. **Install Python dependencies**

   ```bash
   pip install -r requirements.txt
   ```

3. **Run Log capture program**

   ```bash
   python log_capture.py
   ```
4. **Run the application**

   ```bash
   python serveur.py
   ```

5. **Access the application**
   
   Open your browser and navigate to http://127.0.0.1:8000

## Project Structure

- `Log_project/` - Main app for managing logs
- `static/` - HTML templates and Static assets

## Additional Information

- `last_send.txt` - File where the Timestamp of the last capture is save
- `logs_fusionnes.json` - JSON file to save logs with a particular structure

