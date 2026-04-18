# Cyber Triage Tool

AI-assisted cyber triage tool for early-stage digital forensic analysis.

## Tech Stack

- Python, Scikit-learn, Pandas (ML and processing)
- Flask (Backend API)
- React.js, Recharts, Tailwind (Frontend)
- MongoDB (Database)
- ReportLab (PDF Reports)

## Setup

### Backend

cd backend
pip install -r requirements.txt
python app.py

### Frontend

cd frontend
npm install
npm start

## Dataset Setup

This project uses the CICIDS2017 dataset.

1. Download from Kaggle:
   https://www.kaggle.com/datasets/ericanacletoribeiro/cicids2017-cleaned-and-preprocessed

2. Place the file in the data/ folder:
   cyber-triage-tool/data/cicids2017_cleaned.csv

3. The data/ folder is gitignored — never commit CSV files to this repo

## Contributors

Pull requests welcome. Please open an issue first to discuss changes.
