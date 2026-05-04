# Password Strength Checker

## Project Overview

Password Strength Checker is a Python security project that analyzes password quality, flags risky patterns, estimates entropy, and suggests stronger alternatives. It includes a command-line interface, a FastAPI API, and a real-time browser UI with a strength meter and dark mode.

## Features

- Detects weak keyboard patterns such as `qwerty`
- Detects alphabet sequences such as `abc`
- Detects number sequences such as `123`
- Detects repeated characters such as `aaa` or `111`
- Checks password length, uppercase, lowercase, numbers, and symbols
- Estimates entropy and offline crack time
- Generates strong password suggestions with required character mix
- Avoids predictable generated passwords
- Provides rate-limited API endpoints
- Includes a real-time web UI with strength meter
- Includes a dark mode toggle
- Includes automated tests for required cases and edge cases

## Tech Stack

- Python
- FastAPI
- Pydantic
- SlowAPI
- Uvicorn
- HTML, CSS, and JavaScript
- unittest

## Setup

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Run the tests:

```bash
python -m unittest discover -s tests
```

## Run the CLI

```bash
python main.py
```

## Run the Web App

```bash
uvicorn app:app --reload
```

Open:

```text
http://127.0.0.1:8000
```

## API Example

Analyze a password:

```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d "{\"password\":\"Test@1234\"}"
```

Generate a strong password:

```bash
curl http://127.0.0.1:8000/api/generate
```

## API Response

```json
{
  "score": 3,
  "strength": "Medium",
  "feedback": [
    "Avoid number sequences like 123"
  ],
  "detected_patterns": [
    "Number sequence: 123"
  ],
  "suggested_password": "H&7mQp!2zR@sK9vB",
  "entropy": 59.0,
  "crack_time": "18.27 years"
}
```

## Rate Limiting

The analyze endpoints are limited to `10/minute` per client IP. The password generator endpoint is limited to `20/minute`.

## Endpoints

- `GET /` - Web UI
- `POST /analyze` - Analyze a password using a JSON body
- `POST /api/check` - Backward-compatible alias for `/analyze`
- `GET /api/generate` - Generate a strong password
