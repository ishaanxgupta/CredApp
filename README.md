# CredHub Backend

A FastAPI-based backend service for the CredHub application with MongoDB integration.

## Features

- **Health Check API**: Comprehensive health, readiness, and liveness endpoints
- **Middleware Stack**: CORS, logging, security headers, and rate limiting
- **MongoDB Integration**: Async MongoDB connection using Motor driver
- **Structured Logging**: Request/response logging with unique request IDs
- **API Versioning**: Organized API structure with version prefixes
- **Production Ready**: Error handling, lifespan management, and security headers

## Project Structure

```
backend/
├── app/
│   ├── __init__.py
│   ├── main.py                 # FastAPI application entry point
│   ├── api/
│   │   ├── __init__.py
│   │   └── v1/
│   │       ├── __init__.py
│   │       └── health.py       # Health check endpoints
│   ├── core/
│   │   ├── __init__.py
│   │   └── middleware.py       # CORS, logging, security, rate limiting
│   ├── db/
│   │   ├── __init__.py
│   │   └── mongo.py           # MongoDB connection and utilities
│   └── utils/
│       ├── __init__.py
│       └── logger.py          # Logging configuration
├── requirements.txt
├── .env.example
└── README.md
```

## Setup

1. **Create virtual environment** (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your MongoDB connection details
   ```

4. **Start MongoDB**:
   - Make sure MongoDB is running on your system
   - Default connection: `mongodb://localhost:27017`

5. **Run the application**:
   ```bash
   cd backend
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

## API Endpoints

### Health Check Endpoints

- `GET /` - Root endpoint with API information
- `GET /api/v1/health` - Basic health check
- `GET /api/v1/health/ready` - Readiness check for orchestration
- `GET /api/v1/health/live` - Liveness check for orchestration

### API Documentation

- `GET /docs` - Interactive API documentation (Swagger UI)
- `GET /redoc` - Alternative API documentation (ReDoc)
- `GET /openapi.json` - OpenAPI specification

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MONGODB_URL` | MongoDB connection string | `mongodb://localhost:27017` |
| `DATABASE_NAME` | Database name | `credhub` |
| `LOG_LEVEL` | Logging level | `INFO` |

## Middleware Features

### CORS Middleware
- Configured to allow all origins for development
- **Production**: Update `setup_cors_middleware()` to restrict origins

### Logging Middleware
- Logs all HTTP requests with unique request IDs
- Includes method, URL, response time, and status code
- Adds `X-Request-ID` and `X-Process-Time` headers

### Security Headers Middleware
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`

### Rate Limiting Middleware
- **Current**: In-memory rate limiting (100 requests/minute)
- **Production**: Integrate with Redis for distributed rate limiting

## Database Integration

The application uses Motor (async MongoDB driver) with dependency injection:

```python
from fastapi import Depends
from app.db.mongo import DatabaseDep

@app.get("/example")
async def example_route(db: AsyncIOMotorDatabase = DatabaseDep):
    # Use db for database operations
    result = await db.collection_name.find_one({})
    return result
```

## Development

### Running in Development Mode

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Adding New Routes

1. Create new router in `app/api/v1/`
2. Import and include in `main.py`
3. Follow the existing pattern for dependency injection

### Database Operations

Use the `DatabaseDep` dependency for MongoDB operations:

```python
from app.db.mongo import DatabaseDep

@router.post("/users")
async def create_user(user_data: dict, db: AsyncIOMotorDatabase = DatabaseDep):
    result = await db.users.insert_one(user_data)
    return {"id": str(result.inserted_id)}
```

## Production Considerations

1. **Environment Variables**: Use proper secrets management
2. **CORS**: Configure specific allowed origins
3. **Rate Limiting**: Implement Redis-based distributed rate limiting
4. **Monitoring**: Add application monitoring and metrics
5. **Security**: Implement authentication and authorization
6. **Logging**: Configure structured logging with external services
7. **Database**: Use MongoDB Atlas or managed database service

## License

This project is part of the CredHub application.
