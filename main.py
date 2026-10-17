from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from core.api import routes
from loguru import logger
import sys
from pathlib import Path

app = FastAPI(title="WuRen AI Penetration Testing Platform")

ROOT_DIR = Path(__file__).resolve().parent
STATIC_DIR = ROOT_DIR / "webui" / "static"
REQUIRED_UI_FILES = (
    STATIC_DIR / "index.html",
    STATIC_DIR / "styles" / "app.css",
    STATIC_DIR / "styles" / "tailwind.generated.css",
    STATIC_DIR / "scripts" / "app.js",
)


def _verify_ui_assets() -> None:
    missing = [
        str(path.relative_to(ROOT_DIR))
        for path in REQUIRED_UI_FILES
        if not path.exists()
    ]
    if missing:
        raise RuntimeError(
            "Missing required UI assets: " + ", ".join(missing)
        )
    logger.info("UI assets verified: {}", ", ".join(str(path.relative_to(ROOT_DIR)) for path in REQUIRED_UI_FILES))

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Router
app.include_router(routes.router, prefix="/api", tags=["API"])


@app.on_event("startup")
async def app_startup():
    _verify_ui_assets()
    await routes.start_background_jobs()


@app.on_event("shutdown")
async def app_shutdown():
    await routes.stop_background_jobs()

# Logger Configuration
logger.remove()
logger.add(sys.stderr, level="INFO")
logger.add(routes.log_sink.write, level="INFO")

# Static Files
# Mount static files last to avoid overriding API routes
app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
