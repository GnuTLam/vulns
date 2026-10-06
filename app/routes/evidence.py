"""Evidence files attached to knowledge entries."""

import mimetypes
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, RedirectResponse
from sqlalchemy.orm import Session

from ..models import Evidence, KnowledgeEntry
from ..security import safe_filename, validate_csrf
from ..web import get_db, get_knowledge, require_auth

router = APIRouter(dependencies=[Depends(require_auth)])

# Types the browser may display; everything else is downloaded.
SAFE_INLINE_TYPES = {
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "video/mp4",
    "video/webm",
    "audio/mpeg",
    "audio/ogg",
}


async def store_evidence_files(
    request: Request, db: Session, knowledge: KnowledgeEntry, uploads: list[UploadFile] | None
) -> None:
    """Write uploads under generated names; files already written are removed if any upload fails."""
    settings = request.app.state.settings
    written: list[Path] = []
    try:
        for upload in uploads or []:
            if not upload.filename:
                continue
            original_name = safe_filename(upload.filename)
            suffix = Path(original_name).suffix.lower()[:12]
            stored_name = f"{uuid.uuid4()}{suffix}"
            destination = settings.evidence_dir / stored_name
            size = 0
            with destination.open("wb") as output:
                written.append(destination)
                while chunk := await upload.read(1024 * 1024):
                    size += len(chunk)
                    if size > settings.max_upload_bytes:
                        raise HTTPException(status_code=413, detail="File exceeds upload limit")
                    output.write(chunk)
            mime_type = upload.content_type or mimetypes.guess_type(original_name)[0] or "application/octet-stream"
            db.add(
                Evidence(
                    knowledge_id=knowledge.id,
                    filename=original_name,
                    stored_name=stored_name,
                    mime_type=mime_type,
                    size_bytes=size,
                )
            )
    except Exception:
        for path in written:
            path.unlink(missing_ok=True)
        raise


def _get_evidence(db: Session, evidence_id: str) -> Evidence:
    item = db.get(Evidence, evidence_id)
    if not item:
        raise HTTPException(status_code=404)
    return item


@router.post("/knowledge/{knowledge_id}/evidence")
async def evidence_upload(
    request: Request,
    knowledge_id: str,
    upload: UploadFile = File(...),
    csrf: str = Form(...),
    db: Session = Depends(get_db),
):
    validate_csrf(request, csrf)
    knowledge = get_knowledge(db, knowledge_id)
    await store_evidence_files(request, db, knowledge, [upload])
    db.commit()
    return RedirectResponse(f"/knowledge/{knowledge.id}#evidence", status_code=303)


@router.get("/evidence/{evidence_id}")
def evidence_view(request: Request, evidence_id: str, download: bool = False, db: Session = Depends(get_db)):
    item = _get_evidence(db, evidence_id)
    path = request.app.state.settings.evidence_dir / item.stored_name
    if not path.exists():
        raise HTTPException(status_code=404)
    inline = item.mime_type in SAFE_INLINE_TYPES and not download
    response = FileResponse(path, media_type=item.mime_type if inline else "application/octet-stream")
    disposition = "inline" if inline else "attachment"
    response.headers["Content-Disposition"] = (
        f'{disposition}; filename="{item.filename.encode("ascii", "ignore").decode() or "evidence"}"'
    )
    return response


@router.post("/evidence/{evidence_id}/delete")
def evidence_delete(request: Request, evidence_id: str, csrf: str = Form(...), db: Session = Depends(get_db)):
    validate_csrf(request, csrf)
    item = _get_evidence(db, evidence_id)
    knowledge_id = item.knowledge_id
    (request.app.state.settings.evidence_dir / item.stored_name).unlink(missing_ok=True)
    db.delete(item)
    db.commit()
    return RedirectResponse(f"/knowledge/{knowledge_id}#evidence", status_code=303)
