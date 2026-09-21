"""AI assistant route (controlled boundary between AI and data)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from backend.ai import assistant as assistant_ai
from backend.database import get_db
from backend.models.entities import User
from backend.models.schemas import AssistantRequest, AssistantResponse
from backend.security.audit import write_audit
from backend.security.deps import get_current_user
from backend.security.rate_limit import check_rate_limit
from backend.services import carbon_service
from backend.utils.request_context import build_client_context

router = APIRouter(prefix="/ai", tags=["ai"])


@router.post("/assistant", response_model=AssistantResponse)
def assistant(payload: AssistantRequest, request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Stricter rate limit: prevent excessive AI/API usage.
    check_rate_limit(request, scope="ai", limit=20, window=60)

    ctx = build_client_context(request)
    # Only aggregated, non-identifying context reaches the model.
    context = carbon_service.build_assistant_context(db, user)
    reply, model_used = assistant_ai.answer(payload.message, context)

    write_audit(
        db,
        event="AI_ASSISTANT",
        user_id=user.id,
        ip_address=ctx.ip_address,
        device_info=ctx.user_agent[:512],
        result="SUCCESS",
        details={"model": model_used, "message_length": len(payload.message)},
    )
    return AssistantResponse(reply=reply, grounded_on_user_data=True, model=model_used)
