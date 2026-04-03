"""Auth router — /me, profile update, org update."""
import logging
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Optional

from middleware.clerk_auth import get_current_user, invalidate_user_cache
from middleware.rate_limit import rate_limit_auth
from database import get_database

logger = logging.getLogger(__name__)
router = APIRouter(
    prefix="/auth",
    tags=["auth"],
    dependencies=[Depends(rate_limit_auth)],
)


class UpdateProfileRequest(BaseModel):
    full_name: Optional[str] = Field(None, min_length=1, max_length=100)


class UpdateOrgRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)


@router.get("/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return current_user


@router.patch("/profile")
async def update_profile(
    data: UpdateProfileRequest,
    current_user: dict = Depends(get_current_user),
    db=Depends(get_database),
):
    if data.full_name is None:
        raise HTTPException(status_code=400, detail="No fields to update")
    user = current_user["user"]
    await db.execute(
        lambda c: c.table("users")
        .update({"full_name": data.full_name.strip()})
        .eq("id", user["id"])
        .execute()
    )
    await invalidate_user_cache(user["clerk_user_id"])
    return {"message": "Profile updated"}


@router.patch("/org")
async def update_org(
    data: UpdateOrgRequest,
    current_user: dict = Depends(get_current_user),
    db=Depends(get_database),
):
    if data.name is None:
        raise HTTPException(status_code=400, detail="No fields to update")
    org = current_user["org"]
    await db.execute(
        lambda c: c.table("organizations")
        .update({"name": data.name.strip()})
        .eq("id", org["id"])
        .execute()
    )
    await invalidate_user_cache(current_user["user"]["clerk_user_id"])
    return {"message": "Organization updated"}
