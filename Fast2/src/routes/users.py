from typing import List

from fastapi import APIRouter, HTTPException, Depends, status, Path, Query
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.db import get_db
from src.database.models import Account
from src.schemas import UserResponse, UserSchema, UserUpdateSchema
from src.repository import users as repository_users
from src.services.auth import auth_service

router = APIRouter(prefix='/users', tags=["users"])


@router.get("/", response_model=List[UserResponse])
async def get_users(limit: int = Query(10, ge=10, le=500), offset: int = Query(0, ge=0, le=200),
                    db: AsyncSession = Depends(get_db), acc: Account = Depends(auth_service.get_current_acc)):
    users = await repository_users.get_users(limit, offset, db, acc)
    return users


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(user_id: int = Path(ge=1), db: AsyncSession = Depends(get_db),
                   acc: Account = Depends(auth_service.get_current_acc)):
    user = await repository_users.get_user(user_id, db, acc)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="NOT FOUND!",
        )
    return user


@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(body: UserSchema, db: AsyncSession = Depends(get_db),
                      acc: Account = Depends(auth_service.get_current_acc)):
    user = await repository_users.create_user(body, db, acc)
    return user


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(body: UserUpdateSchema, user_id: int = Path(ge=1), db: AsyncSession = Depends(get_db),
                      acc: Account = Depends(auth_service.get_current_acc)):
    user = await repository_users.update_user(user_id, body, db, acc)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="NOT FOUND!",
        )
    return user


@router.delete("/{user_id}", response_model=UserResponse)
async def delete_user(user_id: int = Path(ge=1), db: AsyncSession = Depends(get_db),
                      acc: Account = Depends(auth_service.get_current_acc)):
    user = await repository_users.remove_user(user_id, db, acc)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="NOT FOUND!",
        )
    return user
