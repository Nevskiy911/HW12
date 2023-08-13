from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.models import User, Account
from src.schemas import UserSchema, UserUpdateSchema


async def get_users(limit: int, offset: int, db: AsyncSession, acc: Account):
    sq = select(User).filter_by(acc=acc).offset(offset).limit(limit)
    users = await db.execute(sq)
    return users.scalars().all()


async def get_user(user_id: int, db: AsyncSession, acc: Account):
    sq = select(User).filter_by(id=user_id, acc=acc)
    user = await db.execute(sq)
    return user.scalar_one_or_none()


async def create_user(body: UserSchema, db: AsyncSession, acc: Account):
    user = User(first_name=body.first_name, last_name=body.last_name, email=body.email, phone_number=body.phone_number,
                birthday=body.birthday, acc=acc)
    if body.data:
        user.data = body.data
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def update_user(user_id: int, body: UserUpdateSchema, db: AsyncSession, acc: Account):
    sq = select(User).filter_by(id=user_id, acc=acc)
    result = await db.execute(sq)
    user = result.scalar_one_or_none()
    if user:
        user.first_name = body.first_name
        user.last_name = body.last_name
        user.email = body.email
        user.phone_number = body.phone_number
        user.birthday = body.birthday
        user.data = body.data
        await db.commit()
        await db.refresh(user)
    return user


async def remove_user(user_id: int, db: AsyncSession, acc: Account):
    sq = select(User).filter_by(id=user_id, acc=acc)
    result = await db.execute(sq)
    user = result.scalar_one_or_none()
    if user:
        await db.delete(user)
        await db.commit()
    return user
