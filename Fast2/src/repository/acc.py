import logging

from libgravatar import Gravatar
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.models import Account
from src.schemas import AccountSchema


async def get_acc_by_email(email: str, db: AsyncSession) -> Account:
    sq = select(Account).filter_by(email=email)
    result = await db.execute(sq)
    acc = result.scalar_one_or_none()
    logging.info(acc)
    return acc


async def create_acc(body: AccountSchema, db: AsyncSession) -> Account:
    avatar = None
    try:
        g = Gravatar(body.email)
        avatar = g.get_image()
    except Exception as e:
        logging.error(e)
    new_acc = Account(**body.model_dump(), avatar=avatar)
    db.add(new_acc)
    await db.commit()
    await db.refresh(new_acc)
    return new_acc


async def update_token(user: Account, token: str | None, db: AsyncSession) -> None:
    user.refresh_token = token
    await db.commit()