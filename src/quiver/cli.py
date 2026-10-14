"""`quiver-admin`: operator commands run inside the api container.

docker compose exec api quiver-admin set-password
docker compose run --rm migrate          (runs `quiver-admin migrate`)
"""

import argparse
import asyncio
import getpass
import sys

from sqlalchemy import select, update

MIN_PASSWORD_LENGTH = 12
DEFAULT_ORG = "default"


def _read_password(from_stdin: bool) -> str:
    if from_stdin:
        return sys.stdin.readline().rstrip("\n")
    first = getpass.getpass("New operator password: ")
    second = getpass.getpass("Repeat password: ")
    if first != second:
        raise SystemExit("Passwords do not match.")
    return first


async def _set_password(username: str, password: str, settings=None) -> str:
    from datetime import UTC, datetime

    from quiver.api.auth import hash_password
    from quiver.core.config import get_settings
    from quiver.core.db import make_engine, make_sessionmaker
    from quiver.core.models import AuthSession, Organization, User

    engine = make_engine(settings or get_settings())
    try:
        async with make_sessionmaker(engine)() as db:
            org = await db.scalar(select(Organization).where(Organization.name == DEFAULT_ORG))
            if org is None:
                org = Organization(name=DEFAULT_ORG)
                db.add(org)
                await db.flush()
            user = await db.scalar(select(User).where(User.username == username))
            if user is None:
                db.add(
                    User(org_id=org.id, username=username, password_hash=hash_password(password))
                )
                action = "created"
            else:
                user.password_hash = hash_password(password)
                # A password change ends every existing login.
                await db.execute(
                    update(AuthSession)
                    .where(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None))
                    .values(revoked_at=datetime.now(UTC))
                )
                action = "updated"
            await db.commit()
    finally:
        await engine.dispose()
    return action


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="quiver-admin")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("migrate", help="apply database migrations")
    sp = sub.add_parser("set-password", help="create the operator account or change its password")
    sp.add_argument("--username", default="operator")
    sp.add_argument("--password-stdin", action="store_true", help="read the password from stdin")
    args = parser.parse_args(argv)

    if args.command == "migrate":
        from quiver.core.migrate import upgrade_to_head

        upgrade_to_head()
        print("Database is up to date.")
        return 0

    password = _read_password(args.password_stdin)
    if len(password) < MIN_PASSWORD_LENGTH:
        raise SystemExit(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    action = asyncio.run(_set_password(args.username, password))
    print(f"Operator '{args.username}' {action}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
