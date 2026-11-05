"""Global kill switch: stops every engagement in the operator's organization at once."""

from fastapi import APIRouter, Depends

from quiver.api.auth import DbDep, OperatorDep, require_operator
from quiver.api.engagements import KillSwitchIn, KillSwitchOut, apply_kill_switch
from quiver.core.models import Organization

router = APIRouter(
    prefix="/kill-switch", tags=["kill switch"], dependencies=[Depends(require_operator)]
)


@router.get("", response_model=KillSwitchOut)
async def get_global_kill_switch(db: DbDep, user: OperatorDep):
    return KillSwitchOut.of(await db.get(Organization, user.org_id))


@router.put("", response_model=KillSwitchOut)
async def set_global_kill_switch(body: KillSwitchIn, db: DbDep, user: OperatorDep):
    """Engage or release the global kill switch. While engaged, the policy gate denies every
    action in every engagement of the organization."""
    org = await db.get(Organization, user.org_id)
    apply_kill_switch(db, org, user, body)
    await db.commit()
    await db.refresh(org)
    return KillSwitchOut.of(org)
