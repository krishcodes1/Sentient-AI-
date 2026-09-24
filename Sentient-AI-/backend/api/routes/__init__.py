"""Re-exports the agent, audit, auth and connectors APIRouters as ``*_router`` names."""

from api.routes.agent import router as agent_router
from api.routes.audit import router as audit_router
from api.routes.auth import router as auth_router
from api.routes.connectors import router as connectors_router

__all__ = ["agent_router", "audit_router", "auth_router", "connectors_router"]
