from sqlalchemy import String, Text, Boolean, JSON
from sqlalchemy.orm import Mapped, mapped_column
from app.db.database import Base
import uuid


class Tool(Base):
    __tablename__ = "tools"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[str] = mapped_column(String, nullable=False)  # recon, web, enum, vuln, util
    binary: Mapped[str] = mapped_column(String, nullable=False)    # e.g. "nmap"
    default_flags: Mapped[str] = mapped_column(Text, default="")   # e.g. "-sV -sC"
    # Parameter slots: [{"name": "target", "flag": "-p", "placeholder": "10.10.10.1", "required": true}]
    parameters: Mapped[list] = mapped_column(JSON, default=list)
    # Workflow tags: ["external", "web", "internal"]
    workflow_tags: Mapped[list] = mapped_column(JSON, default=list)
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
