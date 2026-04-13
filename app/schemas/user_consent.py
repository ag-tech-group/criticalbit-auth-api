from datetime import datetime

from pydantic import BaseModel, Field

from app.consent import CONSENT_TYPES


class ConsentEntryRead(BaseModel):
    consented: bool
    version: str
    consented_at: datetime
    is_stale: bool


class ConsentsResponse(BaseModel):
    current_policy_version: str
    consents: dict[str, ConsentEntryRead]


class ConsentEntryCreate(BaseModel):
    type: str = Field(..., max_length=50)
    consented: bool

    def validated_type(self) -> str:
        if self.type not in CONSENT_TYPES:
            raise ValueError(f"Unknown consent type '{self.type}'")
        return self.type


class ConsentsCreate(BaseModel):
    consents: list[ConsentEntryCreate]
