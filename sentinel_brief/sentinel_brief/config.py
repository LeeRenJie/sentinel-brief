"""Config + model factory. Vertex via Application Default Credentials (ADC).

Set GOOGLE_CLOUD_PROJECT to your GCP project, or rely on the project resolved by
ADC (`gcloud config set project ...`). LOCATION defaults to us-central1.

Model tiers (gemini-2.5-* verified available on Vertex at the Day-0 spike;
gemini-3-pro-preview & 2.0-flash 404'd on the test project):
  - PRO_MODEL   = gemini-2.5-pro   -> Supervisor + Adjudicator (reasoning-heavy)
  - FLASH_MODEL = gemini-2.5-flash -> Correlator + Responder + Detection Engineer
"""
from __future__ import annotations

import os

import google.auth
from splunklib.ai import GoogleModel

LOCATION = os.environ.get("GOOGLE_CLOUD_LOCATION", "us-central1")
PRO_MODEL = os.environ.get("GEMINI_PRO_MODEL", "gemini-2.5-pro")
FLASH_MODEL = os.environ.get("GEMINI_FLASH_MODEL", "gemini-2.5-flash")

_CLOUD_SCOPE = ["https://www.googleapis.com/auth/cloud-platform"]


def _adc():
    """Return (credentials, project) from ADC."""
    return google.auth.default(scopes=_CLOUD_SCOPE)


def resolve_project() -> str:
    """GCP project from GOOGLE_CLOUD_PROJECT, else the ADC-resolved default."""
    explicit = os.environ.get("GOOGLE_CLOUD_PROJECT")
    if explicit:
        return explicit
    _, project = _adc()
    if not project:
        raise RuntimeError(
            "No GCP project found. Set GOOGLE_CLOUD_PROJECT or run "
            "`gcloud config set project <your-project>`."
        )
    return project


def make_model(model_id: str, temperature: float | None = None) -> GoogleModel:
    """Build a Vertex-backed GoogleModel using ADC credentials."""
    credentials, _ = _adc()
    return GoogleModel(
        model=model_id,
        project=resolve_project(),
        location=LOCATION,
        credentials=credentials,
        vertexai=True,
        temperature=temperature,
    )


def pro_model(temperature: float | None = None) -> GoogleModel:
    return make_model(PRO_MODEL, temperature=temperature)


def flash_model(temperature: float | None = None) -> GoogleModel:
    return make_model(FLASH_MODEL, temperature=temperature)
