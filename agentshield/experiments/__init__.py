"""Experimental research harnesses, separate from stable benchmark APIs."""

from agentshield.experiments.real_model import (
    ActionOutcome,
    ExperimentMetrics,
    ModelOutcome,
    ProtocolSmokeReport,
    RealModelExperiment,
    RealModelTrial,
    run_real_model_experiment,
)

__all__ = [
    "ActionOutcome", "ExperimentMetrics", "ModelOutcome", "ProtocolSmokeReport",
    "RealModelExperiment", "RealModelTrial", "run_real_model_experiment",
]
