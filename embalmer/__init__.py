"""embalmer — firmware analysis pipeline.

embalmer is the orchestration layer of the necromancer suite for firmware
reverse engineering. It does not reimplement extraction or binary analysis;
it composes existing tools:

    extract (unblob)  ->  filesystem inspection  ->  binary analysis (blight)

producing a single structured firmware audit report (JSON or markdown).
"""

__version__ = "0.1.0"
