"""
The sentinel the diagnose checks share.

Every check that can be handed a measurement by its caller — the nft set
contents, a unit's state, a counter — takes PROBE as the default and measures
for itself only then. None is not usable for that: several of those
observations use None to mean a real state (not running / could not ask).
"""

PROBE = object()
