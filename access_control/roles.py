"""
access_control.roles
~~~~~~~~~~~~~~~~~~~~
Single source of truth for business role constants.

The canonical Role enum lives on ``inventory.User.Role`` so that it
remains co-located with the database column.  This module re-exports it
so that other apps can write::

    from access_control.roles import Role

without depending on the model import path.
"""

from inventory.models import User

# Re-export the Role enum for convenience.
Role = User.Role

# Convenience sets for common groupings.
ORG_WIDE_ROLES = frozenset({
    Role.ADMIN,
    Role.SALES_HEAD,
    Role.BUSINESS_MANAGER,
})

SALES_HIERARCHY_ROLES = frozenset({
    Role.RSM,
    Role.ASM,
    Role.SALESPERSON,
})

OPERATIONAL_ROLES = frozenset({
    Role.ACCOUNTS_OPERATIONS,
    Role.WAREHOUSE,
})
