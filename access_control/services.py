"""
access_control.services
~~~~~~~~~~~~~~~~~~~~~~~
Public façade for the access-control subsystem.

Other Django apps should import from here::

    from access_control.services import (
        has_permission,
        get_accessible_customers,
        get_accessible_salespeople,
        can_access_customer,
        can_access_salesperson,
        get_salesperson_for_user,
        get_direct_reports,
    )

This keeps external coupling to a single import path and hides
internal module layout.
"""

from access_control.permissions import (          # noqa: F401
    has_permission,
    get_permissions_for_role,
    Perms,
)

from access_control.scopes import (               # noqa: F401
    get_salesperson_for_user,
    get_direct_reports,
    get_accessible_salespeople,
    get_accessible_customers,
    can_access_salesperson,
    can_access_customer,
)
