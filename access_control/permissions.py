"""
access_control.permissions
~~~~~~~~~~~~~~~~~~~~~~~~~~
Central permission codes and the role → permission matrix.

Every permission is a plain string constant.  The ROLE_PERMISSIONS dict
maps each Role to the *set* of permissions it holds.

Usage from any app::

    from access_control.permissions import has_permission, Perms

    if has_permission(request.user, Perms.CUSTOMER_EDIT):
        ...
"""

from __future__ import annotations

from inventory.models import User

Role = User.Role


# =====================================================================
# 1. Permission code constants
# =====================================================================

class Perms:
    """Namespace for all permission code strings."""

    # ── Customer ────────────────────────────────────────────────────
    CUSTOMER_VIEW = "customer.view"
    CUSTOMER_VIEW_INDIVIDUAL = "customer.view_individual"
    CUSTOMER_VIEW_TEAM = "customer.view_team"
    CUSTOMER_VIEW_ALL = "customer.view_all"
    CUSTOMER_EDIT = "customer.edit"
    CUSTOMER_TRANSFER = "customer.transfer"

    # ── Payment ─────────────────────────────────────────────────────
    PAYMENT_VIEW_INDIVIDUAL = "payment.view_individual"
    PAYMENT_VIEW_TEAM = "payment.view_team"
    PAYMENT_VIEW_ALL = "payment.view_all"

    # ── Inventory ───────────────────────────────────────────────────
    INVENTORY_VIEW = "inventory.view"

    # ── Incentive ───────────────────────────────────────────────────
    INCENTIVE_VIEW_ASM = "incentive.view_asm"
    INCENTIVE_VIEW_RSM = "incentive.view_rsm"
    INCENTIVE_VIEW_ORG = "incentive.view_org"

    # ── Call Logs ───────────────────────────────────────────────────
    CALLLOGS_VIEW = "calllogs.view"
    CALLLOGS_VIEW_TEAM = "calllogs.view_team"
    CALLLOGS_VIEW_ALL = "calllogs.view_all"

    # ── Proforma ────────────────────────────────────────────────────
    PROFORMA_CREATE = "proforma.create"
    PROFORMA_VIEW_SALES_PRICE = "proforma.view_sales_price"
    PROFORMA_VIEW_ADMIN_PRICE = "proforma.view_admin_price"

    # ── Operations ──────────────────────────────────────────────────
    STOCK_REQUEST = "stock.request"
    CREDIT_OVERDUE = "credit.overdue"
    DISPATCH = "dispatch"

    # ── Request Logs ────────────────────────────────────────────────
    REQUEST_LOGS_VIEW = "request_logs.view"


# =====================================================================
# 2. Role → Permission Matrix
# =====================================================================

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {

    # ── ADMIN ───────────────────────────────────────────────────────
    Role.ADMIN: frozenset({
        Perms.CUSTOMER_VIEW,
        Perms.CUSTOMER_VIEW_INDIVIDUAL,
        Perms.CUSTOMER_VIEW_TEAM,
        Perms.CUSTOMER_VIEW_ALL,
        Perms.CUSTOMER_EDIT,
        Perms.CUSTOMER_TRANSFER,
        Perms.PAYMENT_VIEW_INDIVIDUAL,
        Perms.PAYMENT_VIEW_TEAM,
        Perms.PAYMENT_VIEW_ALL,
        Perms.INVENTORY_VIEW,
        Perms.INCENTIVE_VIEW_ASM,
        Perms.INCENTIVE_VIEW_RSM,
        Perms.INCENTIVE_VIEW_ORG,
        Perms.CALLLOGS_VIEW,
        Perms.CALLLOGS_VIEW_TEAM,
        Perms.CALLLOGS_VIEW_ALL,
        Perms.PROFORMA_CREATE,
        Perms.PROFORMA_VIEW_SALES_PRICE,
        Perms.PROFORMA_VIEW_ADMIN_PRICE,
        Perms.STOCK_REQUEST,
        Perms.CREDIT_OVERDUE,
        Perms.DISPATCH,
        Perms.REQUEST_LOGS_VIEW,
    }),

    # ── SALES HEAD ──────────────────────────────────────────────────
    Role.SALES_HEAD: frozenset({
        Perms.CUSTOMER_VIEW,
        Perms.CUSTOMER_VIEW_INDIVIDUAL,
        Perms.CUSTOMER_VIEW_TEAM,
        Perms.CUSTOMER_VIEW_ALL,
        Perms.CUSTOMER_EDIT,
        Perms.PAYMENT_VIEW_INDIVIDUAL,
        Perms.PAYMENT_VIEW_TEAM,
        Perms.PAYMENT_VIEW_ALL,
        Perms.INCENTIVE_VIEW_ASM,
        Perms.INCENTIVE_VIEW_RSM,
        Perms.INCENTIVE_VIEW_ORG,
        Perms.CALLLOGS_VIEW,
        Perms.CALLLOGS_VIEW_TEAM,
        Perms.CALLLOGS_VIEW_ALL,
        Perms.PROFORMA_CREATE,
        Perms.PROFORMA_VIEW_SALES_PRICE,
    }),

    # ── BUSINESS MANAGER ────────────────────────────────────────────
    Role.BUSINESS_MANAGER: frozenset({
        Perms.CUSTOMER_VIEW,
        Perms.CUSTOMER_VIEW_INDIVIDUAL,
        Perms.CUSTOMER_VIEW_TEAM,
        Perms.CUSTOMER_VIEW_ALL,
        Perms.CUSTOMER_EDIT,
        Perms.PAYMENT_VIEW_INDIVIDUAL,
        Perms.PAYMENT_VIEW_TEAM,
        Perms.PAYMENT_VIEW_ALL,
        Perms.INVENTORY_VIEW,
        Perms.INCENTIVE_VIEW_ASM,
        Perms.INCENTIVE_VIEW_RSM,
        Perms.INCENTIVE_VIEW_ORG,
        Perms.CREDIT_OVERDUE,
        Perms.REQUEST_LOGS_VIEW,
        Perms.PROFORMA_CREATE,
        Perms.PROFORMA_VIEW_SALES_PRICE,
    }),

    # ── HR ──────────────────────────────────────────────────────────
    # Assigned to HR personnel (Vanshika, Anshika).
    # Defined with no scopes and no responsibilities (empty permission set)
    # until explicit HR workflows are introduced.
    Role.HR: frozenset(),

    # ── ACCOUNTS & OPERATIONS ───────────────────────────────────────
    Role.ACCOUNTS_OPERATIONS: frozenset({
        Perms.PAYMENT_VIEW_INDIVIDUAL,
        Perms.PAYMENT_VIEW_TEAM,
        Perms.PAYMENT_VIEW_ALL,
        Perms.INVENTORY_VIEW,
        Perms.INCENTIVE_VIEW_ASM,
        Perms.INCENTIVE_VIEW_RSM,
        Perms.INCENTIVE_VIEW_ORG,
        Perms.STOCK_REQUEST,
        Perms.DISPATCH,
    }),

    # ── WAREHOUSE ───────────────────────────────────────────────────
    Role.WAREHOUSE: frozenset({
        Perms.DISPATCH,
    }),

    # ── RSM (Regional Sales Manager) ────────────────────────────────
    Role.RSM: frozenset({
        Perms.CUSTOMER_VIEW,
        Perms.CUSTOMER_VIEW_INDIVIDUAL,
        Perms.CUSTOMER_VIEW_TEAM,
        Perms.PAYMENT_VIEW_INDIVIDUAL,
        Perms.PAYMENT_VIEW_TEAM,
        Perms.INCENTIVE_VIEW_ASM,
        Perms.CALLLOGS_VIEW,
        Perms.CALLLOGS_VIEW_TEAM,
        Perms.PROFORMA_CREATE,
        Perms.PROFORMA_VIEW_SALES_PRICE,
    }),

    # ── ASM (Area Sales Manager) ────────────────────────────────────
    Role.ASM: frozenset({
        Perms.CUSTOMER_VIEW,
        Perms.CUSTOMER_VIEW_INDIVIDUAL,
        Perms.CUSTOMER_VIEW_TEAM,
        Perms.CUSTOMER_TRANSFER,
        Perms.PAYMENT_VIEW_INDIVIDUAL,
        Perms.PAYMENT_VIEW_TEAM,
        Perms.INCENTIVE_VIEW_ASM,
        Perms.INCENTIVE_VIEW_RSM,
        Perms.CALLLOGS_VIEW,
        Perms.CALLLOGS_VIEW_TEAM,
        Perms.PROFORMA_CREATE,
        Perms.PROFORMA_VIEW_SALES_PRICE,
    }),

    # ── SALESPERSON ─────────────────────────────────────────────────
    Role.SALESPERSON: frozenset({
        Perms.CUSTOMER_VIEW,
        Perms.CUSTOMER_VIEW_INDIVIDUAL,
        Perms.PAYMENT_VIEW_INDIVIDUAL,
        Perms.CALLLOGS_VIEW,
        Perms.PROFORMA_CREATE,
        Perms.PROFORMA_VIEW_SALES_PRICE,
    }),
}


# =====================================================================
# 3. Public API
# =====================================================================

def has_permission(user, permission_code: str) -> bool:
    """
    Check whether *user* is granted *permission_code*.

    Rules (in priority order):
    1. Anonymous / inactive users → always False.
    2. Django superusers → always True (explicit admin override).
    3. Lookup in ROLE_PERMISSIONS matrix.
    """
    if not user or not getattr(user, "is_authenticated", False):
        return False
    if not user.is_active:
        return False
    if user.is_superuser:
        return True
    role_perms = ROLE_PERMISSIONS.get(user.role, frozenset())
    return permission_code in role_perms


def get_permissions_for_role(role: str) -> frozenset[str]:
    """Return all permission codes granted to *role*."""
    return ROLE_PERMISSIONS.get(role, frozenset())
