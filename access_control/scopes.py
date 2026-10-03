"""
access_control.scopes
~~~~~~~~~~~~~~~~~~~~~
Data-scoping helpers that determine **which records** a user can access.

These functions work with QuerySets and return filtered results based on
the user's role and position in the SalesPerson hierarchy.

Usage::

    from access_control.scopes import get_accessible_customers

    qs = get_accessible_customers(request.user)
"""

from __future__ import annotations

from django.db.models import QuerySet

from inventory.models import User
from access_control.roles import ORG_WIDE_ROLES

Role = User.Role


# =====================================================================
# SalesPerson helpers
# =====================================================================

def get_salesperson_for_user(user) -> "SalesPerson | None":
    """
    Return the SalesPerson instance linked to *user*, or None.

    Uses the existing ``user.salesperson_profile`` reverse FK.
    """
    if not user or not getattr(user, "is_authenticated", False):
        return None
    # SalesPerson.user is a FK, so user.salesperson_profile is a manager.
    return user.salesperson_profile.select_related("manager").first()


def get_direct_reports(salesperson) -> QuerySet:
    """
    Return a QuerySet of SalesPerson objects that directly report to
    *salesperson* (i.e. whose ``manager`` is *salesperson*).
    """
    from customer_dashboard.models import SalesPerson

    if salesperson is None:
        return SalesPerson.objects.none()
    return SalesPerson.objects.filter(manager=salesperson)


def _collect_descendants(salesperson) -> set[int]:
    """
    Recursively collect all descendant SalesPerson IDs under *salesperson*
    (breadth-first).  Includes *salesperson* itself.

    Uses iterative BFS to avoid deep recursion on large trees.
    """
    from customer_dashboard.models import SalesPerson

    if salesperson is None:
        return set()

    visited: set[int] = {salesperson.pk}
    queue = [salesperson.pk]

    while queue:
        current_ids = queue
        queue = []
        children = SalesPerson.objects.filter(
            manager_id__in=current_ids,
        ).values_list("id", flat=True)
        for child_id in children:
            if child_id not in visited:
                visited.add(child_id)
                queue.append(child_id)

    return visited


def get_accessible_salespeople(user) -> QuerySet:
    """
    Return a QuerySet of SalesPerson objects the user is allowed to see.

    - Org-wide roles (ADMIN, SALES_HEAD, BUSINESS_MANAGER): all salespeople.
    - RSM: themselves + all descendants (ASMs and their salespeople).
    - ASM: themselves + direct-report salespeople.
    - SALESPERSON: only themselves.
    - All others: empty QuerySet.
    """
    from customer_dashboard.models import SalesPerson

    if not user or not getattr(user, "is_authenticated", False):
        return SalesPerson.objects.none()

    # Superuser gets everything.
    if user.is_superuser:
        return SalesPerson.objects.all()

    # Org-wide visibility roles.
    if user.role in ORG_WIDE_ROLES:
        return SalesPerson.objects.all()

    sp = get_salesperson_for_user(user)
    if sp is None:
        return SalesPerson.objects.none()

    if user.role == Role.RSM:
        ids = _collect_descendants(sp)
        return SalesPerson.objects.filter(pk__in=ids)

    if user.role == Role.ASM:
        ids = _collect_descendants(sp)
        return SalesPerson.objects.filter(pk__in=ids)

    if user.role == Role.SALESPERSON:
        return SalesPerson.objects.filter(pk=sp.pk)

    # Accounts, Warehouse, HR, etc. — no sales hierarchy access.
    return SalesPerson.objects.none()


def get_accessible_customers(user) -> QuerySet:
    """
    Return a QuerySet of Customer objects the user may access.

    Scoping is driven by accessible salespeople:
    - Customers assigned to any accessible salesperson are visible.
    - Org-wide roles see all customers.
    - Returns .none() when access cannot be determined.
    """
    from customer_dashboard.models import Customer

    if not user or not getattr(user, "is_authenticated", False):
        return Customer.objects.none()

    if user.is_superuser:
        return Customer.objects.all()

    if user.role in ORG_WIDE_ROLES:
        return Customer.objects.all()

    accessible_sp = get_accessible_salespeople(user)
    if not accessible_sp.exists():
        return Customer.objects.none()

    return Customer.objects.filter(salesperson__in=accessible_sp)


# =====================================================================
# Access-check helpers (single record)
# =====================================================================

def can_access_salesperson(user, salesperson) -> bool:
    """Return True if *user* is allowed to view *salesperson*'s data."""
    if not user or not getattr(user, "is_authenticated", False):
        return False
    if user.is_superuser:
        return True
    if user.role in ORG_WIDE_ROLES:
        return True

    sp = get_salesperson_for_user(user)
    if sp is None:
        return False

    if sp.pk == salesperson.pk:
        return True

    accessible_ids = _collect_descendants(sp)
    return salesperson.pk in accessible_ids


def can_access_customer(user, customer) -> bool:
    """Return True if *user* is allowed to view *customer*'s data."""
    if not user or not getattr(user, "is_authenticated", False):
        return False
    if user.is_superuser:
        return True
    if user.role in ORG_WIDE_ROLES:
        return True

    if customer.salesperson is None:
        # Unassigned customers — only org-wide roles can see them.
        return False

    return can_access_salesperson(user, customer.salesperson)
