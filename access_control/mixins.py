"""
access_control.mixins
~~~~~~~~~~~~~~~~~~~~~
Reusable view mixins for permission and data-scoping checks.

These are generic — NOT role-specific (no AdminMixin, ASMMixin, etc.).
They delegate all logic to ``access_control.services``.

Usage::

    from access_control.mixins import PermissionRequiredMixin, CustomerScopeMixin

    class CustomerListView(PermissionRequiredMixin, CustomerScopeMixin, ListView):
        required_permission = "customer.view"

        def get_queryset(self):
            return self.get_customer_queryset()
"""

from __future__ import annotations

from django.contrib.auth.mixins import AccessMixin
from django.shortcuts import redirect

from access_control.services import (
    has_permission,
    get_accessible_customers,
    get_accessible_salespeople,
)


class PermissionRequiredMixin(AccessMixin):
    """
    Deny access unless the user holds the permission specified by
    ``required_permission``.

    Set ``required_permission`` on the view class::

        class MyView(PermissionRequiredMixin, TemplateView):
            required_permission = "customer.edit"

    If multiple permissions are needed, override ``check_permissions()``.
    """

    required_permission: str | None = None
    permission_denied_url: str | None = None

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return self.handle_no_permission()

        if not self.check_permissions(request.user):
            if self.permission_denied_url:
                return redirect(self.permission_denied_url)
            return redirect("welcome")

        return super().dispatch(request, *args, **kwargs)

    def check_permissions(self, user) -> bool:
        """
        Override for complex multi-permission checks.
        Default: check ``self.required_permission``.
        """
        if self.required_permission is None:
            return True
        return has_permission(user, self.required_permission)


class CustomerScopeMixin:
    """
    Provides ``get_customer_queryset()`` returning only customers the
    current user is allowed to see.

    Requires ``self.request`` (standard in Django CBVs).
    """

    def get_customer_queryset(self):
        return get_accessible_customers(self.request.user)


class SalesHierarchyMixin:
    """
    Provides ``get_salesperson_queryset()`` returning only salespeople
    the current user is allowed to see.

    Requires ``self.request`` (standard in Django CBVs).
    """

    def get_salesperson_queryset(self):
        return get_accessible_salespeople(self.request.user)
