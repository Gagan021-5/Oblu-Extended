"""
access_control.tests
~~~~~~~~~~~~~~~~~~~~
Tests for the RBAC foundation: permissions, scoping, and hierarchy.
"""

from django.test import TestCase, RequestFactory
from django.contrib.auth import get_user_model

from customer_dashboard.models import SalesPerson, Customer

from access_control.permissions import has_permission, Perms, ROLE_PERMISSIONS
from access_control.scopes import (
    get_salesperson_for_user,
    get_direct_reports,
    get_accessible_salespeople,
    get_accessible_customers,
    can_access_salesperson,
    can_access_customer,
)
from access_control.roles import Role, ORG_WIDE_ROLES

User = get_user_model()


class _HierarchyTestBase(TestCase):
    """
    Sets up a realistic sales hierarchy for reuse across test cases:

        RSM-1
          ├── ASM-1
          │     ├── SP-1  (has Cust-A, Cust-B)
          │     └── SP-2  (has Cust-C)
          └── ASM-2
                └── SP-3  (has Cust-D)

        RSM-2  (separate tree)
          └── ASM-3
                └── SP-4  (has Cust-E)
    """

    @classmethod
    def setUpTestData(cls):
        # ── Users ───────────────────────────────────────────────────
        cls.admin_user = User.objects.create_user(
            "admin_u", password="pass", role=Role.ADMIN,
        )
        cls.sales_head_user = User.objects.create_user(
            "sh_u", password="pass", role=Role.SALES_HEAD,
        )
        cls.bm_user = User.objects.create_user(
            "bm_u", password="pass", role=Role.BUSINESS_MANAGER,
        )
        cls.hr_user = User.objects.create_user(
            "hr_u", password="pass", role=Role.HR,
        )
        cls.acct_user = User.objects.create_user(
            "acct_u", password="pass", role=Role.ACCOUNTS_OPERATIONS,
        )
        cls.wh_user = User.objects.create_user(
            "wh_u", password="pass", role=Role.WAREHOUSE,
        )

        cls.rsm1_user = User.objects.create_user(
            "rsm1_u", password="pass", role=Role.RSM,
        )
        cls.rsm2_user = User.objects.create_user(
            "rsm2_u", password="pass", role=Role.RSM,
        )
        cls.asm1_user = User.objects.create_user(
            "asm1_u", password="pass", role=Role.ASM,
        )
        cls.asm2_user = User.objects.create_user(
            "asm2_u", password="pass", role=Role.ASM,
        )
        cls.asm3_user = User.objects.create_user(
            "asm3_u", password="pass", role=Role.ASM,
        )
        cls.sp1_user = User.objects.create_user(
            "sp1_u", password="pass", role=Role.SALESPERSON,
        )
        cls.sp2_user = User.objects.create_user(
            "sp2_u", password="pass", role=Role.SALESPERSON,
        )
        cls.sp3_user = User.objects.create_user(
            "sp3_u", password="pass", role=Role.SALESPERSON,
        )
        cls.sp4_user = User.objects.create_user(
            "sp4_u", password="pass", role=Role.SALESPERSON,
        )

        # ── SalesPerson hierarchy ───────────────────────────────────
        cls.rsm1 = SalesPerson.objects.create(name="RSM-1", user=cls.rsm1_user)
        cls.rsm2 = SalesPerson.objects.create(name="RSM-2", user=cls.rsm2_user)

        cls.asm1 = SalesPerson.objects.create(name="ASM-1", user=cls.asm1_user, manager=cls.rsm1)
        cls.asm2 = SalesPerson.objects.create(name="ASM-2", user=cls.asm2_user, manager=cls.rsm1)
        cls.asm3 = SalesPerson.objects.create(name="ASM-3", user=cls.asm3_user, manager=cls.rsm2)

        cls.sp1 = SalesPerson.objects.create(name="SP-1", user=cls.sp1_user, manager=cls.asm1)
        cls.sp2 = SalesPerson.objects.create(name="SP-2", user=cls.sp2_user, manager=cls.asm1)
        cls.sp3 = SalesPerson.objects.create(name="SP-3", user=cls.sp3_user, manager=cls.asm2)
        cls.sp4 = SalesPerson.objects.create(name="SP-4", user=cls.sp4_user, manager=cls.asm3)

        # ── Customers ──────────────────────────────────────────────
        _c = lambda name, sp: Customer.objects.create(
            name=name, phone=f"000-{name}", pincode="110001",
            address="Test", state="Test", district="Test", salesperson=sp,
        )
        cls.cust_a = _c("Cust-A", cls.sp1)
        cls.cust_b = _c("Cust-B", cls.sp1)
        cls.cust_c = _c("Cust-C", cls.sp2)
        cls.cust_d = _c("Cust-D", cls.sp3)
        cls.cust_e = _c("Cust-E", cls.sp4)


# ====================================================================
# Permission tests
# ====================================================================

class HasPermissionTest(_HierarchyTestBase):

    def test_anonymous_always_denied(self):
        from django.contrib.auth.models import AnonymousUser
        anon = AnonymousUser()
        self.assertFalse(has_permission(anon, Perms.CUSTOMER_VIEW))

    def test_inactive_user_denied(self):
        user = User.objects.create_user("inactive", password="p", role=Role.ADMIN, is_active=False)
        self.assertFalse(has_permission(user, Perms.CUSTOMER_VIEW))

    def test_superuser_always_granted(self):
        su = User.objects.create_superuser("su", password="pass")
        self.assertTrue(has_permission(su, Perms.DISPATCH))
        self.assertTrue(has_permission(su, Perms.REQUEST_LOGS_VIEW))
        self.assertTrue(has_permission(su, "nonexistent.perm"))

    def test_admin_has_all_expected(self):
        for perm in ROLE_PERMISSIONS[Role.ADMIN]:
            self.assertTrue(
                has_permission(self.admin_user, perm),
                f"Admin should have {perm}",
            )

    def test_warehouse_dispatch_only(self):
        self.assertTrue(has_permission(self.wh_user, Perms.DISPATCH))
        self.assertFalse(has_permission(self.wh_user, Perms.CUSTOMER_VIEW))
        self.assertFalse(has_permission(self.wh_user, Perms.PAYMENT_VIEW_ALL))
        self.assertFalse(has_permission(self.wh_user, Perms.INVENTORY_VIEW))

    def test_hr_has_no_permissions_or_scopes(self):
        """HR is defined as a role placeholder but currently has zero permissions and zero scopes."""
        self.assertEqual(len(ROLE_PERMISSIONS[Role.HR]), 0)
        self.assertFalse(has_permission(self.hr_user, Perms.CUSTOMER_VIEW))
        self.assertFalse(has_permission(self.hr_user, Perms.PAYMENT_VIEW_ALL))
        self.assertFalse(has_permission(self.hr_user, Perms.PROFORMA_CREATE))
        self.assertFalse(has_permission(self.hr_user, Perms.DISPATCH))
        self.assertFalse(has_permission(self.hr_user, Perms.INVENTORY_VIEW))
        # Ensure zero data scope
        self.assertEqual(get_accessible_customers(self.hr_user).count(), 0)
        self.assertEqual(get_accessible_salespeople(self.hr_user).count(), 0)

    def test_salesperson_basic_permissions(self):
        self.assertTrue(has_permission(self.sp1_user, Perms.CUSTOMER_VIEW))
        self.assertTrue(has_permission(self.sp1_user, Perms.CUSTOMER_VIEW_INDIVIDUAL))
        self.assertTrue(has_permission(self.sp1_user, Perms.PROFORMA_CREATE))
        self.assertFalse(has_permission(self.sp1_user, Perms.CUSTOMER_VIEW_ALL))
        self.assertFalse(has_permission(self.sp1_user, Perms.CUSTOMER_EDIT))
        self.assertFalse(has_permission(self.sp1_user, Perms.DISPATCH))

    def test_rsm_permissions(self):
        self.assertTrue(has_permission(self.rsm1_user, Perms.CUSTOMER_VIEW_TEAM))
        self.assertTrue(has_permission(self.rsm1_user, Perms.PROFORMA_CREATE))
        self.assertFalse(has_permission(self.rsm1_user, Perms.CUSTOMER_VIEW_ALL))
        self.assertFalse(has_permission(self.rsm1_user, Perms.DISPATCH))

    def test_asm_has_customer_transfer(self):
        self.assertTrue(has_permission(self.asm1_user, Perms.CUSTOMER_TRANSFER))
        self.assertFalse(has_permission(self.sp1_user, Perms.CUSTOMER_TRANSFER))

    def test_accounts_operations_permissions(self):
        self.assertTrue(has_permission(self.acct_user, Perms.PAYMENT_VIEW_ALL))
        self.assertTrue(has_permission(self.acct_user, Perms.STOCK_REQUEST))
        self.assertTrue(has_permission(self.acct_user, Perms.DISPATCH))
        self.assertFalse(has_permission(self.acct_user, Perms.CUSTOMER_EDIT))


# ====================================================================
# Hierarchy / scoping tests
# ====================================================================

class SalespersonHierarchyTest(_HierarchyTestBase):

    def test_get_salesperson_for_user(self):
        self.assertEqual(get_salesperson_for_user(self.rsm1_user), self.rsm1)
        self.assertEqual(get_salesperson_for_user(self.sp1_user), self.sp1)
        self.assertIsNone(get_salesperson_for_user(self.admin_user))

    def test_get_direct_reports_rsm(self):
        reports = get_direct_reports(self.rsm1)
        self.assertCountEqual(list(reports), [self.asm1, self.asm2])

    def test_get_direct_reports_asm(self):
        reports = get_direct_reports(self.asm1)
        self.assertCountEqual(list(reports), [self.sp1, self.sp2])

    def test_get_direct_reports_sp(self):
        reports = get_direct_reports(self.sp1)
        self.assertEqual(reports.count(), 0)


class AccessibleSalespeopleTest(_HierarchyTestBase):

    def test_admin_sees_all(self):
        qs = get_accessible_salespeople(self.admin_user)
        self.assertEqual(qs.count(), SalesPerson.objects.count())

    def test_sales_head_sees_all(self):
        qs = get_accessible_salespeople(self.sales_head_user)
        self.assertEqual(qs.count(), SalesPerson.objects.count())

    def test_rsm_sees_own_tree(self):
        qs = get_accessible_salespeople(self.rsm1_user)
        expected = {self.rsm1, self.asm1, self.asm2, self.sp1, self.sp2, self.sp3}
        self.assertCountEqual(list(qs), list(expected))

    def test_rsm_does_not_see_other_rsm(self):
        qs = get_accessible_salespeople(self.rsm1_user)
        self.assertNotIn(self.rsm2, qs)
        self.assertNotIn(self.asm3, qs)
        self.assertNotIn(self.sp4, qs)

    def test_asm_sees_own_team(self):
        qs = get_accessible_salespeople(self.asm1_user)
        expected = {self.asm1, self.sp1, self.sp2}
        self.assertCountEqual(list(qs), list(expected))

    def test_asm_does_not_see_other_asm_team(self):
        qs = get_accessible_salespeople(self.asm1_user)
        self.assertNotIn(self.asm2, qs)
        self.assertNotIn(self.sp3, qs)

    def test_salesperson_sees_only_self(self):
        qs = get_accessible_salespeople(self.sp1_user)
        self.assertCountEqual(list(qs), [self.sp1])

    def test_warehouse_sees_none(self):
        qs = get_accessible_salespeople(self.wh_user)
        self.assertEqual(qs.count(), 0)

    def test_hr_sees_none(self):
        qs = get_accessible_salespeople(self.hr_user)
        self.assertEqual(qs.count(), 0)

    def test_anonymous_sees_none(self):
        from django.contrib.auth.models import AnonymousUser
        qs = get_accessible_salespeople(AnonymousUser())
        self.assertEqual(qs.count(), 0)


class AccessibleCustomersTest(_HierarchyTestBase):

    def test_admin_sees_all_customers(self):
        qs = get_accessible_customers(self.admin_user)
        self.assertEqual(qs.count(), Customer.objects.count())

    def test_rsm_sees_own_tree_customers(self):
        qs = get_accessible_customers(self.rsm1_user)
        expected = {self.cust_a, self.cust_b, self.cust_c, self.cust_d}
        self.assertCountEqual(list(qs), list(expected))

    def test_rsm_denied_other_tree_customers(self):
        qs = get_accessible_customers(self.rsm1_user)
        self.assertNotIn(self.cust_e, qs)

    def test_asm_sees_team_customers(self):
        qs = get_accessible_customers(self.asm1_user)
        expected = {self.cust_a, self.cust_b, self.cust_c}
        self.assertCountEqual(list(qs), list(expected))

    def test_asm_denied_other_asm_customers(self):
        qs = get_accessible_customers(self.asm1_user)
        self.assertNotIn(self.cust_d, qs)

    def test_salesperson_own_customers(self):
        qs = get_accessible_customers(self.sp1_user)
        expected = {self.cust_a, self.cust_b}
        self.assertCountEqual(list(qs), list(expected))

    def test_salesperson_denied_other_sp_customers(self):
        qs = get_accessible_customers(self.sp1_user)
        self.assertNotIn(self.cust_c, qs)
        self.assertNotIn(self.cust_d, qs)
        self.assertNotIn(self.cust_e, qs)

    def test_warehouse_no_customer_access(self):
        qs = get_accessible_customers(self.wh_user)
        self.assertEqual(qs.count(), 0)


class CanAccessTest(_HierarchyTestBase):

    def test_can_access_own_salesperson(self):
        self.assertTrue(can_access_salesperson(self.asm1_user, self.asm1))

    def test_asm_can_access_own_sp(self):
        self.assertTrue(can_access_salesperson(self.asm1_user, self.sp1))

    def test_asm_cannot_access_other_asm_sp(self):
        self.assertFalse(can_access_salesperson(self.asm1_user, self.sp3))

    def test_rsm_can_access_asm_and_sp(self):
        self.assertTrue(can_access_salesperson(self.rsm1_user, self.asm1))
        self.assertTrue(can_access_salesperson(self.rsm1_user, self.sp1))

    def test_rsm_cannot_access_other_rsm_tree(self):
        self.assertFalse(can_access_salesperson(self.rsm1_user, self.asm3))
        self.assertFalse(can_access_salesperson(self.rsm1_user, self.sp4))

    def test_can_access_customer(self):
        self.assertTrue(can_access_customer(self.sp1_user, self.cust_a))
        self.assertFalse(can_access_customer(self.sp1_user, self.cust_c))
        self.assertTrue(can_access_customer(self.admin_user, self.cust_e))

    def test_anonymous_cannot_access(self):
        from django.contrib.auth.models import AnonymousUser
        anon = AnonymousUser()
        self.assertFalse(can_access_customer(anon, self.cust_a))
        self.assertFalse(can_access_salesperson(anon, self.sp1))


# ====================================================================
# User model helper tests
# ====================================================================

class UserModelHelperTest(TestCase):

    def test_has_role(self):
        user = User.objects.create_user("u1", password="p", role=Role.ASM)
        self.assertTrue(user.has_role(Role.ASM))
        self.assertTrue(user.has_role(Role.ASM, Role.RSM))
        self.assertFalse(user.has_role(Role.ADMIN))

    def test_is_sales_management(self):
        for role in (Role.RSM, Role.ASM, Role.SALES_HEAD):
            user = User(role=role)
            self.assertTrue(user.is_sales_management, f"{role} should be sales management")
        for role in (Role.ADMIN, Role.WAREHOUSE, Role.SALESPERSON, Role.HR):
            user = User(role=role)
            self.assertFalse(user.is_sales_management, f"{role} should NOT be sales management")

    def test_role_display(self):
        user = User(role=Role.ACCOUNTS_OPERATIONS)
        self.assertEqual(user.role_display, "Accounts & Operations")
