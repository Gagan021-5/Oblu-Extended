from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import InventoryItem, Category, MonthlyStockData, DailyStockData, User, PurchaseOrderTrackingItem, PurchaseOrderTracking, PurchaseOrderStage, PurchaseOrderStageLog

# Register your models here.

@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Extends Django's built-in UserAdmin to expose the role field."""
    list_display = ("username", "role", "is_accountant", "is_staff", "is_active")
    list_filter = ("role", "is_accountant", "is_staff", "is_active")

    # Add 'role' to the default fieldsets (under Personal info).
    fieldsets = BaseUserAdmin.fieldsets + (
        ("Business Role", {"fields": ("role", "is_accountant", "is_viewer")}),
    )

admin.site.register(InventoryItem)

admin.site.register(Category)

admin.site.register(MonthlyStockData)

admin.site.register(DailyStockData)

admin.site.register(PurchaseOrderTracking)

admin.site.register(PurchaseOrderTrackingItem)

admin.site.register(PurchaseOrderStage)

admin.site.register(PurchaseOrderStageLog)

