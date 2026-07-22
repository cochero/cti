from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from accounts.models import Membership, User

admin.site.register(User, UserAdmin)


@admin.register(Membership)
class MembershipAdmin(admin.ModelAdmin):
    list_display = ("user", "tenant_id", "role", "is_default")
    list_filter = ("role",)
