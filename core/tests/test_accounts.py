import uuid

import pytest
from django.db import IntegrityError

from accounts.models import Membership, User


@pytest.mark.django_db
def test_email_is_the_login_identity():
    u = User.objects.create_user(
        username="chris", email="chris@example.com", password="x"
    )
    assert User.USERNAME_FIELD == "email"
    assert str(u) == "chris@example.com"


@pytest.mark.django_db
def test_duplicate_email_rejected():
    User.objects.create_user(username="a", email="dup@example.com", password="x")
    with pytest.raises(IntegrityError):
        User.objects.create_user(username="b", email="dup@example.com", password="x")


@pytest.mark.django_db
def test_single_default_membership_enforced():
    u = User.objects.create_user(username="a", email="a@example.com", password="x")
    Membership.objects.create(
        user=u, tenant_id=uuid.uuid4(), role=Membership.Role.ANALYST, is_default=True
    )
    with pytest.raises(IntegrityError):
        Membership.objects.create(
            user=u, tenant_id=uuid.uuid4(), role=Membership.Role.VIEWER, is_default=True
        )
