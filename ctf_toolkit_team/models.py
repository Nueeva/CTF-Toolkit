from django.conf import settings
from django.db import models

ROLES = [("owner", "Owner"), ("editor", "Editor"), ("viewer", "Viewer")]


class Case(models.Model):
    id = models.CharField(max_length=32, primary_key=True)
    title = models.CharField(max_length=200)


class Membership(models.Model):
    case = models.ForeignKey(Case, on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    role = models.CharField(max_length=6, choices=ROLES)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["case", "user"], name="one_case_role_per_user")]


class Invitation(models.Model):
    case = models.ForeignKey(Case, on_delete=models.CASCADE)
    digest = models.CharField(max_length=64, unique=True)
    role = models.CharField(max_length=6, choices=ROLES)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True)
