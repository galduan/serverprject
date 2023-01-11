# Create your models here.
from django.contrib.auth.models import AbstractUser
from django.db import models


class UsersData(AbstractUser):
    resetCode = models.CharField(max_length=40, blank=True, default='', null=True)
    lastPasswords = models.JSONField(blank=True, default=dict)
    email = models.CharField(max_length=40, blank=False,unique=True)