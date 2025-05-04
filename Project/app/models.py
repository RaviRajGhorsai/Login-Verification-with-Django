from django.db import models
from django.contrib.auth.models import AbstractUser


# Create your models here.

class User(AbstractUser):
    # Add any additional fields you want to the user model here
    email = models.EmailField(unique=True)
    