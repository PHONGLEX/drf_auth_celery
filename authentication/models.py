from django.db import models
from django.contrib.auth.models import BaseUserManager, PermissionsMixin, AbstractBaseUser
from rest_framework_simplejwt.tokens import RefreshToken


class UserManager(BaseUserManager):
    
    def _create_user(self, email, name, password, **kwargs):
        if email is None:
            raise TypeError("Email is required")
        if name is None:
            raise TypeError("Name is required")
        
        user = self.model(name=name, email=self.normalize_email(email))
        user.set_password(password)
        user.save()
        return user
    
    def create_superuser(self, email, name, password, **kwargs):
        if password is None:
            raise TypeError("Password is required")
        
        user = self._create_user(email, name, password, **kwargs)
        user.is_staff = True
        user.is_superuser = True
        user.save()
        return user        


class User(PermissionsMixin, AbstractBaseUser):
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name"]
    
    objects = UserManager()
    
    def __str__(self):
        return self.email
    
    def tokens(self):
        refresh = RefreshToken.for_user(self)
        
        return {
            "access": str(refresh.access_token),
            "refresh": str(refresh)
        }