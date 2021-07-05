from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken

from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import smart_str, force_bytes
from django.contrib import auth
from django.contrib.auth.tokens import PasswordResetTokenGenerator

from .models import User


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=50, write_only=True)
    
    class Meta:
        model = User
        fields = ["email", "name", "password"]
        
    def validate(self, attrs):
        email = attrs.get('email', '')
        name = attrs.get('name', '')
        
        if not name.isalnum():
            raise TypeError("Name should only contain alpha numeric characters")
        
        return attrs
    
    def create(self, validated_data):
        return User.objects._create_user(**validated_data)
    
    
class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField()
    
    class Meta:
        model = User
        fields = ["token", ]
        
        
class LoginSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    name = serializers.CharField(read_only=True)
    email = serializers.CharField()
    tokens = serializers.CharField(read_only=True)
    
    class Meta:
        model = User
        fields = ["email", "name", "password", "tokens"]
        
    def validate(self, attrs):
        email = attrs.get("email", "")
        name = attrs.get("name", "")
        password = attrs.get("password", "")
        
        user = auth.authenticate(email=email, password=password)
        
        if user is None:
            raise AuthenticationFailed("Invalid credentials, try again")
        if not user.is_active:
            raise AuthenticationFailed("Account disable, contact admin")
        if not user.is_verified:
            raise AuthenticationFailed("Account is not verified")
        
        return {
            "name": user.name,
            "email": user.email,
            "tokens": user.tokens()
        }
        
        
class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.CharField()
    
    class Meta:
        fields = ["email", ]
        
        
class SetNewPasswordSerializer(serializers.Serializer):
    uidb64 = serializers.CharField(write_only=True)
    token = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True)
    
    class Meta:
        fields = ['uidb64', "token", "password"]
        
    def validate(self, attrs):
        try:
            uidb64 = attrs.get('uidb64', '')
            token = attrs.get('token', '')
            password = attrs.get('password', '')
            
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed("Invalid token, please request a new one")
            
            user.set_password(password)
            user.save()
            return user
            
        except Exception as e:
            raise AuthenticationFailed("Invalid token, please request a new one")
        
        return attrs
    
    
class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    
    def validate(self, attrs):
        self.token = attrs.get("refresh", "")
        
        return attrs
    
    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except Exception as e:
            raise e