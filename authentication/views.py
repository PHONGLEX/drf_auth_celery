from django.shortcuts import render
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import smart_str, force_bytes
from django.urls import reverse
from django.conf import settings

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework import permissions
from rest_framework.views import APIView

from .models import User
from .utils import EmailHelper
from .serializers import *
from .tasks import send_email_task

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

import jwt


class RegisterView(generics.GenericAPIView):
    serializer_class = UserSerializer
    
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        
        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])
        site = get_current_site(request).domain
        url = reverse("email-verify")
        token = RefreshToken.for_user(user)
        link = "http://" + site + url + "?token=" + str(token)
        body = "Hi " + user.name + \
               "\n use the link below to verify your account " + link
        
        data = {
            "subject": "Verify your account",
            "body": body,
            "to": user.email
        }
        
        send_email_task.delay(data)
        
        return Response({"message": "We have sent you an email to verify your account"}, status=status.HTTP_201_CREATED)
    
    
class EmailVerificationView(generics.GenericAPIView):
    
    serializer_class = EmailVerificationSerializer
    
    token_param_config = openapi.Parameter('token', in_=openapi.IN_QUERY,
											description='Description', type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request, *args, **kwargs):
        token = request.GET.get('token')
        
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms="HS256")
            user = User.objects.get(id=payload["user_id"])
            
            if not user.is_verified:
                user.is_verified = True
                user.save()
                
            return Response({"message": "Successfully activated"}, status=status.HTTP_200_OK)
            
        except jwt.exceptions.ExpiredSignatureError as e:
            return Response({"error": "Activation expired"}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as e:
            return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)
        
        
class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    
class RequestResetPasswordView(generics.GenericAPIView):
    
    serializer_class = ResetPasswordSerializer
    
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(force_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            site = get_current_site(request).domain
            url = reverse("reset-password-confirm", kwargs={
                "uidb64": uidb64,
                "token": token
            })
            link = "http://" + site + url
            body = "Hi " + user.name + \
                 "\n Use the link below to reset your password " + link
            data = {
                "subject": "Reset your password",
                "body": body,
                "to": user.email
            }
            
            send_email_task.delay(data)
            
            return Response({"message": "We have sent you an email to reset your password"}, status=status.HTTP_200_OK)
        
        
class CheckTokenView(APIView):
    
    def post(self, request, uidb64, token):
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({"error": "Token invalid, please request a new one"}, status=status.HTTP_400_BAD_REQUEST)
            
            return Response({"success": True, "message": "Credential valid", "uidb64": uidb64, "token": token}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": "Token invalid, please request a new one"}, status=status.HTTP_400_BAD_REQUEST)
        
        
class SetNewPasswordView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer
    
    def patch(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        return Response({"success": True, "message": "Password reset success"}, status=status.HTTP_200_OK)
    
    
class LogoutView(generics.GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = (permissions.IsAuthenticated,)    
    
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        
        return Response(status=status.HTTP_204_NO_CONTENT)