from django.urls import path

from . import views

urlpatterns = [
    path("register/", views.RegisterView.as_view(), name="register"),
    path("email-verify/", views.EmailVerificationView.as_view(), name="email-verify"),
    path("login/", views.LoginView.as_view(), name="login"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
    path("reset-password/", views.RequestResetPasswordView.as_view(), name="reset-password"),
    path("reset-password-confirm/<uidb64>/<token>/", views.CheckTokenView.as_view(), name="reset-password-confirm"),
    path("set-new-password/", views.SetNewPasswordView.as_view(), name="set-new-password"),
]