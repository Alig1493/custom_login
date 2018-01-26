from django.conf.urls import url
from django.contrib import admin
from django.urls import include
from rest_framework_jwt.views import obtain_jwt_token, refresh_jwt_token, verify_jwt_token

from rest_auth.views import LoginView, LogoutView

from login.views import UserRegistration

app_name = "login"

urlpatterns = [
    url(r'^register/$', UserRegistration.as_view(), name="register"),
    url(r'^login/$', LoginView.as_view(), name="login"),
    url(r'^logout/$', LogoutView.as_view(), name="logout"),
]
