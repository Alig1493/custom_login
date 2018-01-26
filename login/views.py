# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from allauth.account.utils import complete_signup

from rest_auth.views import LoginView, sensitive_post_parameters_m
from rest_auth.registration.views import RegisterView
from rest_auth.models import TokenModel
from rest_auth.serializers import JWTSerializer
from rest_auth.utils import jwt_encode

from login.serializers import RegisterSerializer, LoginSerializer


class UserRegistration(RegisterView):
    serializer_class = RegisterSerializer
    permission_classes = (AllowAny,)
    token_model = TokenModel

    @sensitive_post_parameters_m
    def dispatch(self, *args, **kwargs):
        return super(RegisterView, self).dispatch(*args, **kwargs)

    def get_response_data(self, user):
        data = {
            'user': user,
            'token': self.token
        }
        return JWTSerializer(data).data

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)

        return Response(self.get_response_data(user),
                        status=status.HTTP_201_CREATED,
                        headers=headers)

    def perform_create(self, serializer):
        user = serializer.save()
        self.token = jwt_encode(user)
        complete_signup(self.request._request, user, False, None)
        return user
